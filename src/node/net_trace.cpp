// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/net_trace.h>

#include <logging.h>
#include <tinyformat.h>
#include <util/thread.h>
#include <util/time.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <exception>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>

namespace node {

namespace {
//! Upper bounds for subscriber options, to keep the memory bound sane.
constexpr uint32_t MAX_PAYLOAD_BYTES{4 * 1024 * 1024};
constexpr uint32_t MAX_QUEUE_EVENTS{1 << 20};
//! Payload bytes stored inline in a ring slot; larger payloads use the slot's
//! heap buffer (allocated on the producer, capacity kept for reuse).
constexpr size_t INLINE_PAYLOAD{64};
//! Shrink a slot's heap payload buffer back below this after use.
constexpr size_t MAX_RETAINED_PAYLOAD{64 * 1024};
//! Polling interval of the delivery thread when max_batch_wait_us is 0.
constexpr std::chrono::microseconds MIN_POLL_INTERVAL{50};

interfaces::NetMessageTraceOptions ClampOptions(interfaces::NetMessageTraceOptions opts)
{
    opts.max_payload_bytes = std::min(opts.max_payload_bytes, MAX_PAYLOAD_BYTES);
    opts.max_queue_events = std::clamp<uint32_t>(opts.max_queue_events, 1, MAX_QUEUE_EVENTS);
    opts.max_batch_events = std::clamp<uint32_t>(opts.max_batch_events, 1, opts.max_queue_events);
    opts.max_batch_wait_us = std::min<uint32_t>(opts.max_batch_wait_us, 1'000'000);
    return opts;
}

int64_t NowUs()
{
    return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

template <size_t N>
void CopyString(std::array<char, N>& dst, std::string_view src)
{
    const size_t n{std::min(src.size(), N - 1)};
    std::memcpy(dst.data(), src.data(), n);
    dst[n] = '\0';
}

//! One event as stored in the ring. Plain data plus one optional heap buffer
//! for payloads larger than INLINE_PAYLOAD.
struct Slot {
    std::atomic<size_t> seq;
    bool inbound;
    int64_t peer_id;
    uint64_t msg_size;
    int64_t timestamp_us;
    uint32_t payload_len;
    std::array<char, 80> peer_addr;
    std::array<char, 24> conn_type;
    std::array<char, 16> msg_type;
    std::array<unsigned char, INLINE_PAYLOAD> payload_inline;
    std::vector<unsigned char> payload_heap;
};

//! Bounded multi-producer, single-consumer ring (Vyukov's algorithm).
//! Producers never block: a full ring makes TryPush return false.
class EventRing
{
public:
    explicit EventRing(uint32_t min_capacity)
        : m_mask{std::bit_ceil<size_t>(std::max<uint32_t>(min_capacity, 2)) - 1},
          m_slots(m_mask + 1)
    {
        for (size_t i = 0; i <= m_mask; ++i) m_slots[i].seq.store(i, std::memory_order_relaxed);
    }

    //! Claim a slot, fill it with `fill(slot)`, publish it. Returns false if full.
    template <typename Fill>
    bool TryPush(Fill&& fill)
    {
        size_t pos{m_enqueue.load(std::memory_order_relaxed)};
        Slot* slot;
        while (true) {
            slot = &m_slots[pos & m_mask];
            const size_t seq{slot->seq.load(std::memory_order_acquire)};
            const intptr_t diff{static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos)};
            if (diff == 0) {
                if (m_enqueue.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed)) break;
            } else if (diff < 0) {
                return false; // full
            } else {
                pos = m_enqueue.load(std::memory_order_relaxed);
            }
        }
        fill(*slot);
        slot->seq.store(pos + 1, std::memory_order_release);
        return true;
    }

    //! Consume one slot with `consume(slot)`. Single consumer only. Returns false if empty.
    template <typename Consume>
    bool TryPop(Consume&& consume)
    {
        Slot& slot{m_slots[m_dequeue & m_mask]};
        const size_t seq{slot.seq.load(std::memory_order_acquire)};
        if (static_cast<intptr_t>(seq) - static_cast<intptr_t>(m_dequeue + 1) != 0) return false;
        consume(slot);
        slot.seq.store(m_dequeue + m_mask + 1, std::memory_order_release);
        ++m_dequeue;
        return true;
    }

private:
    const size_t m_mask;
    std::vector<Slot> m_slots;
    alignas(64) std::atomic<size_t> m_enqueue{0};
    alignas(64) size_t m_dequeue{0};
};
} // namespace

struct NetMessageTracer::Subscriber : std::enable_shared_from_this<Subscriber> {
    Subscriber(std::weak_ptr<State> state, interfaces::NetMessageTraceOptions options,
               std::unique_ptr<interfaces::NetMessageTrace> cb)
        : opts{ClampOptions(options)}, m_state{std::move(state)}, ring{opts.max_queue_events}, callback{std::move(cb)} {}

    const interfaces::NetMessageTraceOptions opts;
    const std::weak_ptr<State> m_state;

    EventRing ring;
    //! Events dropped because the ring was full (producers, relaxed).
    std::atomic<uint64_t> dropped{0};
    //! Producers currently inside record() for this subscriber; removal waits for zero.
    std::atomic<int> in_use{0};
    //! Set when delivery failed (client gone); producers skip the subscriber.
    std::atomic<bool> dead{false};

    //! Only for stopping the delivery thread. Producers never touch these.
    Mutex mutex;
    std::condition_variable cv;
    bool stop GUARDED_BY(mutex){false};

    //! Only touched by the delivery thread.
    std::unique_ptr<interfaces::NetMessageTrace> callback;
    std::thread thread;
    std::once_flag stopped;

    //! Producer side: copy one event into the ring. Wait-free, no allocation
    //! unless the payload exceeds the inline buffer.
    void Push(bool inbound, int64_t peer_id, std::string_view peer_addr, std::string_view conn_type,
              std::string_view msg_type, std::span<const unsigned char> payload, int64_t now_us)
    {
        const size_t copy{std::min<size_t>(payload.size(), opts.max_payload_bytes)};
        const bool ok{ring.TryPush([&](Slot& s) {
            s.inbound = inbound;
            s.peer_id = peer_id;
            s.msg_size = payload.size();
            s.timestamp_us = now_us;
            s.payload_len = copy;
            CopyString(s.peer_addr, peer_addr);
            CopyString(s.conn_type, conn_type);
            CopyString(s.msg_type, msg_type);
            if (copy <= INLINE_PAYLOAD) {
                std::memcpy(s.payload_inline.data(), payload.data(), copy);
            } else {
                s.payload_heap.assign(payload.begin(), payload.begin() + copy);
            }
        })};
        if (!ok) dropped.fetch_add(1, std::memory_order_relaxed);
    }

    //! Delivery thread: move up to max_batch_events out of the ring.
    void Drain(std::vector<interfaces::NetMessageInfo>& batch)
    {
        while (batch.size() < opts.max_batch_events) {
            const bool got{ring.TryPop([&](Slot& s) {
                auto& info{batch.emplace_back()};
                info.inbound = s.inbound;
                info.peer_id = s.peer_id;
                info.peer_addr = s.peer_addr.data();
                info.conn_type = s.conn_type.data();
                info.msg_type = s.msg_type.data();
                info.msg_size = s.msg_size;
                info.timestamp_us = s.timestamp_us;
                if (s.payload_len <= INLINE_PAYLOAD) {
                    info.payload.assign(s.payload_inline.begin(), s.payload_inline.begin() + s.payload_len);
                } else {
                    info.payload.swap(s.payload_heap);
                    info.payload.resize(s.payload_len);
                    s.payload_heap.clear();
                    if (s.payload_heap.capacity() > MAX_RETAINED_PAYLOAD) s.payload_heap.shrink_to_fit();
                }
            })};
            if (!got) break;
        }
    }

    //! Delivery loop, runs on `thread`. Polls the ring; producers never signal.
    void Run() EXCLUSIVE_LOCKS_REQUIRED(!mutex)
    {
        std::vector<interfaces::NetMessageInfo> batch;
        batch.reserve(opts.max_batch_events);
        const std::chrono::microseconds wait{opts.max_batch_wait_us > 0 ? std::chrono::microseconds{opts.max_batch_wait_us} : MIN_POLL_INTERVAL};
        while (true) {
            batch.clear();
            Drain(batch);
            if (batch.size() < opts.max_batch_events) {
                // Not full: give the batch a moment to fill (or, when idle, just poll).
                {
                    WAIT_LOCK(mutex, lock);
                    cv.wait_for(lock, wait, [this]() EXCLUSIVE_LOCKS_REQUIRED(mutex) { return stop; });
                    if (stop) break;
                }
                Drain(batch);
                if (batch.empty()) continue;
            }
            const uint64_t dropped_now{dropped.exchange(0, std::memory_order_relaxed)};
            try {
                callback->messages(batch, dropped_now);
            } catch (const std::exception& e) {
                LogDebug(BCLog::IPC, "Net message trace subscriber failed, removing it: %s\n", e.what());
                dead.store(true, std::memory_order_relaxed);
                if (auto state{m_state.lock()}) state->Remove(shared_from_this());
                break;
            }
        }
        // Destroy the callback from this thread. For IPC clients this sends
        // the destroy request over the connection (or logs if it is gone).
        callback.reset();
    }

    //! Idempotent. Never joins from the delivery thread itself.
    void Stop() EXCLUSIVE_LOCKS_REQUIRED(!mutex)
    {
        std::call_once(stopped, [this] {
            {
                LOCK(mutex);
                stop = true;
            }
            cv.notify_all();
            if (thread.joinable() && thread.get_id() != std::this_thread::get_id()) {
                thread.join();
            }
        });
    }
};

void NetMessageTracer::State::Remove(const std::shared_ptr<Subscriber>& sub)
{
    LOCK(mutex);
    for (auto& slot : slots) {
        if (slot.load(std::memory_order_acquire) != sub.get()) continue;
        slot.store(nullptr, std::memory_order_release);
        active.fetch_sub(1, std::memory_order_relaxed);
        // Wait for producers that picked up the pointer before it was cleared.
        while (sub->in_use.load(std::memory_order_acquire) != 0) std::this_thread::yield();
        owned.erase(std::find(owned.begin(), owned.end(), sub));
        return;
    }
}

NetMessageTracer::NetMessageTracer() : m_state{std::make_shared<State>()} {}

NetMessageTracer::~NetMessageTracer()
{
    std::vector<std::shared_ptr<Subscriber>> subs;
    {
        LOCK(m_state->mutex);
        for (auto& slot : m_state->slots) slot.store(nullptr, std::memory_order_release);
        m_state->active.store(0, std::memory_order_relaxed);
        subs.swap(m_state->owned);
    }
    for (const auto& sub : subs) {
        while (sub->in_use.load(std::memory_order_acquire) != 0) std::this_thread::yield();
        sub->Stop();
    }
}

size_t NetMessageTracer::subscriberCount() const
{
    LOCK(m_state->mutex);
    return m_state->owned.size();
}

void NetMessageTracer::record(bool inbound, int64_t peer_id, std::string_view peer_addr, std::string_view conn_type,
                              std::string_view msg_type, std::span<const unsigned char> payload)
{
    const int64_t now_us{NowUs()};
    for (auto& slot : m_state->slots) {
        Subscriber* sub{slot.load(std::memory_order_acquire)};
        if (!sub) continue;
        sub->in_use.fetch_add(1, std::memory_order_acquire);
        // Re-check after announcing use: Remove() clears the slot first, then waits for in_use.
        if (slot.load(std::memory_order_acquire) == sub && !sub->dead.load(std::memory_order_relaxed) &&
            (inbound ? sub->opts.inbound : sub->opts.outbound)) {
            sub->Push(inbound, peer_id, peer_addr, conn_type, msg_type, payload, now_us);
        }
        sub->in_use.fetch_sub(1, std::memory_order_release);
    }
}

std::unique_ptr<interfaces::Handler> NetMessageTracer::subscribe(const interfaces::NetMessageTraceOptions& options,
                                                                 std::unique_ptr<interfaces::NetMessageTrace> callback)
{
    auto sub{std::make_shared<Subscriber>(m_state, options, std::move(callback))};
    {
        LOCK(m_state->mutex);
        auto it{std::find_if(m_state->slots.begin(), m_state->slots.end(),
                             [](const auto& s) { return s.load(std::memory_order_relaxed) == nullptr; })};
        if (it == m_state->slots.end()) {
            throw std::runtime_error(strprintf("Too many net message trace subscribers (max %d)", m_state->slots.size()));
        }
        m_state->owned.push_back(sub);
        sub->thread = std::thread(&util::TraceThread, "nettrace", [sub] { sub->Run(); });
        it->store(sub.get(), std::memory_order_release);
        m_state->active.fetch_add(1, std::memory_order_relaxed);
    }
    return interfaces::MakeCleanupHandler([weak_state = std::weak_ptr<State>(m_state), sub] {
        if (auto state{weak_state.lock()}) state->Remove(sub);
        sub->Stop();
    });
}

} // namespace node
