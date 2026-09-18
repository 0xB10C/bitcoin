// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/net_trace.h>

#include <logging.h>
#include <tinyformat.h>
#include <util/shared_memory.h>
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
//! Largest payload buffer kept for reuse (bounded by PAYLOAD_POOL_SIZE of them).
constexpr size_t MAX_RETAINED_PAYLOAD{MAX_PAYLOAD_BYTES};
//! Polling interval of the delivery thread when max_batch_wait_us is 0.
constexpr std::chrono::microseconds MIN_POLL_INTERVAL{50};
//! Upper bounds for the shared memory payload arena.
constexpr uint64_t MAX_SHM_BYTES{1024 * 1024 * 1024};
constexpr uint32_t MAX_ARENA_SLOTS{4096};
//! Arena slots are page aligned so that a slot never shares a page with another.
constexpr uint64_t ARENA_PAGE{4096};

interfaces::NetMessageTraceOptions ClampOptions(interfaces::NetMessageTraceOptions opts)
{
    opts.max_payload_bytes = std::min(opts.max_payload_bytes, MAX_PAYLOAD_BYTES);
    opts.max_queue_events = std::clamp<uint32_t>(opts.max_queue_events, 1, MAX_QUEUE_EVENTS);
    opts.max_batch_events = std::clamp<uint32_t>(opts.max_batch_events, 1, opts.max_queue_events);
    opts.max_batch_wait_us = std::min<uint32_t>(opts.max_batch_wait_us, 1'000'000);
    opts.max_queue_bytes = std::max<uint64_t>(opts.max_queue_bytes, opts.max_payload_bytes);
    opts.max_batch_bytes = std::max<uint64_t>(opts.max_batch_bytes, 1);
    opts.shm_bytes = std::min<uint64_t>(opts.shm_bytes, MAX_SHM_BYTES);
    // Below the inline slot buffer the arena would cost more than it saves.
    opts.shm_min_payload_bytes = std::max<uint32_t>(opts.shm_min_payload_bytes, INLINE_PAYLOAD + 1);
    return opts;
}

//! Geometry of the shared memory payload arena, empty when it is not used.
struct ArenaPlan {
    uint64_t slot_bytes{0};
    uint32_t slot_count{0};
};

ArenaPlan PlanArena(const interfaces::NetMessageTraceOptions& opts)
{
    if (opts.shm_bytes == 0 || opts.max_payload_bytes < opts.shm_min_payload_bytes) return {};
    const uint64_t slot_bytes{((opts.max_payload_bytes + ARENA_PAGE - 1) / ARENA_PAGE) * ARENA_PAGE};
    if (slot_bytes == 0 || opts.shm_bytes < slot_bytes) return {};
    return {slot_bytes, static_cast<uint32_t>(std::min<uint64_t>(opts.shm_bytes / slot_bytes, MAX_ARENA_SLOTS))};
}

util::SharedMemory MakeArena(const ArenaPlan& plan)
{
    if (plan.slot_count == 0) return {};
    std::string error;
    auto shm{util::SharedMemory::Create(plan.slot_bytes * plan.slot_count, error)};
    if (!shm) LogDebug(BCLog::IPC, "Net message trace: no shared payload arena: %s\n", error);
    return shm;
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
struct Event {
    bool inbound;
    int64_t peer_id;
    uint64_t msg_size;
    int64_t timestamp_us;
    //! Captured payload bytes, inline, on the heap or in the arena slot.
    uint32_t payload_len;
    //! Arena slot holding the payload, or -1 when it is inline/on the heap.
    int32_t payload_slot;
    std::array<char, 80> peer_addr;
    std::array<char, 24> conn_type;
    std::array<char, 16> msg_type;
    std::array<unsigned char, INLINE_PAYLOAD> payload_inline;
    std::vector<unsigned char> payload_heap;
};

//! Bounded lock-free multi-producer multi-consumer ring (Vyukov's algorithm).
//! Nobody ever blocks: a full ring makes TryPush return false, an empty one
//! makes TryPop return false.
template <typename T>
class Ring
{
public:
    explicit Ring(size_t min_capacity)
        : m_mask{std::bit_ceil<size_t>(std::max<size_t>(min_capacity, 2)) - 1},
          m_slots(m_mask + 1)
    {
        for (size_t i = 0; i <= m_mask; ++i) m_slots[i].seq.store(i, std::memory_order_relaxed);
    }

    //! Claim a slot, fill it with `fill(T&)`, publish it. Returns false if full.
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
        fill(slot->value);
        slot->seq.store(pos + 1, std::memory_order_release);
        return true;
    }

    //! Consume one slot with `consume(T&)`. Returns false if empty.
    template <typename Consume>
    bool TryPop(Consume&& consume)
    {
        size_t pos{m_dequeue.load(std::memory_order_relaxed)};
        Slot* slot;
        while (true) {
            slot = &m_slots[pos & m_mask];
            const size_t seq{slot->seq.load(std::memory_order_acquire)};
            const intptr_t diff{static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos + 1)};
            if (diff == 0) {
                if (m_dequeue.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed)) break;
            } else if (diff < 0) {
                return false; // empty
            } else {
                pos = m_dequeue.load(std::memory_order_relaxed);
            }
        }
        consume(slot->value);
        slot->seq.store(pos + m_mask + 1, std::memory_order_release);
        return true;
    }

private:
    struct Slot {
        std::atomic<size_t> seq;
        T value;
    };
    const size_t m_mask;
    std::vector<Slot> m_slots;
    alignas(64) std::atomic<size_t> m_enqueue{0};
    alignas(64) std::atomic<size_t> m_dequeue{0};
};

//! Number of large payload buffers kept for reuse per subscriber (at most
//! PAYLOAD_POOL_SIZE * MAX_RETAINED_PAYLOAD bytes retained).
constexpr size_t PAYLOAD_POOL_SIZE{16};
} // namespace

struct NetMessageTracer::Subscriber : std::enable_shared_from_this<Subscriber> {
    Subscriber(std::weak_ptr<State> state, interfaces::NetMessageTraceOptions options,
               std::unique_ptr<interfaces::NetMessageTrace> cb)
        : opts{ClampOptions(options)}, m_state{std::move(state)}, plan{PlanArena(opts)}, arena{MakeArena(plan)},
          ring{opts.max_queue_events}, free_slots{std::max<uint32_t>(plan.slot_count, 1)}, pool{PAYLOAD_POOL_SIZE},
          callback{std::move(cb)}
    {
        if (!arena) return;
        for (uint32_t i{0}; i < plan.slot_count; ++i) {
            free_slots.TryPush([&](uint32_t& s) { s = i; });
        }
    }

    const interfaces::NetMessageTraceOptions opts;
    const std::weak_ptr<State> m_state;

    //! Shared memory arena for large payloads. Only used once the subscriber
    //! has been told about it (arena_ready), so that it is mapped on the other
    //! side before the first byte is written into it.
    const ArenaPlan plan;
    util::SharedMemory arena;
    std::atomic<bool> arena_ready{false};

    Ring<Event> ring;
    //! Indices of arena slots not currently holding an undelivered payload.
    Ring<uint32_t> free_slots;
    //! Reusable heap buffers for payloads larger than INLINE_PAYLOAD, so
    //! steady-state large messages do not allocate (and page-fault) per event.
    Ring<std::vector<unsigned char>> pool;
    //! Payload bytes currently held in the ring (producers add, consumer subtracts).
    std::atomic<uint64_t> queued_bytes{0};
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
        const bool use_arena{copy >= opts.shm_min_payload_bytes && arena_ready.load(std::memory_order_relaxed)};
        uint32_t slot{0};
        if (use_arena) {
            // The only copy of a large payload: straight into the memory the
            // subscriber has mapped. Nothing else touches these bytes.
            if (!free_slots.TryPop([&](uint32_t& s) { slot = s; })) {
                dropped.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            std::memcpy(arena.data() + uint64_t{slot} * plan.slot_bytes, payload.data(), copy);
        } else if (copy > INLINE_PAYLOAD) {
            // Byte bound: reserve first, give back on failure.
            if (queued_bytes.fetch_add(copy, std::memory_order_relaxed) + copy > opts.max_queue_bytes) {
                queued_bytes.fetch_sub(copy, std::memory_order_relaxed);
                dropped.fetch_add(1, std::memory_order_relaxed);
                return;
            }
        }
        const bool ok{ring.TryPush([&](Event& s) {
            s.inbound = inbound;
            s.peer_id = peer_id;
            s.msg_size = payload.size();
            s.timestamp_us = now_us;
            s.payload_len = copy;
            s.payload_slot = use_arena ? static_cast<int32_t>(slot) : -1;
            CopyString(s.peer_addr, peer_addr);
            CopyString(s.conn_type, conn_type);
            CopyString(s.msg_type, msg_type);
            if (use_arena) {
                // Payload already written to the arena.
            } else if (copy <= INLINE_PAYLOAD) {
                std::memcpy(s.payload_inline.data(), payload.data(), copy);
            } else {
                // Capacity is rounded up to 8 bytes: the IPC layer may attach the
                // buffer to the outgoing message as-is, and Cap'n Proto reads up to
                // the next word boundary.
                const size_t padded{(copy + 7) & ~size_t{7}};
                if (s.payload_heap.capacity() < padded) {
                    // Try a recycled buffer before allocating.
                    pool.TryPop([&](std::vector<unsigned char>& buf) { s.payload_heap.swap(buf); });
                    if (s.payload_heap.capacity() < padded) s.payload_heap.reserve(padded);
                }
                s.payload_heap.assign(payload.begin(), payload.begin() + copy);
            }
        })};
        if (!ok) {
            if (use_arena) {
                free_slots.TryPush([&](uint32_t& s) { s = slot; });
            } else if (copy > INLINE_PAYLOAD) {
                queued_bytes.fetch_sub(copy, std::memory_order_relaxed);
            }
            dropped.fetch_add(1, std::memory_order_relaxed);
        }
    }

    //! Delivery thread: move events out of the ring until the batch is full
    //! (by count or payload bytes). Returns the batch's payload bytes.
    uint64_t Drain(std::vector<interfaces::NetMessageInfo>& batch, uint64_t batch_bytes)
    {
        while (batch.size() < opts.max_batch_events && (batch.empty() || batch_bytes < opts.max_batch_bytes)) {
            const bool got{ring.TryPop([&](Event& s) {
                auto& info{batch.emplace_back()};
                info.inbound = s.inbound;
                info.peer_id = s.peer_id;
                info.peer_addr = s.peer_addr.data();
                info.conn_type = s.conn_type.data();
                info.msg_type = s.msg_type.data();
                info.msg_size = s.msg_size;
                info.timestamp_us = s.timestamp_us;
                info.payload_slot = s.payload_slot;
                info.payload_len = s.payload_slot >= 0 ? s.payload_len : 0;
                if (s.payload_slot >= 0) {
                    // Payload stays in the arena; the batch carries only the slot.
                } else if (s.payload_len <= INLINE_PAYLOAD) {
                    info.payload.assign(s.payload_inline.begin(), s.payload_inline.begin() + s.payload_len);
                } else {
                    info.payload.swap(s.payload_heap);
                    queued_bytes.fetch_sub(s.payload_len, std::memory_order_relaxed);
                }
                batch_bytes += info.payload.size();
            })};
            if (!got) break;
        }
        return batch_bytes;
    }

    //! After delivery, hand the arena slots of a batch back to the producers.
    //! Must run only once the subscriber is done reading them, i.e. after
    //! messages() returned.
    void ReleaseSlots(std::vector<interfaces::NetMessageInfo>& batch)
    {
        for (auto& info : batch) {
            if (info.payload_slot < 0) continue;
            free_slots.TryPush([&](uint32_t& s) { s = static_cast<uint32_t>(info.payload_slot); });
            info.payload_slot = -1;
        }
    }

    //! After delivery, keep large payload buffers for reuse by producers.
    void RecycleBuffers(std::vector<interfaces::NetMessageInfo>& batch)
    {
        for (auto& info : batch) {
            if (info.payload.capacity() <= INLINE_PAYLOAD) continue;
            if (info.payload.capacity() > MAX_RETAINED_PAYLOAD) {
                std::vector<unsigned char>().swap(info.payload);
                continue;
            }
            info.payload.clear();
            pool.TryPush([&](std::vector<unsigned char>& buf) { buf.swap(info.payload); });
        }
    }

    //! Delivery loop, runs on `thread`. Polls the ring; producers never signal.
    void Run() EXCLUSIVE_LOCKS_REQUIRED(!mutex)
    {
        std::vector<interfaces::NetMessageInfo> batch;
        batch.reserve(opts.max_batch_events);
        if (arena) {
            // Only start using the arena once the subscriber has mapped it,
            // which it does in this call. If it cannot, the arena stays unused
            // and payloads travel inline as usual.
            try {
                callback->payloadArena(arena.name(), plan.slot_bytes, plan.slot_count);
                arena_ready.store(true, std::memory_order_relaxed);
            } catch (const std::exception& e) {
                LogDebug(BCLog::IPC, "Net message trace subscriber cannot use a shared payload arena: %s\n", e.what());
            }
        }
        const std::chrono::microseconds wait{opts.max_batch_wait_us > 0 ? std::chrono::microseconds{opts.max_batch_wait_us} : MIN_POLL_INTERVAL};
        while (true) {
            RecycleBuffers(batch);
            batch.clear();
            uint64_t bytes{Drain(batch, 0)};
            if (batch.size() < opts.max_batch_events && bytes < opts.max_batch_bytes) {
                // Not full: give the batch a moment to fill (or, when idle, just poll).
                {
                    WAIT_LOCK(mutex, lock);
                    cv.wait_for(lock, wait, [this]() EXCLUSIVE_LOCKS_REQUIRED(mutex) { return stop; });
                    if (stop) break;
                }
                Drain(batch, bytes);
                if (batch.empty()) continue;
            }
            const uint64_t dropped_now{dropped.exchange(0, std::memory_order_relaxed)};
            try {
                callback->messages(batch, dropped_now);
                ReleaseSlots(batch);
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
