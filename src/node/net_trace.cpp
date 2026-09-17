// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/net_trace.h>

#include <logging.h>
#include <util/thread.h>
#include <util/time.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <exception>
#include <mutex>
#include <thread>
#include <utility>

namespace node {

namespace {
//! Upper bounds for subscriber options, to keep the memory bound sane.
constexpr uint32_t MAX_PAYLOAD_BYTES{4 * 1024 * 1024};
constexpr uint32_t MAX_QUEUE_EVENTS{1 << 20};

interfaces::NetMessageTraceOptions ClampOptions(interfaces::NetMessageTraceOptions opts)
{
    opts.max_payload_bytes = std::min(opts.max_payload_bytes, MAX_PAYLOAD_BYTES);
    opts.max_queue_events = std::clamp<uint32_t>(opts.max_queue_events, 1, MAX_QUEUE_EVENTS);
    opts.max_batch_events = std::clamp<uint32_t>(opts.max_batch_events, 1, opts.max_queue_events);
    return opts;
}
} // namespace

struct NetMessageTracer::Subscriber : std::enable_shared_from_this<Subscriber> {
    Subscriber(std::weak_ptr<State> state, interfaces::NetMessageTraceOptions options,
               std::unique_ptr<interfaces::NetMessageTrace> cb)
        : opts{ClampOptions(options)}, m_state{std::move(state)}, callback{std::move(cb)} {}

    const interfaces::NetMessageTraceOptions opts;
    const std::weak_ptr<State> m_state;

    Mutex mutex;
    std::condition_variable cv;
    std::deque<std::shared_ptr<const interfaces::NetMessageInfo>> queue GUARDED_BY(mutex);
    uint64_t dropped GUARDED_BY(mutex){0};
    bool stop GUARDED_BY(mutex){false};
    //! Set when delivery failed (client gone). record() skips dead subscribers.
    bool dead GUARDED_BY(mutex){false};

    //! Only touched by the delivery thread.
    std::unique_ptr<interfaces::NetMessageTrace> callback;
    std::thread thread;
    std::once_flag stopped;

    //! Delivery loop, runs on `thread`.
    void Run()
    {
        std::vector<std::shared_ptr<const interfaces::NetMessageInfo>> pending;
        std::vector<interfaces::NetMessageInfo> batch;
        while (true) {
            uint64_t dropped_now{0};
            {
                WAIT_LOCK(mutex, lock);
                cv.wait(lock, [this]() EXCLUSIVE_LOCKS_REQUIRED(mutex) { return stop || !queue.empty(); });
                if (stop) break;
                const size_t n{std::min<size_t>(queue.size(), opts.max_batch_events)};
                pending.assign(std::make_move_iterator(queue.begin()), std::make_move_iterator(queue.begin() + n));
                queue.erase(queue.begin(), queue.begin() + n);
                dropped_now = std::exchange(dropped, 0);
            }
            batch.clear();
            batch.reserve(pending.size());
            for (const auto& info : pending) {
                batch.push_back(*info);
                if (batch.back().payload.size() > opts.max_payload_bytes) {
                    batch.back().payload.resize(opts.max_payload_bytes);
                }
            }
            pending.clear();
            try {
                callback->messages(batch, dropped_now);
            } catch (const std::exception& e) {
                LogDebug(BCLog::IPC, "Net message trace subscriber failed, removing it: %s\n", e.what());
                {
                    LOCK(mutex);
                    dead = true;
                }
                if (auto state{m_state.lock()}) state->Remove(shared_from_this());
                break;
            }
        }
        // Destroy the callback from this thread. For IPC clients this sends
        // the destroy request over the connection (or logs if it is gone).
        callback.reset();
    }

    //! Idempotent. Never joins from the delivery thread itself.
    void Stop()
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

void NetMessageTracer::State::RecomputeMaxPayload()
{
    AssertLockHeld(mutex);
    uint32_t max{0};
    for (const auto& sub : subscribers) max = std::max(max, sub->opts.max_payload_bytes);
    max_payload = max;
}

void NetMessageTracer::State::Remove(const std::shared_ptr<Subscriber>& sub)
{
    LOCK(mutex);
    auto it{std::find(subscribers.begin(), subscribers.end(), sub)};
    if (it == subscribers.end()) return;
    subscribers.erase(it);
    RecomputeMaxPayload();
    active.fetch_sub(1, std::memory_order_relaxed);
}

NetMessageTracer::NetMessageTracer() : m_state{std::make_shared<State>()} {}

NetMessageTracer::~NetMessageTracer()
{
    std::vector<std::shared_ptr<Subscriber>> subs;
    {
        LOCK(m_state->mutex);
        subs.swap(m_state->subscribers);
        m_state->max_payload = 0;
        m_state->active.store(0, std::memory_order_relaxed);
    }
    for (const auto& sub : subs) sub->Stop();
}

size_t NetMessageTracer::subscriberCount() const
{
    LOCK(m_state->mutex);
    return m_state->subscribers.size();
}

void NetMessageTracer::record(bool inbound, int64_t peer_id, std::string_view peer_addr, std::string_view conn_type,
                              std::string_view msg_type, std::span<const unsigned char> payload)
{
    const int64_t now_us{std::chrono::duration_cast<std::chrono::microseconds>(
                             std::chrono::steady_clock::now().time_since_epoch())
                             .count()};
    LOCK(m_state->mutex);
    if (m_state->subscribers.empty()) return;

    auto info{std::make_shared<interfaces::NetMessageInfo>()};
    info->inbound = inbound;
    info->peer_id = peer_id;
    info->peer_addr = peer_addr;
    info->conn_type = conn_type;
    info->msg_type = msg_type;
    info->msg_size = payload.size();
    const size_t copy_bytes{std::min<size_t>(payload.size(), m_state->max_payload)};
    info->payload.assign(payload.begin(), payload.begin() + copy_bytes);
    info->timestamp_us = now_us;

    for (const auto& sub : m_state->subscribers) {
        if (!(inbound ? sub->opts.inbound : sub->opts.outbound)) continue;
        LOCK(sub->mutex);
        if (sub->dead || sub->stop) continue;
        if (sub->queue.size() >= sub->opts.max_queue_events) {
            ++sub->dropped;
            continue;
        }
        sub->queue.push_back(info);
        if (sub->queue.size() == 1 || sub->queue.size() >= sub->opts.max_batch_events) {
            sub->cv.notify_one();
        }
    }
}

std::unique_ptr<interfaces::Handler> NetMessageTracer::subscribe(const interfaces::NetMessageTraceOptions& options,
                                                                 std::unique_ptr<interfaces::NetMessageTrace> callback)
{
    auto sub{std::make_shared<Subscriber>(m_state, options, std::move(callback))};
    {
        LOCK(m_state->mutex);
        m_state->subscribers.push_back(sub);
        m_state->RecomputeMaxPayload();
        m_state->active.fetch_add(1, std::memory_order_relaxed);
    }
    sub->thread = std::thread(&util::TraceThread, "nettrace", [sub] { sub->Run(); });
    return interfaces::MakeCleanupHandler([weak_state = std::weak_ptr<State>(m_state), sub] {
        if (auto state{weak_state.lock()}) state->Remove(sub);
        sub->Stop();
    });
}

} // namespace node
