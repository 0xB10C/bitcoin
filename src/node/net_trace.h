// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_NET_TRACE_H
#define BITCOIN_NODE_NET_TRACE_H

#include <interfaces/tracing.h>
#include <sync.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace node {

/**
 * Fan-out hub for P2P message trace events.
 *
 * The net code calls active() (a relaxed atomic load) on every message and
 * record() only when there is at least one subscriber. record() builds the
 * event once and appends it to each subscriber's bounded queue. A dedicated
 * delivery thread per subscriber drains that queue in batches and calls the
 * subscriber's callback, so no callback (and no IPC) ever runs on the net
 * threads. Events recorded while a subscriber's queue is full are dropped and
 * the drop count is reported with the next batch.
 *
 * This header must not include net.h (net.cpp includes this header).
 */
class NetMessageTracer
{
public:
    NetMessageTracer();
    //! Stops and joins all delivery threads.
    ~NetMessageTracer();

    NetMessageTracer(const NetMessageTracer&) = delete;
    NetMessageTracer& operator=(const NetMessageTracer&) = delete;

    //! Cheap hot-path check. When false nothing else is touched.
    bool active() const { return m_state->active.load(std::memory_order_relaxed) > 0; }

    //! Record one message event. Only call when active() is true.
    void record(bool inbound, int64_t peer_id, std::string_view peer_addr, std::string_view conn_type,
                std::string_view msg_type, std::span<const unsigned char> payload);

    //! Add a subscriber and start its delivery thread. Destroying the returned
    //! handler (or calling disconnect() on it) removes the subscriber and joins
    //! its delivery thread.
    std::unique_ptr<interfaces::Handler> subscribe(const interfaces::NetMessageTraceOptions& options,
                                                   std::unique_ptr<interfaces::NetMessageTrace> callback);

    //! Number of current subscribers (for tests).
    size_t subscriberCount() const;

private:
    struct Subscriber;
    //! Shared so that handler cleanups running after the tracer is destroyed
    //! (possible with IPC clients disconnecting late) are harmless.
    struct State {
        mutable Mutex mutex;
        std::vector<std::shared_ptr<Subscriber>> subscribers GUARDED_BY(mutex);
        //! Largest max_payload_bytes over all subscribers.
        uint32_t max_payload GUARDED_BY(mutex){0};
        std::atomic<int> active{0};

        //! Remove a subscriber if present. Idempotent. Does not join.
        void Remove(const std::shared_ptr<Subscriber>& sub) EXCLUSIVE_LOCKS_REQUIRED(!mutex);
        void RecomputeMaxPayload() EXCLUSIVE_LOCKS_REQUIRED(mutex);
    };
    std::shared_ptr<State> m_state;
};

} // namespace node

#endif // BITCOIN_NODE_NET_TRACE_H
