// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_NET_TRACE_H
#define BITCOIN_NODE_NET_TRACE_H

#include <interfaces/tracing.h>
#include <sync.h>

#include <array>
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
 * record() only when there is at least one subscriber. record() copies the
 * event into each subscriber's bounded lock-free ring; it never blocks, never
 * takes a lock and never makes a system call (a payload larger than the
 * inline slot buffer may allocate). A dedicated delivery thread per subscriber
 * polls its ring, batches events and calls the subscriber's callback, so no
 * callback (and no IPC) ever runs on the net threads. Events recorded while a
 * subscriber's ring is full are dropped and the drop count is reported with
 * the next batch.
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
    static constexpr size_t MAX_SUBSCRIBERS{8};
    //! Shared so that handler cleanups running after the tracer is destroyed
    //! (possible with IPC clients disconnecting late) are harmless.
    //! One publication slot. The slot itself outlives every subscriber that
    //! passes through it, so producers can announce their use on it (in_use)
    //! before they touch the subscriber it points at.
    struct alignas(64) Slot {
        std::atomic<Subscriber*> sub{nullptr};
        //! Producers currently inside record() for whatever this slot points
        //! at. Remove() clears `sub`, then waits for this to reach zero.
        std::atomic<int> in_use{0};
    };
    struct State {
        //! Serializes subscribe/remove only; producers never take it.
        mutable Mutex mutex;
        //! Subscribers visible to producers, read lock-free in record().
        std::array<Slot, MAX_SUBSCRIBERS> slots{};
        //! Ownership of the subscribers in `slots`.
        std::vector<std::shared_ptr<Subscriber>> owned GUARDED_BY(mutex);
        std::atomic<int> active{0};

        //! Remove a subscriber if present. Idempotent. Does not join.
        void Remove(const std::shared_ptr<Subscriber>& sub) EXCLUSIVE_LOCKS_REQUIRED(!mutex);
    };
    std::shared_ptr<State> m_state;
};

} // namespace node

#endif // BITCOIN_NODE_NET_TRACE_H
