// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERFACES_TRACING_H
#define BITCOIN_INTERFACES_TRACING_H

#include <interfaces/handler.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace node {
struct NodeContext;
} // namespace node

namespace interfaces {

//! One P2P message event. Mirrors the data passed to the
//! net:inbound_message and net:outbound_message USDT tracepoints.
struct NetMessageInfo {
    //! True for a message received from a peer, false for a message sent to a peer.
    bool inbound{false};
    //! Peer id (CNode::GetId()).
    int64_t peer_id{0};
    //! Peer address and port (CNode::m_addr_name).
    std::string peer_addr;
    //! Connection type (CNode::ConnectionTypeAsString()).
    std::string conn_type;
    //! Message type (e.g. "ping", "inv", "block").
    std::string msg_type;
    //! Full message payload size in bytes, even if payload below is truncated.
    uint64_t msg_size{0};
    //! First NetMessageTraceOptions::max_payload_bytes bytes of the payload,
    //! unless payload_slot is set.
    std::vector<unsigned char> payload;
    //! When >= 0, the captured payload is not in `payload` but in the shared
    //! memory arena announced by NetMessageTrace::payloadArena(), at byte
    //! offset payload_slot * slot_bytes, and is payload_len bytes long. The
    //! bytes are only valid for the duration of the messages() call that
    //! delivered the event. -1 means the payload is inline in `payload`.
    int32_t payload_slot{-1};
    //! Number of captured payload bytes in the arena slot (0 if payload_slot < 0).
    uint32_t payload_len{0};
    //! Time the event was recorded, in microseconds on std::chrono::steady_clock
    //! (CLOCK_MONOTONIC on Linux, so comparable across local processes).
    int64_t timestamp_us{0};
};

struct NetMessageTraceOptions {
    //! Whether to receive inbound messages.
    bool inbound{true};
    //! Whether to receive outbound messages.
    bool outbound{true};
    //! Maximum number of payload bytes to include per event (0 = no payload).
    uint32_t max_payload_bytes{0};
    //! Maximum number of events buffered in the node for this subscriber.
    //! Events recorded while the buffer is full are dropped and counted.
    uint32_t max_queue_events{65536};
    //! Maximum number of events delivered in a single messages() call.
    uint32_t max_batch_events{1024};
    //! After the first event of a batch arrives, wait up to this long for the
    //! batch to fill up to max_batch_events before delivering it. Trades
    //! latency for fewer, larger IPC calls (0 = deliver as soon as possible).
    //! Per-call overhead dominates at high event rates, so 1 ms is the default.
    uint32_t max_batch_wait_us{1000};
    //! Maximum payload bytes buffered in the node for this subscriber. Events
    //! whose payload would exceed this are dropped and counted.
    uint64_t max_queue_bytes{64 * 1024 * 1024};
    //! Stop filling a batch once its payload bytes reach this (a batch always
    //! holds at least one event). Payloads passed through the shared memory
    //! arena do not count towards this, since they are not part of the batch.
    uint64_t max_batch_bytes{4 * 1024 * 1024};
    //! Size in bytes of a shared memory region the node sets up for this
    //! subscriber to pass large payloads through without copying them into
    //! the IPC message (0 = do not use shared memory). Only useful for a
    //! subscriber that can map the region, i.e. one on the same machine.
    //! The region is divided into slots of max_payload_bytes (rounded up to a
    //! page), so it must be at least that large to be used at all.
    uint64_t shm_bytes{0};
    //! Payloads of at least this many bytes go through the shared memory
    //! arena when one was set up; smaller ones stay inline in the IPC message,
    //! where they are cheaper than a slot round trip.
    uint32_t shm_min_payload_bytes{4096};
};

//! Callback interface implemented by a tracing client. Called from a
//! dedicated node thread, one batch at a time, never concurrently.
class NetMessageTrace
{
public:
    virtual ~NetMessageTrace() = default;

    //! Deliver a batch of events. `dropped` is the number of events discarded
    //! since the previous batch because the subscriber's buffer was full.
    virtual void messages(const std::vector<NetMessageInfo>& messages, uint64_t dropped) = 0;

    //! Announce the shared memory payload arena, called once before the first
    //! messages() call and only if NetMessageTraceOptions::shm_bytes asked for
    //! one and the node could create it. `name` is a POSIX shared memory
    //! object name (see util::SharedMemory) holding slot_count slots of
    //! slot_bytes bytes each; an event with payload_slot >= 0 has its payload
    //! at offset payload_slot * slot_bytes. Subscribers that do not map the
    //! arena see those events without payload bytes.
    virtual void payloadArena(const std::string& name, uint64_t slot_bytes, uint32_t slot_count) {}
};

//! Interface for subscribing to node trace events.
class Tracing
{
public:
    virtual ~Tracing() = default;

    //! Subscribe to P2P message events. Destroying or disconnect()ing the
    //! returned handler unsubscribes.
    virtual std::unique_ptr<Handler> traceNetMessages(const NetMessageTraceOptions& options,
                                                      std::unique_ptr<NetMessageTrace> callback) = 0;
};

//! Return implementation of Tracing interface.
std::unique_ptr<Tracing> MakeTracing(node::NodeContext& node);

} // namespace interfaces

#endif // BITCOIN_INTERFACES_TRACING_H
