# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

@0xca4c717e6cf65a84;

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("ipc::capnp::messages");

using Handler = import "handler.capnp";
using Proxy = import "/mp/proxy.capnp";
$Proxy.include("interfaces/tracing.h");
$Proxy.includeTypes("ipc/capnp/tracing-types.h");

interface Tracing $Proxy.wrap("interfaces::Tracing") {
    destroy @0 (context :Proxy.Context) -> ();
    traceNetMessages @1 (context :Proxy.Context, options :NetMessageTraceOptions, callback :NetMessageTrace) -> (result :Handler.Handler);
}

# Implemented by the tracing client. Called by a dedicated node thread, one
# batch at a time.
interface NetMessageTrace $Proxy.wrap("interfaces::NetMessageTrace") {
    destroy @0 (context :Proxy.Context) -> ();
    messages @1 (context :Proxy.Context, messages :List(NetMessage), dropped :UInt64) -> ();
}

struct NetMessageTraceOptions $Proxy.wrap("interfaces::NetMessageTraceOptions") {
    inbound @0 :Bool = true $Proxy.name("inbound");
    outbound @1 :Bool = true $Proxy.name("outbound");
    maxPayloadBytes @2 :UInt32 = 0 $Proxy.name("max_payload_bytes");
    maxQueueEvents @3 :UInt32 = 65536 $Proxy.name("max_queue_events");
    maxBatchEvents @4 :UInt32 = 1024 $Proxy.name("max_batch_events");
    maxBatchWaitUs @5 :UInt32 = 1000 $Proxy.name("max_batch_wait_us");
}

struct NetMessage $Proxy.wrap("interfaces::NetMessageInfo") {
    inbound @0 :Bool $Proxy.name("inbound");
    peerId @1 :Int64 $Proxy.name("peer_id");
    peerAddr @2 :Text $Proxy.name("peer_addr");
    connType @3 :Text $Proxy.name("conn_type");
    msgType @4 :Text $Proxy.name("msg_type");
    msgSize @5 :UInt64 $Proxy.name("msg_size");
    payload @6 :Data $Proxy.name("payload");
    timestampUs @7 :Int64 $Proxy.name("timestamp_us");
}
