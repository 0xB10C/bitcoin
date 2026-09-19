// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ipc/capnp/tracing-types.h>
#include <ipc/capnp/tracing.capnp.proxy-types.h>

#include <mp/proxy-io.h>
#include <mp/proxy-types.h>

#include <capnp/orphan.h>
#include <kj/time.h>
#include <kj/exception.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <memory>
#include <string_view>
#include <thread>
#include <utility>

namespace mp {
namespace {
void SetText(capnp::Text::Builder out, std::string_view text)
{
    std::memcpy(out.begin(), text.data(), text.size());
}

//! Fill one NetMessage from a NetMessageInfo. Written out by hand rather than
//! going through the generated field machinery, because the streaming path
//! builds its request outside clientInvoke().
void BuildNetMessage(ipc::capnp::messages::NetMessage::Builder builder, const interfaces::NetMessageInfo& m)
{
    builder.setInbound(m.inbound);
    builder.setPeerId(m.peer_id);
    SetText(builder.initPeerAddr(m.peer_addr.size()), m.peer_addr);
    SetText(builder.initConnType(m.conn_type.size()), m.conn_type);
    SetText(builder.initMsgType(m.msg_type.size()), m.msg_type);
    builder.setMsgSize(m.msg_size);
    builder.setTimestampUs(m.timestamp_us);
    builder.setPayloadSlot(m.payload_slot);
    builder.setPayloadLen(m.payload_len);
    if (m.payload.empty()) return;
    // Same zero-copy rule as CustomBuildField() in tracing-types.h: attach a
    // large payload as an external segment instead of copying it into the
    // message. The batch outlives the request, so the bytes stay valid.
    if (m.payload.size() >= NET_MESSAGE_PAYLOAD_EXTERNAL_MIN &&
        reinterpret_cast<uintptr_t>(m.payload.data()) % sizeof(capnp::word) == 0) {
        auto orphanage{capnp::Orphanage::getForMessageContaining(builder)};
        builder.adoptPayload(orphanage.referenceExternalData(
            capnp::Data::Reader{reinterpret_cast<const kj::byte*>(m.payload.data()), m.payload.size()}));
        return;
    }
    auto out{builder.initPayload(m.payload.size())};
    std::memcpy(out.begin(), m.payload.data(), m.payload.size());
}
} // namespace

//! Drives delivery entirely on the Cap'n Proto event loop thread: a timer
//! tick drains a batch, builds the request and sends it without waiting for a
//! response. Nothing crosses a thread boundary, so a batch costs one socket
//! write rather than the pipe write, two condition variable waits and round
//! trip that clientInvoke() pays.
struct ProxyClientCustom<ipc::capnp::messages::NetMessageTrace, interfaces::NetMessageTrace>::Streamer {
    Streamer(ipc::capnp::messages::NetMessageTrace::Client client, EventLoop& loop, uint32_t interval_us,
             std::function<interfaces::NetMessageBatch*()> drain,
             std::function<void(interfaces::NetMessageBatch&, bool)> complete)
        : m_client{std::move(client)}, m_loop{loop},
          m_interval{interval_us * kj::MICROSECONDS}, m_drain{std::move(drain)}, m_complete{std::move(complete)}
    {
    }

    //! Everything below runs on the event loop thread only, so the in-flight
    //! count needs no synchronization.
    ipc::capnp::messages::NetMessageTrace::Client m_client;
    EventLoop& m_loop;
    const kj::Duration m_interval;
    const std::function<interfaces::NetMessageBatch*()> m_drain;
    const std::function<void(interfaces::NetMessageBatch&, bool)> m_complete;
    int m_in_flight{0};
    bool m_stopped{false};

    void Schedule(const std::shared_ptr<Streamer>& self)
    {
        if (m_stopped) return;
        m_loop.m_task_set->add(m_loop.m_io_context.provider->getTimer().afterDelay(m_interval).then(
            [self]() { self->Tick(self); }));
    }

    void Tick(const std::shared_ptr<Streamer>& self)
    {
        if (m_stopped) return;
        // Keep sending until the node has nothing left, or stops handing out
        // batches because too many are already on the wire. One batch per
        // tick would cap delivery at max_batch_events per interval, which
        // silently drops events once the node produces them faster than that.
        while (auto* batch{m_drain()}) Send(self, *batch);
        Schedule(self);
    }

    void Send(const std::shared_ptr<Streamer>& self, interfaces::NetMessageBatch& batch)
    {
        auto request{m_client.messagesStreamRequest(nullptr)};
        auto list{request.initMessages(batch.messages.size())};
        size_t i{0};
        for (const auto& m : batch.messages) BuildNetMessage(list[i++], m);
        request.setDropped(batch.dropped);
        ++m_in_flight;
        // The node owns the batch until Finish() gives it back, so both
        // continuations can simply point at it.
        auto* sent{&batch};
        m_loop.m_task_set->add(request.send().then(
            [self, sent](auto&&) { self->Finish(*sent, /*ok=*/true); },
            [self, sent](const kj::Exception&) { self->Finish(*sent, /*ok=*/false); }));
    }

    void Finish(interfaces::NetMessageBatch& batch, bool ok)
    {
        --m_in_flight;
        // Hands the batch, its arena slots and payload buffers back to the node.
        m_complete(batch, ok);
    }
};

ProxyClientCustom<ipc::capnp::messages::NetMessageTrace, interfaces::NetMessageTrace>::~ProxyClientCustom()
{
    stopStreaming();
}

bool ProxyClientCustom<ipc::capnp::messages::NetMessageTrace, interfaces::NetMessageTrace>::startStreaming(
    uint32_t interval_us,
    std::function<interfaces::NetMessageBatch*()> drain,
    std::function<void(interfaces::NetMessageBatch&, bool ok)> complete)
{
    if (!m_context.connection) return false;
    auto streamer{std::make_shared<Streamer>(m_client, *m_context.loop, std::max<uint32_t>(interval_us, 1),
                                             std::move(drain), std::move(complete))};
    m_streamer = streamer;
    m_context.loop->post([streamer]() { streamer->Schedule(streamer); });
    return true;
}

void ProxyClientCustom<ipc::capnp::messages::NetMessageTrace, interfaces::NetMessageTrace>::stopStreaming()
{
    auto streamer{std::move(m_streamer)};
    if (!streamer) return;
    // Stopping and waiting both happen on the event loop thread, so once this
    // returns no tick or completion can still be running.
    m_context.loop->post([streamer]() { streamer->m_stopped = true; });
    for (int i{0}; i < 10000; ++i) {
        bool busy{false};
        m_context.loop->post([&streamer, &busy]() { busy = streamer->m_in_flight > 0; });
        if (!busy) break;
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
}

} // namespace mp
