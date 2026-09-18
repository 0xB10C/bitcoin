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
#include <thread>
#include <utility>
#include <vector>

namespace mp {
namespace {
//! Batches allowed on the wire at once before delivery pauses and lets events
//! queue (and, if the queue fills, drop) in the node instead.
constexpr int MAX_IN_FLIGHT{4};

//! Fill one NetMessage from a NetMessageInfo. Written out by hand rather than
//! going through the generated field machinery, because the streaming path
//! builds its request outside clientInvoke().
void BuildNetMessage(ipc::capnp::messages::NetMessage::Builder builder, const interfaces::NetMessageInfo& m)
{
    builder.setInbound(m.inbound);
    builder.setPeerId(m.peer_id);
    builder.setPeerAddr(m.peer_addr);
    builder.setConnType(m.conn_type);
    builder.setMsgType(m.msg_type);
    builder.setMsgSize(m.msg_size);
    builder.setTimestampUs(m.timestamp_us);
    builder.setPayloadSlot(m.payload_slot);
    builder.setPayloadLen(m.payload_len);
    if (m.payload.empty()) return;
    // Same zero-copy rule as CustomBuildField() in tracing-types.h: attach a
    // large payload as an external segment instead of copying it into the
    // message. The batch outlives the request, so the bytes stay valid.
    const size_t padded{(m.payload.size() + 7) & ~size_t{7}};
    if (m.payload.size() >= NET_MESSAGE_PAYLOAD_EXTERNAL_MIN && m.payload.capacity() >= padded &&
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
             std::function<bool(std::vector<interfaces::NetMessageInfo>&, uint64_t&)> drain,
             std::function<void(std::vector<interfaces::NetMessageInfo>&, bool)> complete)
        : m_client{std::move(client)}, m_loop{loop},
          m_interval{interval_us * kj::MICROSECONDS}, m_drain{std::move(drain)}, m_complete{std::move(complete)}
    {
    }

    //! Everything below runs on the event loop thread only, so the batch pool
    //! and the in-flight count need no synchronization.
    ipc::capnp::messages::NetMessageTrace::Client m_client;
    EventLoop& m_loop;
    const kj::Duration m_interval;
    const std::function<bool(std::vector<interfaces::NetMessageInfo>&, uint64_t&)> m_drain;
    const std::function<void(std::vector<interfaces::NetMessageInfo>&, bool)> m_complete;
    //! Batches are held by shared_ptr because both continuations of a send
    //! have to name the same one; capturing by move into each would give the
    //! data to whichever lambda the compiler happens to construct first and
    //! leave the other empty.
    std::vector<std::shared_ptr<std::vector<interfaces::NetMessageInfo>>> m_pool;
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
        // Cap outstanding batches so a subscriber that stops reading makes
        // events queue in the node (and be dropped and counted) rather than
        // pile up here.
        // Keep sending until the node has nothing left or too much is already
        // on the wire. One batch per tick would cap delivery at
        // max_batch_events per interval, which silently drops events once the
        // node produces them faster than that.
        while (m_in_flight < MAX_IN_FLIGHT) {
            std::shared_ptr<std::vector<interfaces::NetMessageInfo>> batch;
            if (!m_pool.empty()) {
                batch = std::move(m_pool.back());
                m_pool.pop_back();
            } else {
                batch = std::make_shared<std::vector<interfaces::NetMessageInfo>>();
            }
            uint64_t dropped{0};
            if (!m_drain(*batch, dropped)) {
                if (m_pool.size() < static_cast<size_t>(MAX_IN_FLIGHT)) m_pool.push_back(std::move(batch));
                break;
            }
            Send(self, std::move(batch), dropped);
        }
        Schedule(self);
    }

    void Send(const std::shared_ptr<Streamer>& self,
              std::shared_ptr<std::vector<interfaces::NetMessageInfo>> batch, uint64_t dropped)
    {
        auto request{m_client.messagesStreamRequest(nullptr)};
        auto list{request.initMessages(batch->size())};
        for (size_t i{0}; i < batch->size(); ++i) BuildNetMessage(list[i], (*batch)[i]);
        request.setDropped(dropped);
        ++m_in_flight;
        m_loop.m_task_set->add(request.send().then(
            [self, batch](auto&&) { self->Finish(batch, /*ok=*/true); },
            [self, batch](const kj::Exception&) { self->Finish(batch, /*ok=*/false); }));
    }

    void Finish(const std::shared_ptr<std::vector<interfaces::NetMessageInfo>>& batch, bool ok)
    {
        --m_in_flight;
        // Hands the batch's arena slots and payload buffers back to the node.
        m_complete(*batch, ok);
        batch->clear();
        if (m_pool.size() < static_cast<size_t>(MAX_IN_FLIGHT)) m_pool.push_back(batch);
    }
};

ProxyClientCustom<ipc::capnp::messages::NetMessageTrace, interfaces::NetMessageTrace>::~ProxyClientCustom()
{
    stopStreaming();
}

bool ProxyClientCustom<ipc::capnp::messages::NetMessageTrace, interfaces::NetMessageTrace>::startStreaming(
    uint32_t interval_us,
    std::function<bool(std::vector<interfaces::NetMessageInfo>&, uint64_t&)> drain,
    std::function<void(std::vector<interfaces::NetMessageInfo>&, bool ok)> complete)
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
