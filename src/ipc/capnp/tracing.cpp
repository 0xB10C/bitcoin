// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ipc/capnp/tracing-types.h>
#include <ipc/capnp/tracing.capnp.proxy-types.h>

#include <mp/proxy-io.h>
#include <mp/proxy-types.h>

#include <capnp/orphan.h>
#include <kj/exception.h>

#include <cstring>
#include <memory>
#include <utility>

namespace mp {
namespace {
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

bool ProxyClientCustom<ipc::capnp::messages::NetMessageTrace, interfaces::NetMessageTrace>::messagesAsync(
    std::vector<interfaces::NetMessageInfo> messages, uint64_t dropped,
    std::function<void(std::vector<interfaces::NetMessageInfo>, bool ok)> done)
{
    // The batch has to outlive the request: large payloads are attached to it
    // by reference rather than copied. Holding a reference to this proxy keeps
    // the subscriber (and its shared arena) alive for the same reason.
    auto batch{std::make_shared<std::vector<interfaces::NetMessageInfo>>(std::move(messages))};
    auto callback{std::make_shared<std::function<void(std::vector<interfaces::NetMessageInfo>, bool)>>(std::move(done))};
    m_context.loop->post([this, batch, callback, dropped]() {
        if (!m_context.connection) {
            (*callback)(std::move(*batch), /*ok=*/false);
            return;
        }
        auto request{m_client.messagesStreamRequest(nullptr)};
        auto list{request.initMessages(batch->size())};
        for (size_t i{0}; i < batch->size(); ++i) {
            BuildNetMessage(list[i], (*batch)[i]);
        }
        request.setDropped(dropped);
        // Hand the promise to the event loop and return. The batch comes back
        // through the callback when the request completes, which is also when
        // its arena slots may be reused.
        m_context.loop->m_task_set->add(request.send().then(
            [batch, callback](auto&&) { (*callback)(std::move(*batch), /*ok=*/true); },
            [batch, callback](const kj::Exception&) { (*callback)(std::move(*batch), /*ok=*/false); }));
    });
    return true;
}
} // namespace mp
