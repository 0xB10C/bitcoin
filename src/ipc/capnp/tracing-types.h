// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_IPC_CAPNP_TRACING_TYPES_H
#define BITCOIN_IPC_CAPNP_TRACING_TYPES_H

#include <interfaces/tracing.h>
#include <ipc/capnp/common-types.h>
#include <ipc/capnp/handler-types.h>
#include <ipc/capnp/tracing.capnp.proxy.h>

#include <capnp/orphan.h>

#include <concepts>
#include <cstring>
#include <type_traits>
#include <vector>

namespace mp {
// Custom serializations

//! Payloads at least this large are attached to the outgoing message as an
//! external segment instead of being copied into it.
inline constexpr size_t NET_MESSAGE_PAYLOAD_EXTERNAL_MIN{4096};

template <typename Output>
concept IsNetMessagePayloadOutput = requires(Output& o) {
    { o.m_struct } -> std::convertible_to<ipc::capnp::messages::NetMessage::Builder&>;
};

//! Zero-copy builder for NetMessage.payload: reference the batch's payload
//! buffer as an extra message segment (capnp::Orphanage::referenceExternalData)
//! instead of copying up to 4 MB per event into the message on the event-loop
//! thread. The buffer outlives the request: the delivery thread that owns it
//! blocks in messages() until the call completes. Cap'n Proto reads the bytes
//! between the payload end and the next 8 byte boundary; the producer reserves
//! that padding, and its contents are at worst bytes of an earlier payload
//! already delivered to the same subscriber.
template <typename Value, typename Output>
void CustomBuildField(TypeList<std::vector<unsigned char>>, Priority<3>, InvokeContext& invoke_context, Value&& value, Output&& output)
    requires IsNetMessagePayloadOutput<std::remove_reference_t<Output>>
{
    const std::vector<unsigned char>& payload{value};
    const size_t padded{(payload.size() + 7) & ~size_t{7}};
    if (payload.size() >= NET_MESSAGE_PAYLOAD_EXTERNAL_MIN && payload.capacity() >= padded &&
        reinterpret_cast<uintptr_t>(payload.data()) % sizeof(capnp::word) == 0) {
        ipc::capnp::messages::NetMessage::Builder& builder{output.m_struct};
        auto orphanage{capnp::Orphanage::getForMessageContaining(builder)};
        builder.adoptPayload(orphanage.referenceExternalData(
            capnp::Data::Reader{reinterpret_cast<const kj::byte*>(payload.data()), payload.size()}));
        return;
    }
    auto result{output.init(payload.size())};
    std::memcpy(result.begin(), payload.data(), payload.size());
}
} // namespace mp

#endif // BITCOIN_IPC_CAPNP_TRACING_TYPES_H
