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
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace mp {
// Custom serializations

//! Text <-> std::string_view, for the strings of a NetMessageInfo view. Read
//! views point into the received message, which outlives the call.
template <typename Value, typename Output>
void CustomBuildField(TypeList<std::string_view>, Priority<1>, InvokeContext& invoke_context, Value&& value, Output&& output)
{
    auto result{output.init(value.size())};
    std::memcpy(result.begin(), value.data(), value.size());
}

template <typename Input, typename ReadDest>
decltype(auto) CustomReadField(TypeList<std::string_view>, Priority<1>, InvokeContext& invoke_context, Input&& input, ReadDest&& read_dest)
{
    auto data{input.get()};
    return read_dest.construct(CharCast(data.begin()), data.size());
}

//! List(NetMessage) <-> std::span<const NetMessageInfo>. Building serializes
//! straight out of the node's views. On the receiving side the views are
//! collected in a vector that lives for the duration of the call.
template <typename Value, typename Output>
void CustomBuildField(TypeList<std::span<const interfaces::NetMessageInfo>>, Priority<1>, InvokeContext& invoke_context, Value&& value, Output&& output)
{
    BuildList(TypeList<interfaces::NetMessageInfo>(), invoke_context, output, value);
}

template <typename Accessor, typename ServerContext, typename Fn, typename... Args>
void CustomPassField(TypeList<std::span<const interfaces::NetMessageInfo>>, ServerContext& server_context, Fn&& fn, Args&&... args)
{
    InvokeContext& invoke_context{server_context};
    std::vector<interfaces::NetMessageInfo> batch;
    const auto& params{server_context.call_context.getParams()};
    ReadField(TypeList<std::vector<interfaces::NetMessageInfo>>(), invoke_context, Make<StructField, Accessor>(params),
              ReadDestUpdate(batch));
    fn.invoke(server_context, std::forward<Args>(args)..., std::span<const interfaces::NetMessageInfo>{batch});
}

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
//! between the payload end and the next 8 byte boundary; NetMessageInfo
//! promises that padding, and its contents are at worst bytes of an earlier
//! payload already delivered to the same subscriber.
template <typename Value, typename Output>
void CustomBuildField(TypeList<std::span<const unsigned char>>, Priority<3>, InvokeContext& invoke_context, Value&& value, Output&& output)
    requires IsNetMessagePayloadOutput<std::remove_reference_t<Output>>
{
    const std::span<const unsigned char> payload{value};
    if (payload.size() >= NET_MESSAGE_PAYLOAD_EXTERNAL_MIN &&
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
