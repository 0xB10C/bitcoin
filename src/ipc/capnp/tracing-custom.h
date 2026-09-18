// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_IPC_CAPNP_TRACING_CUSTOM_H
#define BITCOIN_IPC_CAPNP_TRACING_CUSTOM_H

#include <interfaces/tracing.h>
#include <ipc/capnp/tracing.capnp.h>
#include <mp/proxy.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace mp {
//! Streaming delivery of net message trace batches.
//!
//! The generated client would send each batch with clientInvoke(), which hands
//! the call to the event loop thread and then blocks the caller until the
//! subscriber has answered. That round trip costs more node CPU than anything
//! else in the tracing path, and it is paid per batch no matter how few events
//! the batch holds, which is exactly the case for block-sized messages.
//!
//! messagesAsync() instead sends a messagesStream() request and returns as
//! soon as it is on the wire, handing the batch back through a callback when
//! the request completes. messagesStream() takes no Proxy.Context, so the
//! subscriber handles it on its own event loop rather than paying a second
//! thread handoff of its own.
template <>
class ProxyClientCustom<ipc::capnp::messages::NetMessageTrace, interfaces::NetMessageTrace>
    : public ProxyClientBase<ipc::capnp::messages::NetMessageTrace, interfaces::NetMessageTrace>
{
public:
    using ProxyClientBase::ProxyClientBase;

    ~ProxyClientCustom();

    bool canStream() const override { return true; }

    bool startStreaming(uint32_t interval_us,
                        std::function<bool(std::vector<interfaces::NetMessageInfo>&, uint64_t&)> drain,
                        std::function<void(std::vector<interfaces::NetMessageInfo>&, bool ok)> complete) override;
    void stopStreaming() override;

private:
    struct Streamer;
    //! Shared with the event loop so a tick in flight can never outlive us.
    std::shared_ptr<Streamer> m_streamer;
};
} // namespace mp

#endif // BITCOIN_IPC_CAPNP_TRACING_CUSTOM_H
