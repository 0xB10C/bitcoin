// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netsim/pump.h>

#include <net.h>
#include <sync.h>
#include <util/time.h>

namespace netsim {

std::vector<uint8_t> Drain(CNode& conn)
{
    std::vector<uint8_t> wire;
    LOCK(conn.cs_vSend);

    while (true) {
        // Feed the transport from the message queue when it can take another one.
        if (!conn.vSendMsg.empty()) {
            if (conn.m_transport->SetMessageToSend(conn.vSendMsg.front())) {
                conn.vSendMsg.pop_front();
            }
        }

        // The span points into transport-owned storage, so copy before
        // acknowledging the bytes.
        const auto& [to_send, more, msg_type] = conn.m_transport->GetBytesToSend(!conn.vSendMsg.empty());
        if (to_send.empty()) break;
        wire.insert(wire.end(), to_send.begin(), to_send.end());

        // Mirror SocketSendData's accounting. Not cosmetic: the per-message-type
        // totals are how a run reports how many bytes went to ADDR traffic.
        conn.m_last_send = NodeClock::now();
        conn.nSendBytes += to_send.size();
        if (!msg_type.empty()) conn.AccountForSentBytes(msg_type, to_send.size());

        conn.m_transport->MarkBytesSent(to_send.size());
    }

    // Nothing else clears the back-pressure flag once the socket thread is
    // gone, and a node that keeps it set quietly stops sending.
    conn.m_send_memusage = 0;
    conn.fPauseSend = false;
    return wire;
}

void Deliver(const ConnmanTestMsg& connman, CNode& conn, std::span<const uint8_t> bytes)
{
    bool complete{false};
    connman.NodeReceiveMsgBytes(conn, bytes, complete);
}

void Process(SimNode& node, CNode& conn)
{
    bool more_work{true};
    while (more_work) {
        conn.fPauseRecv = false;
        more_work = node.connman->ProcessMessagesOnce(conn);
        node.peerman->SendMessages(conn);
    }
}

} // namespace netsim
