// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETSIM_PUMP_H
#define BITCOIN_NETSIM_PUMP_H

#include <net.h>
#include <netsim/node.h>
#include <test/util/net.h>

#include <cstdint>
#include <span>
#include <vector>

namespace netsim {

/** Move a connection's queued messages onto the wire, returning the bytes.
 *
 * This is CConnman::SocketSendData with the socket taken out. It is not
 * ConnmanTestMsg::FlushSendBuffer, which clears vSendMsg before draining the
 * transport and so discards the queued messages rather than transmitting
 * them. That function exists to throw fuzzer output away.
 */
std::vector<uint8_t> Drain(CNode& conn);

/** Hand wire bytes to a connection's receive side and mark them for processing. */
void Deliver(const ConnmanTestMsg& connman, CNode& conn, std::span<const uint8_t> bytes);

/** Run a connection's message handler until it reports no more work.
 *
 * SendMessages() runs on every pass, including the first one, and that is
 * load-bearing rather than tidy. InitializeNode() does not send VERSION;
 * PeerManager pushes it lazily from SendMessages(), and ProcessMessages()
 * refuses to act on an outbound peer until that has happened. Call
 * ProcessMessages first and alone, and the simulation sits there with an empty
 * queue and no error.
 */
void Process(SimNode& node, CNode& conn) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex);

} // namespace netsim

#endif // BITCOIN_NETSIM_PUMP_H
