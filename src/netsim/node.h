// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETSIM_NODE_H
#define BITCOIN_NETSIM_NODE_H

#include <addrman.h>
#include <net.h>
#include <net_processing.h>
#include <netaddress.h>
#include <test/util/net.h>

#include <cstdint>
#include <memory>

class ChainstateManager;
class CTxMemPool;
class NetGroupManager;
namespace node {
class Warnings;
} // namespace node

namespace netsim {

/** Per-node receive and send buffer caps.
 *
 * Far below the 5 MB and 1 MB production defaults. At scale those defaults
 * dominate every other per-node cost, and nothing in this simulation needs
 * deep queues: the largest message in play is a 1000-entry ADDR.
 */
static constexpr unsigned int RECV_FLOOD_BYTES{1 << 20};
static constexpr unsigned int SEND_BUFFER_BYTES{1 << 18};

/** Everything one simulated node owns.
 *
 * AddrMan, CConnman and PeerManager are the real, unmodified classes. What a
 * node does not own is a ChainstateManager or a CTxMemPool: both are shared
 * across the whole simulation. An empty regtest chainstate costs tens of
 * megabytes, and the address-relay path only ever reads it.
 */
struct SimNode {
    uint32_t id{0};
    /** This node's own address, as its peers see it. */
    CService self;
    /** Whether anyone may open an inbound connection to it. */
    bool listening{false};

    std::unique_ptr<AddrMan> addrman;
    std::unique_ptr<PeerManager> peerman;
    std::unique_ptr<ConnmanTestMsg> connman;

    SimNode() = default;
    ~SimNode();
    SimNode(const SimNode&) = delete;
    SimNode& operator=(const SimNode&) = delete;
};

/** The state every simulated node points at but none of them owns. */
struct SharedContext {
    ChainstateManager& chainman;
    CTxMemPool& mempool;
    node::Warnings& warnings;
    const NetGroupManager& netgroupman;
};

/** Build one node, with its own AddrMan keyspace and its own CConnman seeds. */
std::unique_ptr<SimNode> MakeNode(const SharedContext& ctx, uint32_t id, const CService& self, bool listening);

/** The two CNode ends of one simulated connection.
 *
 * Both are owned by their respective CConnman, which deletes them on
 * destruction by way of PeerManager::FinalizeNode.
 */
struct ConnPair {
    CNode* out_side{nullptr};
    CNode* in_side{nullptr};
};

/** Open a simulated connection from `from` to `to`.
 *
 * Creates both CNode ends, registers each with its own CConnman and
 * initialises both peers. Deliberately does not go through
 * CConnman::ConnectNode, which performs real name resolution and a real socket
 * connect, and whose two delegates have no injection hook.
 *
 * The node ids only have to be unique within each node's own CConnman, but the
 * caller is expected to keep them globally unique so that logs can be read.
 */
ConnPair ConnectPair(const SharedContext& ctx, SimNode& from, SimNode& to, NodeId out_id, NodeId in_id);

} // namespace netsim

#endif // BITCOIN_NETSIM_NODE_H
