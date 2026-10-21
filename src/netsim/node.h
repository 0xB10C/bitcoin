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
#include <util/fs.h>

#include <cstdint>
#include <memory>

class ChainstateManager;
class CTxMemPool;
class NetGroupManager;
class ValidationSignals;
namespace util { class SignalInterrupt; }
namespace node {
class BlockTemplateManager;
class KernelNotifications;
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
 * AddrMan, CConnman and PeerManager are the real, unmodified classes. A node
 * shares the population's CTxMemPool, and shares its ChainstateManager unless
 * the run asked for block relay, which needs one each: see `own_chainman`.
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

    /** The connection-opening timers this node carries between attempts.
     *
     * In production these are locals of ThreadOpenConnections. One per node
     * here, because each node runs its own loop. */
    CConnman::OutboundTimers timers;
    /** This node's own RNG for connection scheduling, seeded per node so the
     *  feeler and extra-peer timers do not march in lockstep. Held by pointer
     *  because FastRandomContext is neither copyable nor movable. */
    std::unique_ptr<FastRandomContext> rng;

    /** Where this node's PeerManager is subscribed, so the destructor can
     *  unsubscribe it. Null when tip notifications are not published. */
    ValidationSignals* subscribed{nullptr};

    /** The chain this node validates against.
     *
     * Either `own_chainman` below or the population's shared one. Never null
     * after MakeNode. */
    ChainstateManager* chainman{nullptr};
    /** This node's own chain, when the run gives each node one.
     *
     * Required for block relay and for nothing else: `AlreadyHaveBlock` asks
     * only whether the header sits in its block index, so a population sharing
     * one index has every block the instant any node does, and no block is
     * ever requested. Measured at 122,816 bytes per node, and no extra
     * threads provided the script-check pools are sized to zero.
     *
     * Declared after the members above so that it outlives them: the
     * destructor tears down explicitly in any case. */
    std::unique_ptr<ValidationSignals> own_signals;
    std::unique_ptr<ChainstateManager> own_chainman;

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
    /** Where block-tip notifications are published.
     *
     * Every node's PeerManager subscribes, exactly as `init.cpp` does with the
     * single production one, so a new block reaches every node's announcement
     * path. Null leaves the nodes unsubscribed, in which case nothing is ever
     * announced and the chain-sync timer in §8 has to be gated off instead. */
    ValidationSignals* validation_signals{nullptr};
    /** Used by `Chain` to mine. Null means the chain cannot be extended. */
    node::BlockTemplateManager* block_templates{nullptr};
    /** Needed only to build a node its own ChainstateManager and, for the
     *  miner, its own BlockTemplateManager. Shared because neither carries
     *  per-node state. */
    node::KernelNotifications* kernel_notifications{nullptr};
    const util::SignalInterrupt* interrupt{nullptr};
};

/** What one simulated node needs to be built. */
struct NodeOptions {
    uint32_t id{0};
    /** This node's own address, as its peers see it. */
    CService self;
    /** Whether anyone may open an inbound connection to it. */
    bool listening{false};
    /** Advertise fRelay=false, as `-blocksonly` does.
     *
     * For a study of topology or address relay that costs nothing in fidelity
     * and saves a great deal of memory: a peer offering transaction relay gets
     * a `Peer::TxRelay`, whose inventory filter is a 527 KiB rolling bloom
     * allocated eagerly, and at roughly sixteen peers per node that one
     * structure is around 8.5 MB. It dominates every other per-node cost,
     * including AddrMan. */
    bool blocks_only{false};
    /** This node's connection budget, as `-maxconnections` sets it. */
    int max_automatic_connections{DEFAULT_MAX_PEER_CONNECTIONS};
    /** Give this node its own ChainstateManager. See `SimNode::own_chainman`. */
    bool own_chain{false};
    /** Where this node's block files go. Only read when `own_chain` is set.
     *
     * The databases are in memory, but BlockManager still wants a directory
     * for `blk*.dat`, so this is the one part of a simulated node that touches
     * a filesystem. `fast_prune` keeps the files to 16 kB chunks. */
    fs::path datadir;
};

/** Build one node, with its own AddrMan keyspace and its own CConnman seeds. */
std::unique_ptr<SimNode> MakeNode(const SharedContext& ctx, const NodeOptions& opts);

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
ConnPair ConnectPair(SimNode& from, SimNode& to, ConnectionType conn_type, NodeId out_id,
                     NodeId in_id);

} // namespace netsim

#endif // BITCOIN_NETSIM_NODE_H
