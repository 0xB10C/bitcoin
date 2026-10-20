// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netsim/node.h>

#include <chainparams.h>
#include <hash.h>
#include <netgroup.h>
#include <protocol.h>
#include <uint256.h>

#include <string>
#include <utility>

namespace netsim {

namespace {
//! Domain separators, so that the several values derived per node are independent.
const std::string SEED_ADDRMAN{"netsim/addrman"};
const std::string SEED_CONNMAN{"netsim/connman"};
const std::string SEED_PEERMAN{"netsim/peerman"};
const std::string SEED_NONCE{"netsim/nonce"};
const std::string SEED_NETWORK_KEY{"netsim/networkkey"};

//! Our own randomizer id for keyed netgroups. Any fixed value works; see KeyedNetGroup().
constexpr uint64_t NETSIM_RANDOMIZER_ID_NETGROUP{0x6e7473696d6e6700ULL};

uint256 DeriveHash(const std::string& domain, uint32_t id, uint32_t extra = 0)
{
    HashWriter writer{};
    writer << domain << id << extra;
    return writer.GetHash();
}

uint64_t DeriveUint64(const std::string& domain, uint32_t id, uint32_t extra = 0)
{
    return DeriveHash(domain, id, extra).GetUint64(0);
}

/** A keyed netgroup value for a peer.
 *
 * CConnman::CalculateKeyedNetGroup is private and the randomizer id it uses is
 * file-local to net.cpp, so this mirrors the intent rather than the exact
 * derivation: peers sharing a netgroup get the same value, and the mapping
 * differs per node. Only eviction grouping consumes it, and that only cares
 * about which peers collide.
 */
uint64_t KeyedNetGroup(const ConnmanTestMsg& connman, const NetGroupManager& netgroupman, const CNetAddr& addr)
{
    const std::vector<unsigned char> group{netgroupman.GetGroup(addr)};
    return connman.GetDeterministicRandomizer(NETSIM_RANDOMIZER_ID_NETGROUP).Write(group).Finalize();
}
} // namespace

SimNode::~SimNode()
{
    // Order matters and is not obvious. ~CConnman calls Stop(), which deletes
    // every CNode still registered with it, and does so through
    // m_msgproc->FinalizeNode. So the PeerManager has to outlive the CConnman,
    // and the AddrMan has to outlive both because CConnman holds a reference
    // to it. Tearing down explicitly rather than relying on member
    // declaration order keeps that from breaking silently on a reorder.
    connman.reset();
    peerman.reset();
    addrman.reset();
}

std::unique_ptr<SimNode> MakeNode(const SharedContext& ctx, uint32_t id, const CService& self, bool listening)
{
    auto node{std::make_unique<SimNode>()};
    node->id = id;
    node->self = self;
    node->listening = listening;

    // A per-instance seed rather than `deterministic`: the latter would give
    // every node the bucketing key uint256{1} and a zero-keyed RNG, so the
    // whole population would bucket and select in lockstep.
    node->addrman = std::make_unique<AddrMan>(ctx.netgroupman,
                                              /*deterministic=*/false,
                                              /*consistency_check_ratio=*/0,
                                              DeriveHash(SEED_ADDRMAN, id));

    // Distinct CConnman seeds are not cosmetic. RelayAddress chooses its two
    // destinations with GetDeterministicRandomizer(RANDOMIZER_ID_ADDRESS_RELAY),
    // so nodes sharing seeds would pick correlated relay targets and the
    // measured topology would describe the seed instead of the protocol.
    node->connman = std::make_unique<ConnmanTestMsg>(DeriveUint64(SEED_CONNMAN, id, 0),
                                                     DeriveUint64(SEED_CONNMAN, id, 1),
                                                     *node->addrman, ctx.netgroupman, Params());

    PeerManager::Options peerman_opts;
    peerman_opts.max_extra_txs = 0;
    // Its own stream, for the same reason AddrMan gets one. m_rng drives the
    // Poisson address-send and inventory timers, so a shared stream would put
    // every node on the same schedule and an OS-seeded one would make the run
    // unrepeatable.
    peerman_opts.rng_seed = DeriveHash(SEED_PEERMAN, id);
    // banman is null on purpose: a per-node BanMan would cost 539 KiB for its
    // discouragement filter, and nothing here misbehaves.
    node->peerman = PeerManager::make(*node->connman, *node->addrman, /*banman=*/nullptr,
                                      ctx.chainman, ctx.mempool, ctx.warnings, peerman_opts);

    CConnman::Options conn_opts;
    conn_opts.m_msgproc = node->peerman.get();
    // Both flags are required. With PeerManager::SetBestBlock never called,
    // GetDesirableServiceFlags() always demands NODE_NETWORK and NODE_WITNESS,
    // and an outbound peer offering less is disconnected during the handshake.
    conn_opts.m_local_services = ServiceFlags(NODE_NETWORK | NODE_WITNESS);
    conn_opts.nSendBufferMaxSize = SEND_BUFFER_BYTES;
    conn_opts.nReceiveFloodSize = RECV_FLOOD_BYTES;
    // Init(), never Start(): Start() spawns four threads unconditionally, which
    // at any interesting population size is the end of the experiment.
    node->connman->Init(conn_opts);

    return node;
}

ConnPair ConnectPair(const SharedContext& ctx, SimNode& from, SimNode& to, NodeId out_id, NodeId in_id)
{
    constexpr auto SERVICES{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};

    const auto make_opts{[] {
        CNodeOptions opts;
        opts.recv_flood_size = RECV_FLOOD_BYTES;
        // V1 on purpose. V2Transport embeds a whole V1Transport as its
        // fallback, adds a BIP324 cipher state and generates a keypair per
        // connection, and none of that is under study here.
        opts.use_v2transport = false;
        return opts;
    }};

    // The sock is null throughout. CNode's constructor never dereferences it,
    // CConnman::SocketSendData explicitly bails out when it is absent, and we
    // never run SocketHandler.
    auto* out_side{new CNode{
        out_id,
        /*sock=*/nullptr,
        CAddress{to.self, SERVICES},
        KeyedNetGroup(*from.connman, ctx.netgroupman, to.self),
        DeriveUint64(SEED_NONCE, from.id, static_cast<uint32_t>(out_id)),
        /*addrBindIn=*/from.self,
        /*addrNameIn=*/"",
        ConnectionType::OUTBOUND_FULL_RELAY,
        /*inbound_onion=*/false,
        DeriveUint64(SEED_NETWORK_KEY, from.id),
        make_opts()}};

    auto* in_side{new CNode{
        in_id,
        /*sock=*/nullptr,
        CAddress{from.self, SERVICES},
        KeyedNetGroup(*to.connman, ctx.netgroupman, from.self),
        DeriveUint64(SEED_NONCE, to.id, static_cast<uint32_t>(in_id)),
        /*addrBindIn=*/to.self,
        /*addrNameIn=*/"",
        ConnectionType::INBOUND,
        /*inbound_onion=*/false,
        DeriveUint64(SEED_NETWORK_KEY, to.id),
        make_opts()}};

    from.peerman->InitializeNode(*out_side, SERVICES);
    from.connman->AddTestNode(*out_side);

    to.peerman->InitializeNode(*in_side, SERVICES);
    to.connman->AddTestNode(*in_side);

    return ConnPair{out_side, in_side};
}

} // namespace netsim
