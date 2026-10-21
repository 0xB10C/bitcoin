// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netsim/node.h>

#include <chainparams.h>
#include <hash.h>
#include <netgroup.h>
#include <protocol.h>
#include <random.h>
#include <uint256.h>
#include <util/time.h>

#include <string>
#include <utility>

namespace netsim {

namespace {
//! Domain separators, so that the several values derived per node are independent.
const std::string SEED_ADDRMAN{"netsim/addrman"};
const std::string SEED_CONNMAN{"netsim/connman"};
const std::string SEED_PEERMAN{"netsim/peerman"};
const std::string SEED_SCHEDULER{"netsim/scheduler"};
const std::string SEED_NONCE{"netsim/nonce"};
const std::string SEED_NETWORK_KEY{"netsim/networkkey"};

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

} // namespace

SimNode::~SimNode()
{
    // Order matters and is not obvious. ~CConnman calls Stop(), which deletes
    // every CNode still registered with it, and does so through
    // m_msgproc->FinalizeNode. So the PeerManager has to outlive the CConnman,
    // and the AddrMan has to outlive both because CConnman holds a reference
    // to it. Tearing down explicitly rather than relying on member
    // declaration order keeps that from breaking silently on a reorder.
    //
    // Unsubscribing comes first, or the signal list keeps a dangling pointer
    // and the next block tip calls into freed memory.
    if (subscribed != nullptr && peerman != nullptr) {
        subscribed->UnregisterValidationInterface(peerman.get());
    }
    connman.reset();
    peerman.reset();
    addrman.reset();
}

std::unique_ptr<SimNode> MakeNode(const SharedContext& ctx, uint32_t id, const CService& self, bool listening,
                                  bool blocks_only, int max_automatic_connections)
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
    // Advertising fRelay=false stops the peer allocating a Peer::TxRelay for
    // us, and so stops its 527 KiB inventory bloom filter being allocated
    // eagerly. At sixteen peers a node that is around 8.5 MB, which dominates
    // everything else including AddrMan's 640 KiB.
    peerman_opts.ignore_incoming_txs = blocks_only;
    // Its own stream, for the same reason AddrMan gets one. m_rng drives the
    // Poisson address-send and inventory timers, so a shared stream would put
    // every node on the same schedule and an OS-seeded one would make the run
    // unrepeatable.
    peerman_opts.rng_seed = DeriveHash(SEED_PEERMAN, id);
    // With no block ever mined, no node announces one, and ConsiderEviction
    // disconnects every node's headers-sync peer every twenty minutes. That is
    // Core behaving correctly given a static chain, and it caps a usable run
    // at twenty simulated minutes. A run with a chain that advances needs no
    // such gate, so the gate follows whether tip notifications are published
    // at all.
    peerman_opts.disable_chain_sync_timeout = ctx.validation_signals == nullptr;
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
    // Per-node, rather than the process-global fListen. Without this every node
    // self-announces, including the ones nobody can reach, and most of the
    // addresses in circulation end up pointing nowhere.
    conn_opts.m_listen = listening;
    conn_opts.m_max_automatic_connections = max_automatic_connections;
    conn_opts.nSendBufferMaxSize = SEND_BUFFER_BYTES;
    conn_opts.nReceiveFloodSize = RECV_FLOOD_BYTES;
    // Init(), never Start(): Start() spawns four threads unconditionally, which
    // at any interesting population size is the end of the experiment.
    node->connman->Init(conn_opts);

    // Tell the node its own address, which is what a real node learns from the
    // Tor control port, from -i2psam, or from -externalip. Without this an
    // onion or I2P node never self-announces and its address can only spread
    // if something was seeded with it: `version`'s addr_recv field is
    // V1-serialized, and CNetAddr::SerializeV1Array writes onion and I2P
    // addresses as all-zeros, so the peer-reported route an IPv4 node relies
    // on carries nothing. `add_even_if_unreachable` because -externalip is the
    // closest production analogue and says so outright.
    if (listening) {
        node->connman->LocalAddrs().Add(self, LOCAL_MANUAL, /*add_even_if_unreachable=*/true);
    }

    // Arm the connection-opening timers from the same clock ThreadOpenConnections
    // uses, so comparisons against GetTime<microseconds>() line up.
    node->rng = std::make_unique<FastRandomContext>(DeriveHash(SEED_SCHEDULER, id));
    node->timers.Arm(GetTime<std::chrono::microseconds>(), *node->rng);

    // Subscribe to tip notifications, as init.cpp does for the single
    // production PeerManager. This is what makes a new block reach every
    // node's announcement path rather than only the miner's.
    if (ctx.validation_signals != nullptr) {
        ctx.validation_signals->RegisterValidationInterface(node->peerman.get());
        node->subscribed = ctx.validation_signals;
    }

    return node;
}

ConnPair ConnectPair(SimNode& from, SimNode& to, ConnectionType conn_type, NodeId out_id,
                     NodeId in_id)
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
    //
    // inbound_onion stays false even for an onion peer. The flag exists because
    // a real inbound Tor connection arrives from the SOCKS proxy on loopback,
    // so `addr` does not say which network it came over; here `addr` is the
    // peer's actual onion address and ConnectedThroughNetwork() already answers
    // NET_ONION from it.
    auto* out_side{new CNode{
        out_id,
        /*sock=*/nullptr,
        CAddress{to.self, SERVICES},
        from.connman->CalculateKeyedNetGroupPublic(to.self),
        DeriveUint64(SEED_NONCE, from.id, static_cast<uint32_t>(out_id)),
        /*addrBindIn=*/from.self,
        /*addrNameIn=*/"",
        conn_type,
        /*inbound_onion=*/false,
        DeriveUint64(SEED_NETWORK_KEY, from.id),
        make_opts()}};

    auto* in_side{new CNode{
        in_id,
        /*sock=*/nullptr,
        CAddress{from.self, SERVICES},
        to.connman->CalculateKeyedNetGroupPublic(from.self),
        DeriveUint64(SEED_NONCE, to.id, static_cast<uint32_t>(in_id)),
        /*addrBindIn=*/to.self,
        /*addrNameIn=*/"",
        ConnectionType::INBOUND,
        /*inbound_onion=*/false,
        DeriveUint64(SEED_NETWORK_KEY, to.id),
        make_opts()}};

    // AddRef() for the reference m_nodes itself holds, exactly as
    // CreateNodeFromAcceptedSocket and OpenNetworkConnection do.
    // ConnmanTestMsg::AddTestNode skips it, which is fine only for tests that
    // never disconnect: DisconnectNodes() releases that reference, and without
    // it the count goes negative and CNode::GetRefCount asserts.
    out_side->AddRef();
    from.peerman->InitializeNode(*out_side, SERVICES);
    from.connman->AddTestNode(*out_side);

    in_side->AddRef();
    to.peerman->InitializeNode(*in_side, SERVICES);
    to.connman->AddTestNode(*in_side);

    return ConnPair{out_side, in_side};
}

} // namespace netsim
