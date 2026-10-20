// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETSIM_NETWORK_H
#define BITCOIN_NETSIM_NETWORK_H

#include <net.h>
#include <netaddress.h>
#include <netsim/addresses.h>
#include <netsim/clock.h>
#include <netsim/eventqueue.h>
#include <netsim/latency.h>
#include <netsim/node.h>
#include <random.h>
#include <threadsafety.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <vector>

namespace netsim {

/** Which way along a link a chunk of bytes is travelling. */
enum class Direction {
    ToAcceptor,
    ToInitiator,
};

/** One simulated TCP connection between two nodes. */
struct Link {
    uint32_t initiator{0};
    uint32_t acceptor{0};
    CNode* out_side{nullptr};
    CNode* in_side{nullptr};

    /** Latest arrival already scheduled in each direction.
     *
     * TCP does not reorder, but jitter would: a later send drawing less jitter
     * than an earlier one would overtake it and the receiving transport would
     * see a corrupt stream. Each direction therefore keeps a watermark that
     * every new arrival is clamped past. */
    SimTime next_free_to_acceptor{};
    SimTime next_free_to_initiator{};

    /** Set once both CNode ends have been reaped.
     *
     * Connections do close on their own: a feeler hangs up during the VERSION
     * handler, and an addr-fetch connection after its first useful response.
     * A closed link keeps its slot in the vector so that event callbacks
     * holding its index stay valid, and the pointers are nulled as each end is
     * deleted. */
    bool closed{false};
};

/** A population of simulated nodes, the links between them, and the loop that
 *  drives both.
 *
 * Single-threaded by necessity rather than by choice: cs_main, mock time and
 * NetEventsInterface::g_msgproc_mutex are all process-wide, so every node's
 * message handling serialises through one lock anyway. The caller is expected
 * to hold g_msgproc_mutex for the whole run.
 */
class Network
{
public:
    struct Options {
        uint32_t num_nodes{100};
        /** The first `num_listening` nodes accept inbound connections. */
        uint32_t num_listening{20};
        /** Port every node's address carries. Zero means GetListenPort().
         *
         * Aligning with GetListenPort() is not cosmetic. When a node is told
         * its own address by a peer, GetLocalAddrForPeer rebuilds it as "the
         * IP the peer reported, on the port I believe I listen on", and
         * announces that. A universe on a different port therefore floods
         * every AddrMan with addresses nobody is reachable on. */
        uint16_t port{0};
        SimTime start{std::chrono::duration_cast<SimTime>(std::chrono::seconds{1'700'000'000})};
        /** How often each node is given a chance to flush queued sends.
         *
         * One second matches the resolution of what the nodes can observe, so
         * a finer tick would only burn events. */
        SimTime service_interval{std::chrono::seconds{1}};
        /** How often a node attempts one outbound connection.
         *
         * Mirrors the hard 500 ms sleep in ThreadOpenConnections, which is why
         * filling ten outbound slots takes a node at least five simulated
         * seconds no matter how fast the machine is. */
        SimTime open_conn_interval{std::chrono::milliseconds{500}};
        /** Listener addresses pre-loaded into each node's AddrMan.
         *
         * Stands in for hardcoded seeds. Zero leaves every AddrMan empty, in
         * which case no node can ever connect to anything. */
        uint32_t bootstrap_addrs{4};
        /** Advertise fRelay=false, as -blocksonly does. See MakeNode(). */
        bool blocks_only{false};
        /** Each node's connection budget, as -maxconnections sets it.
         *
         * Lowering it is the cheap way to reach the inbound cap, and so to
         * exercise eviction, without a population of hundreds. */
        int max_automatic_connections{DEFAULT_MAX_PEER_CONNECTIONS};
        RegionLatency::Options latency{};
        uint256 rng_seed{uint256{1}};
    };

    Network(Options opts, const SharedContext& ctx);
    ~Network();

    Network(const Network&) = delete;
    Network& operator=(const Network&) = delete;

    uint32_t NumNodes() const { return static_cast<uint32_t>(m_nodes.size()); }
    SimNode& At(uint32_t id);
    const SimNode& At(uint32_t id) const;
    SimClock& Clock() { return m_clock; }
    EventQueue& Queue() { return m_queue; }
    const AddressUniverse& Addresses() const { return m_universe; }

    /** The node listening on `addr`, if any. */
    std::optional<uint32_t> ListenerAt(const CService& addr) const;

    /** Open a connection from `from` to `to`.
     *
     * Returns false, without side effects, when `to` is not listening, is
     * `from` itself, is already connected to `from`, or has no inbound slot
     * left.
     */
    bool Connect(uint32_t from, uint32_t to, ConnectionType conn_type = ConnectionType::OUTBOUND_FULL_RELAY)
        EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex);

    /** Run until `duration` of simulated time has elapsed. */
    void RunFor(SimTime duration) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex);

    size_t LinkCount() const { return m_links.size(); }
    const std::vector<Link>& Links() const { return m_links; }
    /** Connections refused because the acceptor had no inbound slot free. */
    uint64_t InboundRefusals() const { return m_inbound_refusals; }
    /** Total bytes handed to the latency model, across every link. */
    uint64_t BytesTransferred() const { return m_bytes_transferred; }
    /** Outbound attempts whose chosen address had nobody listening on it. */
    uint64_t FailedAttempts() const { return m_failed_attempts; }
    /** Outbound attempts the node aimed at its own address.
     *
     * Core suppresses these with IsLocal(), which reads the process-global
     * mapLocalHost. One global table cannot express a per-node view of "my
     * own addresses", so the simulator filters them instead and counts them
     * here. A non-zero figure is expected, not a bug. */
    uint64_t SelfPicks() const { return m_self_picks; }
    /** Outbound attempts the acceptor turned away. */
    uint64_t RejectedAttempts() const { return m_rejected_attempts; }
    /** Links whose ends have both hung up, feelers included. */
    uint64_t ClosedLinks() const { return m_closed_links; }
    /** Inbound connections accepted by evicting an existing peer. */
    uint64_t Evictions() const { return m_evictions; }
    /** Connections opened, by connection type. */
    uint64_t OpenedOfType(ConnectionType type) const;

private:
    void ServiceEndpoint(size_t link_index, Direction outgoing)
        EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex);
    void ScheduleDelivery(size_t link_index, Direction outgoing, std::vector<uint8_t>&& wire);

    // Reached only through an event callback. The lock is held for the whole
    // run, but the analysis cannot see through std::function, so these assert
    // at runtime instead.
    void DeliverNow(size_t link_index, Direction outgoing, const std::vector<uint8_t>& wire)
        NO_THREAD_SAFETY_ANALYSIS;
    void ServiceNode(uint32_t id) NO_THREAD_SAFETY_ANALYSIS;
    /** One outbound attempt, using Core's own selection logic. */
    void TryOpenOutbound(uint32_t id) NO_THREAD_SAFETY_ANALYSIS;

    /** Close this node's links whose either end hung up, and delete its CNodes. */
    void ReapNode(uint32_t id) NO_THREAD_SAFETY_ANALYSIS;

    void Bootstrap();
    void ArmServiceTick(uint32_t id, SimTime at);
    void ArmOpenConnTick(uint32_t id, SimTime at);

    const Options m_opts;
    const SharedContext m_ctx;
    AddressUniverse m_universe;
    SimClock m_clock;
    EventQueue m_queue;
    RegionLatency m_latency;
    FastRandomContext m_rng;

    std::vector<std::unique_ptr<SimNode>> m_nodes;
    /** Stable storage: event callbacks capture indices into this. */
    std::vector<Link> m_links;
    std::vector<std::vector<size_t>> m_links_by_node;
    std::map<CService, uint32_t> m_listeners;

    NodeId m_next_node_id{0};
    uint64_t m_inbound_refusals{0};
    uint64_t m_bytes_transferred{0};
    uint64_t m_failed_attempts{0};
    uint64_t m_self_picks{0};
    uint64_t m_rejected_attempts{0};
    uint64_t m_closed_links{0};
    uint64_t m_evictions{0};
    std::map<ConnectionType, uint64_t> m_opened_by_type;
};

} // namespace netsim

#endif // BITCOIN_NETSIM_NETWORK_H
