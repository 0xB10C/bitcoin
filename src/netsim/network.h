// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETSIM_NETWORK_H
#define BITCOIN_NETSIM_NETWORK_H

#include <net.h>
#include <netaddress.h>
#include <netsim/addresses.h>
#include <netsim/chain.h>
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

    /** What the initiator opened this as. Kept on the link because the CNode
     *  that knew is deleted when the connection closes, and a closed feeler is
     *  exactly the thing an analysis wants to count. */
    ConnectionType conn_type{ConnectionType::OUTBOUND_FULL_RELAY};
    SimTime opened_at{};
    uint64_t bytes_to_acceptor{0};
    uint64_t bytes_to_initiator{0};

    /** Bumped every time this slot is recycled.
     *
     * A closed link's slot is reused, so a delivery queued before the recycle
     * would otherwise land on whatever connection took its place. Events carry
     * the generation they were scheduled under and are discarded if it no
     * longer matches. */
    uint32_t gen{0};

    /** Latest arrival already scheduled in each direction.
     *
     * TCP does not reorder, but jitter would: a later send drawing less jitter
     * than an earlier one would overtake it and the receiving transport would
     * see a corrupt stream. Each direction therefore keeps a watermark that
     * every new arrival is clamped past. */
    SimTime next_free_to_acceptor{};
    SimTime next_free_to_initiator{};

    /** Set once both CNode ends have been reaped, after which the slot is
     *  returned to the free list and may be recycled.
     *
     * Connections do close on their own: a feeler hangs up during the VERSION
     * handler, and an addr-fetch connection after its first useful response. */
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
         * which case no node can ever connect to anything.
         *
         * Sixteen rather than a handful, and the reason is performance rather
         * than realism. `AddrMan::Select()` picks a random slot out of 81,920
         * and retries until it finds an occupied one, so its cost scales
         * inversely with how full the table is. With four addresses a single
         * selection probes tens of thousands of slots, and
         * `TryPickOutboundAddress` makes up to a hundred selections per
         * attempt. Measured at 1000 nodes forming their topology: four
         * bootstrap addresses cost 147 seconds of wall clock, sixteen cost 5,
         * for the same resulting topology. Sparse-table selection was 97% of
         * the run. */
        uint32_t bootstrap_addrs{16};
        /** Advertise fRelay=false, as -blocksonly does. See MakeNode(). */
        bool blocks_only{false};
        /** Each node's connection budget, as -maxconnections sets it.
         *
         * Lowering it is the cheap way to reach the inbound cap, and so to
         * exercise eviction, without a population of hundreds. */
        int max_automatic_connections{DEFAULT_MAX_PEER_CONNECTIONS};
        /** Listeners whose addresses are withheld from the bootstrap seeding.
         *
         * The first `num_tracked` listening nodes. Nobody starts out knowing
         * them, so the only route their addresses have into the population is
         * Core's own address relay: the node learns its own address from the
         * `addr_recv` field of a peer's VERSION, announces it to that peer,
         * and the peer gossips it on to two more. How far and how fast that
         * gets is the measurement. */
        uint32_t num_tracked{0};
        /** How often to count who holds each tracked address. Zero disables.
         *
         * A sample is one hash lookup per (node, tracked address), so the cost
         * is small, but it is also a whole-population scan that the nodes
         * cannot see, so it does not belong on a fine schedule. */
        SimTime addr_sample_interval{std::chrono::duration_cast<SimTime>(std::chrono::minutes{1})};
        /** Network mix and netgroup shape of the population's addresses.
         *
         * Its `num_nodes`, `port` and `seed` are overwritten from the fields
         * above, so there is one source of truth for each. */
        AddressUniverse::Options addresses{};
        /** The shared chain: how long it starts out and how fast it grows.
         *
         * Needs `SharedContext::block_templates` and, to be announced at all,
         * `SharedContext::validation_signals`. */
        Chain::Options chain{};
        /** Mine a block every `chain.spacing` of simulated time.
         *
         * Off by default so that a run measuring topology or addresses pays
         * nothing for it. On, it is what keeps `ConsiderEviction` satisfied
         * without gating the check off. */
        bool mine{false};
        /** Give every node its own ChainstateManager.
         *
         * Required to study block relay, and pointless otherwise. With one
         * shared chain index `AlreadyHaveBlock` answers yes for every node the
         * instant any of them has a header, so no block is ever requested and
         * propagation cannot be observed. Costs 122,816 bytes per node. */
        bool per_node_chain{false};
        /** Where per-node block files go, one directory per node.
         *
         * Only read with `per_node_chain`. The databases are in memory; this
         * is for `blk*.dat`, which `fast_prune` keeps to 16 kB chunks. */
        fs::path datadir;
        /** Record the instant every node adopted every block.
         *
         * One row per (block, node), which is a propagation curve. Needs
         * `per_node_chain`: with one shared tip there is nothing to observe.
         * Costs about 40 bytes per row, so a thousand nodes and six blocks is
         * a quarter of a megabyte. */
        bool record_block_arrivals{true};
        /** Also record which peer each tracked address first came from.
         *
         * AddrMan keeps the source of every entry, so the address relay tree
         * is already there to be read; it just is not reachable through
         * `FindAddressEntry`. Reading it means walking the holder's tables,
         * which is why this is off by default, and why it is done only on the
         * one sample where a node first appears as a holder. */
        bool record_addr_sources{false};
        RegionLatency::Options latency{};
        uint256 rng_seed{uint256{1}};
    };

    /** When one node's tip first reached one block.
     *
     * The raw material of a propagation curve: one row per (block, node) pair,
     * in the order the nodes got there. Recorded from each node's own
     * `ValidationSignals`, so the instant is the one its chainstate actually
     * advanced rather than anything the simulator inferred.
     */
    struct BlockArrival {
        SimTime at{};
        uint32_t node{0};
        int height{0};
        uint256 hash;
        /** The peer it came from, or -1 for the node that mined it.
         *
         * Exact rather than inferred: a node adopts a block while handling
         * bytes from one particular peer, and the simulator knows which link
         * it was servicing. Together these are the propagation tree. */
        int32_t from{-1};
    };

    /** How an address got to a node. See `AddrArrival::path`. */
    enum class AddrPath {
        /** Forwarded by `RelayAddress`, which is what the ten-minute
         *  freshness gate and the two-peer cap apply to. */
        Pushed,
        /** Served in bulk out of a peer's table, answering GETADDR. Not
         *  age-limited, so it keeps working long after no push can. */
        Pulled,
    };

    /** When one node was first told one tracked address, and by whom.
     *
     * The address-relay counterpart of `BlockArrival`, and now the same kind
     * of evidence: read off the ADDR message as it is handled, so the instant
     * is the real one and the sender is exact. It used to be recovered by
     * polling AddrMan, which could only place an arrival within the sampling
     * interval and could not tell the two paths apart at all.
     */
    struct AddrArrival {
        SimTime at{};
        /** The node that now holds it. */
        uint32_t node{0};
        /** The tracked node whose address it is. */
        uint32_t address_of{0};
        /** The peer that sent it, or -1 if that peer is not a node here. */
        int32_t from{-1};
        /** Which of the two mechanisms delivered it.
         *
         * Taken from the size of the message it arrived in, which is the same
         * test `ProcessAddrs` itself applies: at most ten addresses is a
         * forwarded announcement, more than that is a table dump. */
        AddrPath path{AddrPath::Pushed};
        /** Whether this node went on to forward it. False once the
         *  announcement is past the ten-minute gate. */
        bool relayed{false};
    };

    /** How widely one tracked address had spread, at one instant. */
    struct AddrSample {
        SimTime at{};
        /** The node whose address this is. */
        uint32_t node{0};
        /** Nodes holding it in either AddrMan table, the owner excluded. */
        uint32_t holders{0};
        /** Of those, how many have it in `tried` rather than `new`. */
        uint32_t in_tried{0};
        /** Summed new-table multiplicity, which counts distinct sources that
         *  announced it rather than distinct holders. */
        uint32_t multiplicity{0};
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
    const SharedContext& Context() const { return m_ctx; }
    const RegionLatency& Latency() const { return m_latency; }
    const Options& GetOptions() const { return m_opts; }
    /** The instant the run began, so exported timestamps can be made relative. */
    SimTime StartTime() const { return m_opts.start; }

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

    /** Connections opened over the whole run, closed ones included. */
    uint64_t TotalOpened() const { return m_total_opened; }
    /** Connections still up. This is what the export contains. */
    uint64_t LiveLinks() const { return m_live_links; }
    /** Slots currently allocated, bounded by the peak concurrent count rather
     *  than by every connection the run ever made. Closed links are recycled,
     *  so iterate this only with the `closed` flag in hand. */
    size_t LinkSlots() const { return m_links.size(); }
    const std::vector<Link>& Links() const { return m_links; }
    /** Connections refused because the acceptor had no inbound slot free. */
    uint64_t InboundRefusals() const { return m_inbound_refusals; }
    /** Total bytes handed to the latency model, across every link. */
    uint64_t BytesTransferred() const { return m_bytes_transferred; }
    /** Outbound attempts whose chosen address had nobody listening on it. */
    uint64_t FailedAttempts() const { return m_failed_attempts; }
    /** Outbound attempts the node aimed at its own address.
     *
     * Core suppresses these inside its selection loop via LocalAddresses,
     * which a listening node here is given, so this should now be zero for a
     * listening node. It can still be non-zero for a non-listening one, which
     * has no address of its own to record. */
    uint64_t SelfPicks() const { return m_self_picks; }
    /** Outbound attempts the acceptor turned away. */
    uint64_t RejectedAttempts() const { return m_rejected_attempts; }
    /** Links whose ends have both hung up, feelers included. */
    uint64_t ClosedLinks() const { return m_closed_links; }
    /** Inbound connections accepted by evicting an existing peer. */
    uint64_t Evictions() const { return m_evictions; }
    /** Connections opened, by connection type. */
    uint64_t OpenedOfType(ConnectionType type) const;

    /** Distinct netgroups across the population, as Core computes them.
     *
     * Worth reporting rather than assuming. A node needs ten distinct
     * netgroups among its candidates to fill ten outbound slots, except that
     * Tor and I2P peers are exempt, so a Tor-heavy population saturates on
     * far fewer groups than it appears to have.
     */
    uint32_t NumNetgroups() const;

    /** The chain the whole population shares. */
    const Chain& GetChain() const { return *m_chain; }
    /** The miner, for a test that wants to mine one block at a chosen instant. */
    Chain& GetChain() { return *m_chain; }
    int ChainHeight() const { return m_chain->Height(); }

    /** The nodes whose addresses were withheld from the bootstrap seeding. */
    const std::vector<uint32_t>& TrackedNodes() const { return m_tracked; }
    /** Every coverage sample taken over the run, in time order. */
    const std::vector<AddrSample>& AddrSamples() const { return m_addr_samples; }
    /** Every per-node block arrival, in time order. Empty without
     *  `per_node_chain`, where all nodes share one tip and there is nothing to
     *  observe. */
    const std::vector<BlockArrival>& BlockArrivals() const { return m_block_arrivals; }
    /** Every first-time address acquisition, in time order. Empty unless the
     *  run tracked addresses. */
    const std::vector<AddrArrival>& AddrArrivals() const { return m_addr_arrivals; }

private:
    void ServiceEndpoint(size_t link_index, Direction outgoing)
        EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex);
    void ScheduleDelivery(size_t link_index, Direction outgoing, std::vector<uint8_t>&& wire);

    // Reached only through an event callback. The lock is held for the whole
    // run, but the analysis cannot see through std::function, so these assert
    // at runtime instead.
    void DeliverNow(size_t link_index, uint32_t gen, Direction outgoing, const std::vector<uint8_t>& wire)
        NO_THREAD_SAFETY_ANALYSIS;
    void ServiceNode(uint32_t id) NO_THREAD_SAFETY_ANALYSIS;
    /** One outbound attempt, using Core's own selection logic. */
    void TryOpenOutbound(uint32_t id) NO_THREAD_SAFETY_ANALYSIS;

    /** Close this node's links whose either end hung up, and delete its CNodes. */
    void ReapNode(uint32_t id) NO_THREAD_SAFETY_ANALYSIS;

    void Bootstrap();
    void ArmServiceTick(uint32_t id, SimTime at);
    void ArmOpenConnTick(uint32_t id, SimTime at);
    void ArmAddrSample(SimTime at);
    void ArmMineTick(SimTime at);
    /** Count, for each tracked address, how many nodes now hold it. */
    void SampleAddrCoverage();
    /** One address arriving at one node, straight off the message. */
    void NoteAddrReceived(uint32_t receiver, const AddrReceipt& receipt);

    const Options m_opts;
    const SharedContext m_ctx;
    AddressUniverse m_universe;
    SimClock m_clock;
    EventQueue m_queue;
    RegionLatency m_latency;
    /** Built after the nodes, because with a chain each the miner.s own
     *  ChainstateManager does not exist until then. */
    std::unique_ptr<node::BlockTemplateManager> m_miner_templates;
    std::unique_ptr<Chain> m_chain;
    FastRandomContext m_rng;

    std::vector<std::unique_ptr<SimNode>> m_nodes;
    /** Stable storage: event callbacks capture an index plus a generation. */
    std::vector<Link> m_links;
    /** Slots of closed links, available for the next connection. */
    std::vector<size_t> m_free_links;
    std::vector<std::vector<size_t>> m_links_by_node;
    std::map<CService, uint32_t> m_listeners;
    /** Every node keyed by host, for turning the address of the peer that
     *  sent a message back into a node id. Not just the listeners: a node that
     *  only dials out still sends ADDR messages. */
    std::map<CNetAddr, uint32_t> m_nodes_by_host;
    /** The tracked addresses, keyed by host, so the arrival hook can decide in
     *  one lookup whether an address is one it cares about. */
    std::map<CNetAddr, uint32_t> m_tracked_by_host;
    std::vector<uint32_t> m_tracked;
    std::vector<AddrSample> m_addr_samples;

    /** One per node, subscribed to that node's own tip notifications.
     *
     * Defined in network.cpp: it is a CValidationInterface subclass and
     * nothing outside needs its shape. */
    class TipRecorder;
    std::vector<std::unique_ptr<TipRecorder>> m_tip_recorders;
    std::vector<BlockArrival> m_block_arrivals;
    std::vector<AddrArrival> m_addr_arrivals;
    /** Which nodes already held each tracked address, so a sample can emit
     *  only what is new. Indexed [tracked][node]. */
    std::vector<std::vector<bool>> m_addr_seen;
    /** The peer whose messages are being handled right now, or -1. Read by
     *  the tip recorders to attribute an arrival. See ServiceEndpoint. */
    int32_t m_attributed_peer{-1};

    NodeId m_next_node_id{0};
    uint64_t m_inbound_refusals{0};
    uint64_t m_bytes_transferred{0};
    uint64_t m_failed_attempts{0};
    uint64_t m_self_picks{0};
    uint64_t m_rejected_attempts{0};
    uint64_t m_closed_links{0};
    uint64_t m_total_opened{0};
    uint64_t m_live_links{0};
    uint64_t m_evictions{0};
    std::map<ConnectionType, uint64_t> m_opened_by_type;
};

} // namespace netsim

#endif // BITCOIN_NETSIM_NETWORK_H
