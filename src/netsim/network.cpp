// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netsim/network.h>

#include <net.h>
#include <netgroup.h>
#include <netsim/pump.h>
#include <node/block_template_manager.h>
#include <node/miner.h>
#include <primitives/block.h>
#include <validation.h>
#include <validationinterface.h>
#include <sync.h>
#include <threadsafety.h>
#include <util/check.h>
#include <util/string.h>
#include <util/time.h>

#include <algorithm>
#include <set>
#include <utility>

namespace netsim {

namespace {
Direction Opposite(Direction d)
{
    return d == Direction::ToAcceptor ? Direction::ToInitiator : Direction::ToAcceptor;
}
} // namespace

/** Notes the instant one node's tip reaches a block.
 *
 * Subscribed to that one node's `ValidationSignals`, which only exists when
 * the run gives each node its own chain. `UpdatedBlockTip` rather than
 * `BlockConnected` because the question is when the node *adopted* the block,
 * which is also the instant from which it will announce it onward.
 */
class Network::TipRecorder final : public CValidationInterface
{
public:
    TipRecorder(uint32_t node, std::function<void(uint32_t, const CBlockIndex&)> note)
        : m_node{node}, m_note{std::move(note)}
    {
    }

protected:
    void UpdatedBlockTip(const CBlockIndex* new_tip, const CBlockIndex* /*fork*/,
                         bool /*initial_download*/) override
    {
        if (new_tip != nullptr) m_note(m_node, *new_tip);
    }

private:
    const uint32_t m_node;
    const std::function<void(uint32_t, const CBlockIndex&)> m_note;
};

namespace {
Network::Options ResolveOptions(Network::Options opts)
{
    if (opts.port == 0) opts.port = GetListenPort();
    opts.addresses.num_nodes = opts.num_nodes;
    opts.addresses.port = opts.port;
    opts.addresses.seed = opts.rng_seed;
    // Chain derives its own stream from this, so the block schedule is
    // reproducible and does not shift when anything else changes how often it
    // draws.
    opts.chain.rng_seed = opts.rng_seed;
    return opts;
}
} // namespace

Network::Network(Options opts_in, const SharedContext& ctx)
    : m_opts{ResolveOptions(opts_in)},
      m_ctx{ctx},
      m_universe{m_opts.addresses},
      m_clock{m_opts.start},
      m_latency{m_opts.latency},
      m_rng{m_opts.rng_seed}
{
    Assert(m_opts.num_listening <= m_opts.num_nodes);
    Assert(m_opts.num_tracked <= m_opts.num_listening);
    Assert(m_opts.num_nodes > 0);

    // With one shared chain, prefill before any node exists, so they come up on
    // a chain that is already there rather than watching it appear. With a
    // chain each, the miner's own does not exist yet and the prefill has to
    // wait until after the node loop.
    if (!m_opts.per_node_chain) {
        m_chain = std::make_unique<Chain>(m_ctx.chainman, m_ctx.block_templates,
                                          m_ctx.validation_signals, m_opts.chain);
        m_chain->Prefill(std::chrono::duration_cast<std::chrono::seconds>(m_opts.start));
        m_clock.AdvanceTo(m_opts.start);
    }

    m_tracked.reserve(m_opts.num_tracked);
    for (uint32_t id{0}; id < m_opts.num_tracked; ++id) m_tracked.push_back(id);

    m_nodes.reserve(m_opts.num_nodes);
    m_links_by_node.resize(m_opts.num_nodes);

    for (uint32_t id{0}; id < m_opts.num_nodes; ++id) {
        const bool listening{id < m_opts.num_listening};
        NodeOptions node_opts;
        node_opts.id = id;
        node_opts.self = m_universe.At(id);
        node_opts.listening = listening;
        node_opts.blocks_only = m_opts.blocks_only;
        node_opts.max_automatic_connections = m_opts.max_automatic_connections;
        node_opts.own_chain = m_opts.per_node_chain;
        if (node_opts.own_chain) {
            node_opts.datadir = m_opts.datadir / fs::u8path("node" + util::ToString(id));
        }
        m_nodes.push_back(MakeNode(m_ctx, node_opts));
        if (listening) m_listeners.emplace(m_universe.At(id), id);

        // Stagger the first tick of each kind across its interval. Without
        // this every node acts on the same instants forever, which turns a
        // Poisson send schedule into a synchronised one and makes every node
        // race for the same addresses.
        const auto stagger{[&](SimTime interval) {
            return interval.count() > 0 ? SimTime{static_cast<int64_t>(id) % interval.count()} : SimTime::zero();
        }};
        ArmServiceTick(id, m_clock.Now() + stagger(m_opts.service_interval) + m_opts.service_interval);
        ArmOpenConnTick(id, m_clock.Now() + stagger(m_opts.open_conn_interval) + m_opts.open_conn_interval);
    }

    // One recorder per node, on that node's own signals, so a block's arrival
    // is timed where it actually happened rather than inferred by polling.
    if (m_opts.per_node_chain && m_opts.record_block_arrivals) {
        m_tip_recorders.reserve(m_opts.num_nodes);
        for (uint32_t id{0}; id < m_opts.num_nodes; ++id) {
            m_tip_recorders.push_back(std::make_unique<TipRecorder>(
                id, [this](uint32_t node, const CBlockIndex& tip) {
                    m_block_arrivals.push_back(
                        {m_clock.Now(), node, tip.nHeight, tip.GetBlockHash()});
                }));
            At(id).own_signals->RegisterValidationInterface(m_tip_recorders.back().get());
        }
    }

    // Node 0 is the miner. Its chain is where blocks are built; everyone else
    // has to be told, which is the whole point of the exercise.
    if (m_opts.per_node_chain) {
        m_miner_templates = std::make_unique<node::BlockTemplateManager>(
            m_ctx.mempool, *At(0).chainman, *Assert(m_ctx.kernel_notifications), node::BlockCreateOptions{});
        m_chain = std::make_unique<Chain>(*At(0).chainman, m_miner_templates.get(),
                                          At(0).own_signals.get(), m_opts.chain);
        // Handed to every other node directly rather than relayed, so the
        // population starts synced and what follows measures one block's
        // travel instead of a thousand nodes doing initial block download.
        m_chain->Prefill(std::chrono::duration_cast<std::chrono::seconds>(m_opts.start),
                         [this](const std::shared_ptr<const CBlock>& block) {
                             for (uint32_t id{1}; id < m_opts.num_nodes; ++id) {
                                 Assert(At(id).chainman->ProcessNewBlock(
                                     block, /*force_processing=*/true, /*min_pow_checked=*/true,
                                     /*new_block=*/nullptr));
                             }
                         });
        m_clock.AdvanceTo(m_opts.start);
        // The prefill was handed round rather than relayed, so its arrivals say
        // nothing about propagation. Drop them and start the record at the
        // first block that actually had to travel.
        m_block_arrivals.clear();
    }

    Bootstrap();

    // A baseline reading before anything has connected, so a plot of coverage
    // starts where it should. Then the repeating schedule.
    if (!m_tracked.empty() && m_opts.addr_sample_interval.count() > 0) {
        SampleAddrCoverage();
        ArmAddrSample(m_clock.Now() + m_opts.addr_sample_interval);
    }

    if (m_opts.mine) {
        ArmMineTick(m_clock.Now() + std::chrono::duration_cast<SimTime>(m_chain->NextInterval()));
    }
}

void Network::Bootstrap()
{
    if (m_opts.bootstrap_addrs == 0) return;

    // Tracked listeners are skipped: withholding them is what makes relay the
    // only way their addresses can spread.
    const uint32_t first{m_opts.num_tracked};
    const uint32_t count{m_opts.num_listening - first};
    if (count == 0) return;

    constexpr auto SERVICES{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    const auto now{Now<NodeSeconds>()};

    for (uint32_t id{0}; id < m_opts.num_nodes; ++id) {
        std::vector<CAddress> seeds;
        seeds.reserve(m_opts.bootstrap_addrs);
        for (uint32_t k{0}; k < m_opts.bootstrap_addrs; ++k) {
            const auto pick{first + static_cast<uint32_t>(m_rng.randrange(count))};
            if (pick == id) continue;
            // Backdate like ConvertSeeds does, so these do not all look
            // freshly announced and the selection is not dominated by
            // identical timestamps.
            CAddress addr{m_universe.At(pick), SERVICES};
            addr.nTime = now - std::chrono::seconds{m_rng.randrange(7 * 24 * 60 * 60)};
            seeds.push_back(addr);
        }
        // The node's own address as the source, so that different nodes bucket
        // the same seed differently, as they would learning from different
        // places.
        if (!seeds.empty()) At(id).addrman->Add(seeds, CNetAddr{m_universe.At(id)});
    }
}

Network::~Network()
{
    // Before the nodes, whose signals the recorders are subscribed to.
    for (size_t id{0}; id < m_tip_recorders.size(); ++id) {
        At(static_cast<uint32_t>(id)).own_signals->UnregisterValidationInterface(m_tip_recorders[id].get());
    }
}

SimNode& Network::At(uint32_t id)
{
    Assert(id < m_nodes.size());
    return *m_nodes[id];
}

const SimNode& Network::At(uint32_t id) const
{
    Assert(id < m_nodes.size());
    return *m_nodes[id];
}

std::optional<uint32_t> Network::ListenerAt(const CService& addr) const
{
    const auto it{m_listeners.find(addr)};
    if (it == m_listeners.end()) return std::nullopt;
    return it->second;
}

uint64_t Network::OpenedOfType(ConnectionType type) const
{
    const auto it{m_opened_by_type.find(type)};
    return it == m_opened_by_type.end() ? 0 : it->second;
}

bool Network::Connect(uint32_t from, uint32_t to, ConnectionType conn_type)
{
    if (from == to) return false;
    if (to >= m_nodes.size() || from >= m_nodes.size()) return false;

    SimNode& dialer{At(from)};
    SimNode& acceptor{At(to)};
    if (!acceptor.listening) return false;

    // Core refuses a second connection to an address it is already connected
    // to, so ask it rather than tracking that separately.
    if (dialer.connman->AlreadyConnectedToAddressPublic(acceptor.self)) return false;

    const auto capacity{static_cast<size_t>(acceptor.connman->GetMaxInboundConnections())};
    if (acceptor.connman->GetNodeCount(ConnectionDirection::In) >= capacity) {
        // What CreateNodeFromAcceptedSocket does when the inbound slots are
        // full: try to evict an existing peer, and drop the new connection only
        // if every candidate was protected. The eviction logic is Core's own,
        // so netgroup, ping, and recency protections all apply.
        if (!acceptor.connman->AttemptToEvictConnectionPublic()) {
            ++m_inbound_refusals;
            return false;
        }
        // Eviction only flags the loser. The slot frees up when the disconnect
        // pass actually deletes it.
        ReapNode(to);
        if (acceptor.connman->GetNodeCount(ConnectionDirection::In) >= capacity) {
            ++m_inbound_refusals;
            return false;
        }
        ++m_evictions;
    }

    const NodeId out_id{m_next_node_id++};
    const NodeId in_id{m_next_node_id++};
    const ConnPair pair{ConnectPair(dialer, acceptor, conn_type, out_id, in_id)};
    ++m_opened_by_type[conn_type];

    // Recycle a closed link's slot where one is free, so the vector is bounded
    // by the peak number of concurrent connections rather than by every
    // connection the run ever opened. Feelers alone would otherwise make that
    // unbounded over a long run.
    size_t index;
    uint32_t gen{0};
    if (!m_free_links.empty()) {
        index = m_free_links.back();
        m_free_links.pop_back();
        gen = m_links[index].gen + 1;
    } else {
        index = m_links.size();
        m_links.emplace_back();
    }

    Link& link{m_links[index]};
    link = Link{};
    link.gen = gen;
    link.initiator = from;
    link.acceptor = to;
    link.out_side = pair.out_side;
    link.in_side = pair.in_side;
    link.conn_type = conn_type;
    link.opened_at = m_clock.Now();
    link.next_free_to_acceptor = m_clock.Now();
    link.next_free_to_initiator = m_clock.Now();

    m_links_by_node[from].push_back(index);
    m_links_by_node[to].push_back(index);
    ++m_total_opened;
    ++m_live_links;

    // The dialer has to speak first: PeerManager pushes VERSION lazily from
    // SendMessages, and the acceptor will ignore the link until it arrives.
    ServiceEndpoint(index, Direction::ToAcceptor);
    return true;
}

void Network::ServiceEndpoint(size_t link_index, Direction outgoing)
{
    AssertLockHeld(NetEventsInterface::g_msgproc_mutex);
    Link& link{m_links[link_index]};
    if (link.closed) return;

    const bool from_initiator{outgoing == Direction::ToAcceptor};
    CNode* source{from_initiator ? link.out_side : link.in_side};
    if (source == nullptr) return; // this end has already been reaped
    SimNode& source_node{At(from_initiator ? link.initiator : link.acceptor)};

    Process(source_node, *source);
    auto wire{Drain(*source)};
    if (wire.empty()) return;
    ScheduleDelivery(link_index, outgoing, std::move(wire));
}

void Network::ScheduleDelivery(size_t link_index, Direction outgoing, std::vector<uint8_t>&& wire)
{
    Link& link{m_links[link_index]};
    const bool to_acceptor{outgoing == Direction::ToAcceptor};
    const uint32_t src{to_acceptor ? link.initiator : link.acceptor};
    const uint32_t dst{to_acceptor ? link.acceptor : link.initiator};
    SimTime& watermark{to_acceptor ? link.next_free_to_acceptor : link.next_free_to_initiator};

    const SimTime delay{m_latency.Delay(src, dst, wire.size(), m_rng)};
    const SimTime arrival{std::max(m_clock.Now() + delay, watermark + SimTime{1})};
    watermark = arrival;
    m_bytes_transferred += wire.size();
    if (to_acceptor) {
        link.bytes_to_acceptor += wire.size();
    } else {
        link.bytes_to_initiator += wire.size();
    }

    const uint32_t gen{link.gen};
    m_queue.Post(arrival, [this, link_index, gen, outgoing, bytes = std::move(wire)] {
        DeliverNow(link_index, gen, outgoing, bytes);
    });
}

void Network::DeliverNow(size_t link_index, uint32_t gen, Direction outgoing, const std::vector<uint8_t>& wire)
{
    AssertLockHeld(NetEventsInterface::g_msgproc_mutex);
    Link& link{m_links[link_index]};

    // The slot was recycled while these bytes were in flight, so they belong to
    // a connection that no longer exists.
    if (link.gen != gen) return;

    const bool to_acceptor{outgoing == Direction::ToAcceptor};
    CNode* destination{to_acceptor ? link.in_side : link.out_side};
    // Bytes still in flight when the far end hung up are simply lost, which is
    // what happens to a real socket that closes under them.
    if (link.closed || destination == nullptr) return;
    SimNode& destination_node{At(to_acceptor ? link.acceptor : link.initiator)};

    Deliver(*destination_node.connman, *destination, wire);

    // Let the receiver react immediately, on *every* connection it holds and
    // not only the one the bytes arrived on. This matters more than it looks:
    // ThreadMessageHandler calls SendMessages for every peer on each pass, so a
    // node that learns something from one peer forwards it to the others in the
    // same pass. Servicing only the arriving link would leave the forward
    // waiting for the next periodic tick, which quantised block propagation to
    // one service interval per hop -- a measurement of the tick rather than of
    // the network.
    const uint32_t receiver{to_acceptor ? link.acceptor : link.initiator};
    for (const size_t index : m_links_by_node[receiver]) {
        const Link& other{m_links[index]};
        if (other.closed) continue;
        ServiceEndpoint(index, other.initiator == receiver ? Direction::ToAcceptor : Direction::ToInitiator);
    }
}

void Network::ServiceNode(uint32_t id)
{
    AssertLockHeld(NetEventsInterface::g_msgproc_mutex);
    // A node can queue a send on a connection that received nothing, for
    // instance when RelayAddress picks it as a destination, so every
    // connection needs a periodic chance to flush.
    for (const size_t index : m_links_by_node[id]) {
        const Link& link{m_links[index]};
        if (link.closed) continue;
        ServiceEndpoint(index, link.initiator == id ? Direction::ToAcceptor : Direction::ToInitiator);
    }
    ReapNode(id);
}

void Network::ReapNode(uint32_t id)
{
    AssertLockHeld(NetEventsInterface::g_msgproc_mutex);

    // A connection goes down at both ends, so propagate the flag before
    // anything is deleted. Feelers reach here routinely: they set fDisconnect
    // from the VERSION handler, before verack.
    bool any{false};
    for (const size_t index : m_links_by_node[id]) {
        Link& link{m_links[index]};
        if (link.closed) continue;
        const bool is_initiator{link.initiator == id};
        CNode* mine{is_initiator ? link.out_side : link.in_side};
        CNode* theirs{is_initiator ? link.in_side : link.out_side};
        if (mine == nullptr) continue;
        if (!mine->fDisconnect && (theirs == nullptr || !theirs->fDisconnect)) continue;
        mine->fDisconnect = true;
        if (theirs != nullptr) theirs->fDisconnect = true;
        any = true;
    }
    if (!any) return;

    // Forget our pointers before the disconnect pass deletes the objects. Only
    // this node's own ends are at risk: the far ends belong to another CConnman
    // and are reaped when that node's own tick runs.
    for (const size_t index : m_links_by_node[id]) {
        Link& link{m_links[index]};
        if (link.closed) continue;
        CNode*& mine{link.initiator == id ? link.out_side : link.in_side};
        if (mine != nullptr && mine->fDisconnect) mine = nullptr;
    }

    At(id).connman->DisconnectNodesPublic();

    // Drop the links this node is finished with, and release the slot of any
    // whose far end has gone too. Compacting here is what keeps the per-node
    // list bounded by live degree instead of by history.
    auto& mine{m_links_by_node[id]};
    std::vector<size_t> finished;
    size_t keep{0};
    for (size_t i = 0; i < mine.size(); ++i) {
        const size_t index{mine[i]};
        Link& link{m_links[index]};
        CNode* ours{link.initiator == id ? link.out_side : link.in_side};
        if (ours != nullptr) {
            mine[keep++] = index; // still ours
            continue;
        }
        if (!link.closed && link.out_side == nullptr && link.in_side == nullptr) {
            link.closed = true;
            ++m_closed_links;
            --m_live_links;
            finished.push_back(index);
        }
    }
    mine.resize(keep);

    for (const size_t index : finished) {
        const Link& link{m_links[index]};
        const uint32_t other{link.initiator == id ? link.acceptor : link.initiator};
        auto& theirs{m_links_by_node[other]};
        for (size_t i = 0; i < theirs.size(); ++i) {
            if (theirs[i] == index) {
                theirs[i] = theirs.back();
                theirs.pop_back();
                break;
            }
        }
        m_free_links.push_back(index);
    }
}

void Network::TryOpenOutbound(uint32_t id)
{
    AssertLockHeld(NetEventsInterface::g_msgproc_mutex);
    SimNode& node{At(id)};

    // Ask Core what to open next rather than deciding here. This is the real
    // priority ladder: anchors, then full-relay to capacity, then
    // block-relay-only to capacity, then the stale-tip extra peer, the
    // periodic extra block-relay peer, a feeler, and an extra peer on an
    // unrepresented network. Reimplementing it alongside would mean measuring
    // the reimplementation.
    const CConnman::OutboundSlots slots{node.connman->CountOutboundSlots()};
    const auto now{GetTime<std::chrono::microseconds>()};
    const std::optional<CConnman::NextOutbound> next{
        node.connman->DecideNextOutbound(slots, node.timers, now, *node.rng)};
    if (!next) return;

    node.addrman->ResolveCollisions();

    const std::optional<CAddress> picked{node.connman->TryPickOutboundAddress(
        next->anchor, next->conn_type, next->feeler, slots.netgroups, next->preferred_net)};
    if (!picked) return;

    // Core discards its own address inside the selection loop, via its
    // LocalAddresses table, which MakeNode fills for a listening node. A
    // non-listening node has no address of its own to record, so it can still
    // pick itself and the simulator catches that here. Not counted as a
    // failure: nothing was attempted.
    if (static_cast<const CService&>(*picked) == node.self) {
        ++m_self_picks;
        return;
    }

    // OpenNetworkConnection refuses an address we are already connected to
    // before attempting anything, so AddrMan records no attempt. This happens
    // routinely: an inbound peer does not reserve its netgroup, so the
    // selection loop will happily offer a peer we already have inbound.
    if (node.connman->AlreadyConnectedToAddressPublic(*picked)) {
        ++m_rejected_attempts;
        return;
    }

    // From here a connect is genuinely attempted, and AddrMan records that
    // whether or not it succeeds. The count_failures rule is
    // ThreadOpenConnections': only start counting failures once the node has a
    // couple of distinct-netgroup outbound peers to lose.
    const bool count_failures{static_cast<int>(slots.netgroups.size()) + slots.privacy_network_peers >=
                              std::min<int>(DEFAULT_MAX_PEER_CONNECTIONS - 1, 2)};
    node.addrman->Attempt(*picked, count_failures);

    const std::optional<uint32_t> target{ListenerAt(*picked)};
    if (!target || !Connect(id, *target, next->conn_type)) {
        // Nothing listening there, or the acceptor had no room. A real node
        // learns this from a refused or timed-out connect.
        ++m_failed_attempts;
        return;
    }
    // Good() is deliberately not called here. The VERSION handler in
    // net_processing already does it for every non-inbound peer, and our nodes
    // run the real handler.
}

void Network::ArmServiceTick(uint32_t id, SimTime at)
{
    if (m_opts.service_interval <= SimTime::zero()) return;
    m_queue.Post(at, [this, id, at] {
        ServiceNode(id);
        ArmServiceTick(id, at + m_opts.service_interval);
    });
}

void Network::ArmOpenConnTick(uint32_t id, SimTime at)
{
    if (m_opts.open_conn_interval <= SimTime::zero()) return;
    m_queue.Post(at, [this, id, at] {
        TryOpenOutbound(id);
        ArmOpenConnTick(id, at + m_opts.open_conn_interval);
    });
}

uint32_t Network::NumNetgroups() const
{
    std::set<std::vector<unsigned char>> groups;
    for (uint32_t id{0}; id < m_opts.num_nodes; ++id) {
        groups.insert(m_ctx.netgroupman.GetGroup(m_universe.At(id)));
    }
    return static_cast<uint32_t>(groups.size());
}

void Network::ArmAddrSample(SimTime at)
{
    if (m_opts.addr_sample_interval <= SimTime::zero()) return;
    m_queue.Post(at, [this, at] {
        SampleAddrCoverage();
        ArmAddrSample(at + m_opts.addr_sample_interval);
    });
}

void Network::ArmMineTick(SimTime at)
{
    if (m_opts.chain.spacing <= std::chrono::seconds::zero()) return;
    m_queue.Post(at, [this, at] {
        // One block, from nobody in particular. Which node mined it is not
        // expressible while the chainstate is shared: see chain.h. What
        // matters for the peers is that the tip moved, and that every node's
        // PeerManager heard about it.
        Assert(m_chain->MineOne());
        // The next gap is drawn fresh, so block arrivals are the Poisson
        // process they are on the real network rather than a metronome.
        ArmMineTick(at + std::chrono::duration_cast<SimTime>(m_chain->NextInterval()));
    });
}

void Network::SampleAddrCoverage()
{
    constexpr auto SERVICES{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    const SimTime now{m_clock.Now()};

    for (const uint32_t tracked : m_tracked) {
        const CAddress addr{m_universe.At(tracked), SERVICES};
        AddrSample sample;
        sample.at = now;
        sample.node = tracked;

        for (uint32_t id{0}; id < m_opts.num_nodes; ++id) {
            if (id == tracked) continue; // its own address is not news
            // One hash lookup rather than a table walk, which is what keeps a
            // whole-population sample affordable at 100,000 nodes.
            const auto found{At(id).addrman->FindAddressEntry(addr)};
            if (!found) continue;
            ++sample.holders;
            if (found->tried) {
                ++sample.in_tried;
                ++sample.multiplicity;
            } else {
                sample.multiplicity += static_cast<uint32_t>(found->multiplicity);
            }
        }
        m_addr_samples.push_back(sample);
    }
}

void Network::RunFor(SimTime duration)
{
    AssertLockHeld(NetEventsInterface::g_msgproc_mutex);
    m_queue.RunUntil(m_clock, m_clock.Now() + duration);
}

} // namespace netsim
