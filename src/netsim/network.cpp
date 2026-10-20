// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netsim/network.h>

#include <net.h>
#include <netsim/pump.h>
#include <sync.h>
#include <threadsafety.h>
#include <util/check.h>

#include <algorithm>
#include <utility>

namespace netsim {

namespace {
/** Inbound slots a default-configured node has.
 *
 * Mirrors CConnman::Init(): m_max_inbound is m_max_automatic_connections minus
 * the automatic outbound reservation of 8 full-relay, 2 block-relay and 1
 * feeler. Recomputed here because the member is private.
 */
constexpr int InboundCapacity()
{
    const int automatic_outbound{MAX_OUTBOUND_FULL_RELAY_CONNECTIONS + MAX_BLOCK_RELAY_ONLY_CONNECTIONS +
                                 MAX_FEELER_CONNECTIONS};
    return std::max(0, static_cast<int>(DEFAULT_MAX_PEER_CONNECTIONS) - automatic_outbound);
}

Direction Opposite(Direction d)
{
    return d == Direction::ToAcceptor ? Direction::ToInitiator : Direction::ToAcceptor;
}
} // namespace

Network::Network(Options opts, const SharedContext& ctx)
    : m_opts{opts},
      m_ctx{ctx},
      m_universe{opts.num_nodes, opts.port},
      m_clock{opts.start},
      m_latency{opts.latency},
      m_rng{opts.rng_seed}
{
    Assert(m_opts.num_listening <= m_opts.num_nodes);

    m_nodes.reserve(m_opts.num_nodes);
    m_links_by_node.resize(m_opts.num_nodes);

    for (uint32_t id{0}; id < m_opts.num_nodes; ++id) {
        const bool listening{id < m_opts.num_listening};
        m_nodes.push_back(MakeNode(m_ctx, id, m_universe.At(id), listening));
        if (listening) m_listeners.emplace(m_universe.At(id), id);

        // Stagger the first service tick across the interval. Without this
        // every node flushes on the same instant forever, which turns a
        // Poisson send schedule into a synchronised one.
        const auto offset{SimTime{m_opts.service_interval.count() > 0
                                      ? static_cast<int64_t>(id) % m_opts.service_interval.count()
                                      : 0}};
        ArmServiceTick(id, m_clock.Now() + offset + m_opts.service_interval);
    }
}

Network::~Network() = default;

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

bool Network::Connect(uint32_t from, uint32_t to)
{
    if (from == to) return false;
    if (to >= m_nodes.size() || from >= m_nodes.size()) return false;

    SimNode& dialer{At(from)};
    SimNode& acceptor{At(to)};
    if (!acceptor.listening) return false;

    // Core refuses a second connection to an address it is already connected
    // to, so ask it rather than tracking that separately.
    if (dialer.connman->AlreadyConnectedToAddressPublic(acceptor.self)) return false;

    if (acceptor.connman->GetNodeCount(ConnectionDirection::In) >= static_cast<size_t>(InboundCapacity())) {
        // Production would try AttemptToEvictConnection here. That is private
        // and not exposed by ConnmanTestMsg, so for now the connection is
        // refused and counted; at the populations this is used for, the cap is
        // never reached.
        ++m_inbound_refusals;
        return false;
    }

    const NodeId out_id{m_next_node_id++};
    const NodeId in_id{m_next_node_id++};
    const ConnPair pair{ConnectPair(m_ctx, dialer, acceptor, out_id, in_id)};

    const size_t index{m_links.size()};
    m_links.push_back(Link{from, to, pair.out_side, pair.in_side, m_clock.Now(), m_clock.Now()});
    m_links_by_node[from].push_back(index);
    m_links_by_node[to].push_back(index);

    // The dialer has to speak first: PeerManager pushes VERSION lazily from
    // SendMessages, and the acceptor will ignore the link until it arrives.
    ServiceEndpoint(index, Direction::ToAcceptor);
    return true;
}

void Network::ServiceEndpoint(size_t link_index, Direction outgoing)
{
    AssertLockHeld(NetEventsInterface::g_msgproc_mutex);
    Link& link{m_links[link_index]};

    const bool from_initiator{outgoing == Direction::ToAcceptor};
    CNode* source{from_initiator ? link.out_side : link.in_side};
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

    m_queue.Post(arrival, [this, link_index, outgoing, bytes = std::move(wire)] {
        DeliverNow(link_index, outgoing, bytes);
    });
}

void Network::DeliverNow(size_t link_index, Direction outgoing, const std::vector<uint8_t>& wire)
{
    AssertLockHeld(NetEventsInterface::g_msgproc_mutex);
    Link& link{m_links[link_index]};

    const bool to_acceptor{outgoing == Direction::ToAcceptor};
    CNode* destination{to_acceptor ? link.in_side : link.out_side};
    SimNode& destination_node{At(to_acceptor ? link.acceptor : link.initiator)};

    Deliver(*destination_node.connman, *destination, wire);
    // Let the receiver react immediately, and ship whatever it answers with.
    ServiceEndpoint(link_index, Opposite(outgoing));
}

void Network::ServiceNode(uint32_t id)
{
    AssertLockHeld(NetEventsInterface::g_msgproc_mutex);
    // A node can queue a send on a connection that received nothing, for
    // instance when RelayAddress picks it as a destination, so every
    // connection needs a periodic chance to flush.
    for (const size_t index : m_links_by_node[id]) {
        const Link& link{m_links[index]};
        ServiceEndpoint(index, link.initiator == id ? Direction::ToAcceptor : Direction::ToInitiator);
    }
}

void Network::ArmServiceTick(uint32_t id, SimTime at)
{
    if (m_opts.service_interval <= SimTime::zero()) return;
    m_queue.Post(at, [this, id, at] {
        ServiceNode(id);
        ArmServiceTick(id, at + m_opts.service_interval);
    });
}

void Network::RunFor(SimTime duration)
{
    AssertLockHeld(NetEventsInterface::g_msgproc_mutex);
    m_queue.RunUntil(m_clock, m_clock.Now() + duration);
}

} // namespace netsim
