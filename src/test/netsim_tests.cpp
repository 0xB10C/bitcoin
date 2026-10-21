// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net.h>
#include <net_processing.h>
#include <netaddress.h>
#include <netgroup.h>
// addrman.h first: addrman_impl.h uses AddressPosition without declaring it.
#include <addrman.h>
#include <addrman_impl.h>
#include <chain.h>
#include <common/bloom.h>
#include <netsim/addresses.h>
#include <netsim/chain.h>
#include <netsim/clock.h>
#include <netsim/eventqueue.h>
#include <netsim/export.h>
#include <netsim/latency.h>
#include <netsim/metrics.h>
#include <netsim/network.h>
#include <netsim/node.h>
#include <netsim/pump.h>
#include <netsim/setup.h>
#include <node/protocol_version.h>
#include <protocol.h>
#include <random.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/string.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <map>
#include <sstream>
#include <memory>
#include <set>
#include <utility>
#include <string>
#include <vector>

using namespace std::chrono_literals;
using netsim::AddressUniverse;
using netsim::EventQueue;
using netsim::RegionLatency;
using netsim::SimClock;
using netsim::SimTime;

namespace {
//! An arbitrary but positive starting instant. Mock time reads zero as "not mocked".
const SimTime SIM_START{std::chrono::duration_cast<SimTime>(1'700'000'000s)};

/** TestingSetup plus the shared context a simulated node needs.
 *
 * The ChainstateManager and CTxMemPool here are shared by every node in the
 * simulation. That is not only a memory decision: the address-relay path does
 * touch the chainstate, through IsInitialBlockDownload() gating
 * self-announcement and ActiveChain().Tip() in SendMessages, so the nodes need
 * a real one even though no block is ever relayed.
 */
struct SimTestingSetup : public TestingSetup {
    NetGroupManager netgroupman{NetGroupManager::NoAsmap()};
    netsim::SharedContext ctx;

    /** `with_chain` hands over the validation signals and the block template
     *  manager, which is what a run with a real chain needs: publishing tip
     *  notifications is what makes a new block reach every node's announcement
     *  path, and it is also what tells MakeNode not to gate off the chain-sync
     *  timeout. See SimChainTestingSetup. */
    explicit SimTestingSetup(bool with_chain = false)
        : TestingSetup{ChainType::REGTEST, netsim::SimTestOpts()},
          ctx{*m_node.chainman, *m_node.mempool, *m_node.warnings, netgroupman,
              with_chain ? m_node.validation_signals.get() : nullptr,
              with_chain ? m_node.block_template_manager.get() : nullptr,
              m_node.notifications.get(), m_node.shutdown_signal}
    {
        // MaybeSendAddr() refuses to advertise a node's own address while the
        // chainstate reports initial block download, and self-announcement is
        // the only thing that propagates addresses more than one hop. A run
        // with a chain leaves IBD on its own, because its tip lands on the
        // instant the run starts, and that is itself under test.
        if (!with_chain) static_cast<TestChainstateManager&>(*m_node.chainman).JumpOutOfIbd();
    }
};

/** A simulation that mines on a real chain. See SimTestingSetup. */
struct SimChainTestingSetup : public SimTestingSetup {
    SimChainTestingSetup() : SimTestingSetup{/*with_chain=*/true} {}
};

/** How many nodes filled their full-relay slots, and how many filled none.
 *
 * The pair almost every topology assertion is made against: `isolated == 0`
 * says the population is connected, and a high `saturated` says Core's
 * selection found enough distinct candidates to work with.
 */
struct Saturation {
    size_t saturated{0};
    size_t isolated{0};
};

Saturation CountSaturation(const netsim::Network& net)
{
    Saturation out;
    for (uint32_t id{0}; id < net.NumNodes(); ++id) {
        const int outbound{net.At(id).connman->GetFullOutboundConnCount()};
        if (outbound >= MAX_OUTBOUND_FULL_RELAY_CONNECTIONS) ++out.saturated;
        if (outbound == 0) ++out.isolated;
    }
    return out;
}

/** Shuttle bytes between the two ends of one connection until both go quiet.
 *
 * Returns the number of rounds used. A round is one pass of "let both sides
 * think, then move whatever they produced".
 */
int PumpUntilQuiet(netsim::SimNode& a, CNode& a_side, netsim::SimNode& b, CNode& b_side, int max_rounds = 32)
    EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
{
    for (int round{1}; round <= max_rounds; ++round) {
        netsim::Process(a, a_side);
        netsim::Process(b, b_side);

        // Drain both before delivering either, so one side cannot run ahead
        // inside a single round.
        const auto from_a{netsim::Drain(a_side)};
        const auto from_b{netsim::Drain(b_side)};
        if (from_a.empty() && from_b.empty()) return round;
        if (!from_a.empty()) netsim::Deliver(*b.connman, b_side, from_a);
        if (!from_b.empty()) netsim::Deliver(*a.connman, a_side, from_b);
    }
    return max_rounds;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(netsim_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(netsim_clock_two_resolutions)
{
    SimClock clock{SIM_START};

    // What the simulated nodes believe, at construction.
    BOOST_CHECK(GetTime<std::chrono::seconds>() == 1'700'000'000s);

    // A sub-second step moves simulated time but not the nodes' belief. This is
    // the whole reason the clock carries two resolutions: link latency is far
    // below the resolution of SetMockTime().
    clock.AdvanceTo(SIM_START + 500ms);
    BOOST_CHECK(clock.Now() == SIM_START + 500ms);
    BOOST_CHECK(GetTime<std::chrono::seconds>() == 1'700'000'000s);

    // Crossing a second boundary does move it, and truncates rather than rounds.
    clock.AdvanceTo(SIM_START + 1500ms);
    BOOST_CHECK(clock.Now() == SIM_START + 1500ms);
    BOOST_CHECK(GetTime<std::chrono::seconds>() == 1'700'000'001s);

    clock.AdvanceTo(SIM_START + 90s);
    BOOST_CHECK(GetTime<std::chrono::seconds>() == 1'700'000'090s);
}

BOOST_AUTO_TEST_CASE(netsim_clock_restores_real_time)
{
    {
        SimClock clock{SIM_START};
        BOOST_CHECK(GetMockTime() != 0s);
    }
    // Leaving the simulation must not leave mock time behind for whatever runs next.
    BOOST_CHECK(GetMockTime() == 0s);
}

BOOST_AUTO_TEST_CASE(netsim_eventqueue_ordering)
{
    SimClock clock{SIM_START};
    EventQueue queue;
    std::vector<int> ran;

    // Posted out of order on purpose.
    queue.Post(SIM_START + 30s, [&] { ran.push_back(3); });
    queue.Post(SIM_START + 10s, [&] { ran.push_back(1); });
    queue.Post(SIM_START + 20s, [&] { ran.push_back(2); });

    BOOST_CHECK_EQUAL(queue.Size(), 3U);
    BOOST_CHECK(queue.NextTime() == SIM_START + 10s);

    while (!queue.Empty()) queue.RunOne(clock);

    const std::vector<int> expected{1, 2, 3};
    BOOST_CHECK(ran == expected);
    BOOST_CHECK(clock.Now() == SIM_START + 30s);
}

BOOST_AUTO_TEST_CASE(netsim_eventqueue_ties_keep_post_order)
{
    SimClock clock{SIM_START};
    EventQueue queue;
    std::vector<int> ran;

    // Everything at the same instant. A reproducible run needs these to come
    // back in the order they were posted, not in whatever order the heap likes.
    for (int i{0}; i < 32; ++i) {
        queue.Post(SIM_START + 5s, [&ran, i] { ran.push_back(i); });
    }
    while (!queue.Empty()) queue.RunOne(clock);

    BOOST_REQUIRE_EQUAL(ran.size(), 32U);
    for (int i{0}; i < 32; ++i) BOOST_CHECK_EQUAL(ran[i], i);
}

BOOST_AUTO_TEST_CASE(netsim_eventqueue_reentrant_post)
{
    SimClock clock{SIM_START};
    EventQueue queue;
    int count{0};

    // An event that posts more work is the normal case, not an edge case: a
    // delivered message schedules processing, which schedules the next send.
    std::function<void()> tick = [&] {
        if (++count < 5) queue.Post(clock.Now() + 1s, tick);
    };
    queue.Post(SIM_START + 1s, tick);

    while (!queue.Empty()) queue.RunOne(clock);

    BOOST_CHECK_EQUAL(count, 5);
    BOOST_CHECK(clock.Now() == SIM_START + 5s);
}

BOOST_AUTO_TEST_CASE(netsim_eventqueue_run_until)
{
    SimClock clock{SIM_START};
    EventQueue queue;
    int ran{0};

    for (int i{1}; i <= 10; ++i) queue.Post(SIM_START + std::chrono::seconds{i}, [&] { ++ran; });

    BOOST_CHECK_EQUAL(queue.RunUntil(clock, SIM_START + 4s), 4U);
    BOOST_CHECK_EQUAL(ran, 4);
    BOOST_CHECK_EQUAL(queue.Size(), 6U);
    // The window is consumed even though the last event in it was earlier.
    BOOST_CHECK(clock.Now() == SIM_START + 4s);

    BOOST_CHECK_EQUAL(queue.RunUntil(clock, SIM_START + 100s), 6U);
    BOOST_CHECK(queue.Empty());
    BOOST_CHECK(clock.Now() == SIM_START + 100s);
}

BOOST_AUTO_TEST_CASE(netsim_latency_region_model)
{
    RegionLatency::Options opts;
    opts.num_regions = 6;
    opts.intra_region = 12ms;
    opts.inter_region = 90ms;
    opts.jitter_fraction = 0.25;
    const RegionLatency model{opts};

    // Regions must actually be used, or every delay collapses to one value.
    std::set<unsigned> regions;
    for (uint32_t i{0}; i < 100; ++i) regions.insert(model.Region(i));
    BOOST_CHECK_EQUAL(regions.size(), 6U);

    // Find one same-region and one cross-region pair to compare.
    uint32_t same_a{0}, same_b{0}, diff_b{0};
    for (uint32_t i{1}; i < 100; ++i) {
        if (model.Region(i) == model.Region(same_a) && same_b == 0) same_b = i;
        if (model.Region(i) != model.Region(same_a) && diff_b == 0) diff_b = i;
    }
    BOOST_REQUIRE(same_b != 0);
    BOOST_REQUIRE(diff_b != 0);

    FastRandomContext rng{uint256{7}};
    const auto intra{model.Delay(same_a, same_b, 0, rng)};
    const auto inter{model.Delay(same_a, diff_b, 0, rng)};
    BOOST_CHECK(intra < inter);

    // Jitter stays inside plus or minus a quarter of the base.
    for (int i{0}; i < 200; ++i) {
        const auto d{model.Delay(same_a, same_b, 0, rng)};
        BOOST_CHECK(d >= 9ms);
        BOOST_CHECK(d <= 15ms);
    }

    // Same seed, same sequence of delays. Without this a run cannot be replayed.
    FastRandomContext rng_a{uint256{11}};
    FastRandomContext rng_b{uint256{11}};
    for (int i{0}; i < 50; ++i) {
        BOOST_CHECK(model.Delay(1, 2, 0, rng_a) == model.Delay(1, 2, 0, rng_b));
    }
}

BOOST_AUTO_TEST_CASE(netsim_latency_bandwidth)
{
    RegionLatency::Options opts;
    opts.jitter_fraction = 0.0; // isolate the serialisation term
    opts.intra_region = 10ms;
    opts.inter_region = 10ms;
    opts.bandwidth_bytes_per_second = 1'000'000; // 1 MB/s, so 1 us per byte
    const RegionLatency model{opts};

    FastRandomContext rng{uint256{3}};
    BOOST_CHECK(model.Delay(1, 2, 0, rng) == 10ms);
    BOOST_CHECK(model.Delay(1, 2, 1000, rng) == 11ms);
    BOOST_CHECK(model.Delay(1, 2, 50'000, rng) == 60ms);
}

BOOST_AUTO_TEST_CASE(netsim_address_universe)
{
    constexpr uint32_t NUM{100};
    const AddressUniverse universe{NUM, 8333};
    BOOST_REQUIRE_EQUAL(universe.Size(), NUM);

    const auto netgroupman{NetGroupManager::NoAsmap()};
    std::set<CService> distinct;
    std::set<std::vector<unsigned char>> netgroups;

    for (uint32_t i{0}; i < NUM; ++i) {
        const CService& addr{universe.At(i)};

        // Unroutable addresses are dropped by ProcessAddrs and never stored by
        // AddrMan, so a generator that produces them produces a silent no-op.
        BOOST_CHECK_MESSAGE(addr.IsRoutable(), addr.ToStringAddrPort() + " is not routable");
        BOOST_CHECK(addr.IsIPv4());
        BOOST_CHECK_EQUAL(addr.GetPort(), 8333);

        distinct.insert(addr);
        netgroups.insert(netgroupman.GetGroup(addr));
    }

    BOOST_CHECK_EQUAL(distinct.size(), NUM);
    // One netgroup each. Outbound selection refuses an address sharing a
    // netgroup with an existing outbound peer, so a crowded universe would cap
    // every node's outbound count far below its slot count.
    BOOST_CHECK_EQUAL(netgroups.size(), NUM);
}

/** Addresses on all four networks, in the measured mainnet proportions. */
BOOST_AUTO_TEST_CASE(netsim_address_universe_mainnet_mix)
{
    using Net = AddressUniverse::Net;

    AddressUniverse::Options opts;
    opts.num_nodes = 4000;
    opts.port = 8333;
    opts.UseMainnetMix();
    const AddressUniverse universe{opts};
    BOOST_REQUIRE_EQUAL(universe.Size(), opts.num_nodes);

    // Every network is represented, and in the proportion asked for. The
    // apportionment is deterministic, so this is exact to within one node.
    const uint64_t total{uint64_t{opts.weight_ipv4} + opts.weight_ipv6 + opts.weight_onion + opts.weight_i2p};
    const auto expected{[&](uint32_t weight) {
        return static_cast<uint32_t>(uint64_t{opts.num_nodes} * weight / total);
    }};
    BOOST_CHECK_LE(std::abs(int64_t{universe.CountOn(Net::IPv4)} - expected(opts.weight_ipv4)), 1);
    BOOST_CHECK_LE(std::abs(int64_t{universe.CountOn(Net::IPv6)} - expected(opts.weight_ipv6)), 1);
    BOOST_CHECK_LE(std::abs(int64_t{universe.CountOn(Net::Onion)} - expected(opts.weight_onion)), 1);
    BOOST_CHECK_LE(std::abs(int64_t{universe.CountOn(Net::I2P)} - expected(opts.weight_i2p)), 1);

    // The networks are interleaved rather than laid end to end. That matters
    // because the first node ids are the listeners: a block layout would make
    // every listener IPv4 and the privacy networks unreachable.
    std::set<Net> among_first;
    for (uint32_t id{0}; id < 100; ++id) among_first.insert(universe.NetOf(id));
    BOOST_CHECK_EQUAL(among_first.size(), AddressUniverse::NUM_NETS);

    std::set<CService> distinct;
    for (uint32_t id{0}; id < opts.num_nodes; ++id) {
        const CService& addr{universe.At(id)};
        distinct.insert(addr);
        BOOST_REQUIRE_MESSAGE(addr.IsRoutable(), addr.ToStringAddrPort() + " is not routable");
        BOOST_CHECK_EQUAL(addr.GetPort(), 8333);

        // Each address really is on the network it is filed under. The onion
        // and I2P ones went through CNetAddr::SetSpecial, so Core's own parser
        // accepted them, checksum included.
        switch (universe.NetOf(id)) {
        case Net::IPv4: BOOST_CHECK(addr.IsIPv4()); break;
        case Net::IPv6: BOOST_CHECK(addr.IsIPv6()); break;
        case Net::Onion: BOOST_CHECK(addr.IsTor()); break;
        case Net::I2P: BOOST_CHECK(addr.IsI2P()); break;
        }

        // And it survives a round trip through its text form, which is how it
        // reaches a log or an export.
        CNetAddr reparsed;
        if (addr.IsTor() || addr.IsI2P()) {
            BOOST_REQUIRE(reparsed.SetSpecial(addr.ToStringAddr()));
            BOOST_CHECK(reparsed == static_cast<const CNetAddr&>(addr));
        }
    }
    BOOST_CHECK_EQUAL(distinct.size(), opts.num_nodes);
}

/** Netgroup occupancy drawn from the measured mainnet distribution. */
BOOST_AUTO_TEST_CASE(netsim_address_universe_mainnet_netgroups)
{
    const auto netgroupman{NetGroupManager::NoAsmap()};
    const auto count_groups{[&](const AddressUniverse& universe) {
        std::set<std::vector<unsigned char>> groups;
        for (uint32_t id{0}; id < universe.Size(); ++id) {
            groups.insert(netgroupman.GetGroup(universe.At(id)));
        }
        return groups.size();
    }};

    AddressUniverse::Options opts;
    opts.num_nodes = 4000;
    opts.port = 8333;

    // The historical default: one node per /16, which is the most favourable
    // case Core's outbound diversity rule will ever see.
    BOOST_CHECK_EQUAL(count_groups(AddressUniverse{opts}), opts.num_nodes);

    // With mainnet occupancy the same population crowds into roughly half as
    // many groups. The measured snapshot had 7,514 IPv4 nodes in 4,236 /16s,
    // or 1.77 per group, and sampling that distribution should land near it.
    opts.mainnet_netgroups = true;
    const AddressUniverse crowded{opts};
    const double per_group{double(opts.num_nodes) / double(count_groups(crowded))};
    BOOST_TEST_MESSAGE("nodes per netgroup = " << per_group);
    BOOST_CHECK_GT(per_group, 1.4);
    BOOST_CHECK_LT(per_group, 2.4);
}

/** The load-bearing test: two real nodes complete a real handshake with no sockets. */
BOOST_FIXTURE_TEST_CASE(netsim_two_node_handshake, SimTestingSetup)
{
    SimClock clock{SIM_START};
    const AddressUniverse universe{2, 8333};

    auto dialer{netsim::MakeNode(ctx, {.id = 0, .self = universe.At(0), .listening = false})};
    auto listener{netsim::MakeNode(ctx, {.id = 1, .self = universe.At(1), .listening = true})};

    // One lock for the whole run, as the fuzz driver does. Every
    // ProcessMessages and SendMessages call requires it, and it is a single
    // process-global mutex rather than one per CConnman.
    LOCK(NetEventsInterface::g_msgproc_mutex);

    const auto conn{netsim::ConnectPair(*dialer, *listener, ConnectionType::OUTBOUND_FULL_RELAY, /*out_id=*/0, /*in_id=*/1)};
    BOOST_REQUIRE(conn.out_side != nullptr);
    BOOST_REQUIRE(conn.in_side != nullptr);

    // Nothing has been exchanged yet: InitializeNode does not send VERSION.
    BOOST_CHECK_EQUAL(conn.out_side->nVersion.load(), 0);
    BOOST_CHECK(!conn.out_side->fSuccessfullyConnected);

    const int rounds{PumpUntilQuiet(*dialer, *conn.out_side, *listener, *conn.in_side)};

    // VERSION out, VERSION and VERACK back, VERACK out. Both sides end up
    // fully connected, each having learned the other's protocol version.
    BOOST_CHECK(conn.out_side->fSuccessfullyConnected);
    BOOST_CHECK(conn.in_side->fSuccessfullyConnected);
    BOOST_CHECK_EQUAL(conn.out_side->nVersion.load(), PROTOCOL_VERSION);
    BOOST_CHECK_EQUAL(conn.in_side->nVersion.load(), PROTOCOL_VERSION);
    BOOST_CHECK_EQUAL(conn.out_side->GetCommonVersion(), PROTOCOL_VERSION);
    BOOST_CHECK_EQUAL(conn.in_side->GetCommonVersion(), PROTOCOL_VERSION);

    // Neither side decided to hang up.
    BOOST_CHECK(!conn.out_side->fDisconnect);
    BOOST_CHECK(!conn.in_side->fDisconnect);

    // Both connmans see exactly their one peer.
    BOOST_CHECK_EQUAL(dialer->connman->GetNodeCount(ConnectionDirection::Out), 1U);
    BOOST_CHECK_EQUAL(listener->connman->GetNodeCount(ConnectionDirection::In), 1U);

    // Real bytes moved. A handshake that converged in one round would mean the
    // pump was short-circuiting rather than transporting.
    BOOST_CHECK_GT(rounds, 2);
    CNodeStats stats;
    conn.out_side->CopyStats(stats);
    BOOST_CHECK_GT(stats.nSendBytes, 0U);
    BOOST_CHECK_GT(stats.nRecvBytes, 0U);
}

/** The dialer must learn addresses from its peer's GETADDR response.
 *
 * This is the narrowest end-to-end check of the thing the simulator exists to
 * measure: GETADDR out, ADDR back, ProcessAddrs, AddrMan::Add.
 */
BOOST_FIXTURE_TEST_CASE(netsim_getaddr_populates_addrman, SimTestingSetup)
{
    SimClock clock{SIM_START};
    constexpr uint32_t UNIVERSE{64};
    const AddressUniverse universe{UNIVERSE, 8333};

    auto dialer{netsim::MakeNode(ctx, {.id = 0, .self = universe.At(0), .listening = false})};
    auto listener{netsim::MakeNode(ctx, {.id = 1, .self = universe.At(1), .listening = true})};

    // Give the listener something worth asking for. The source is a third
    // address, so these do not look self-announced.
    const CNetAddr source{universe.At(2)};
    std::vector<CAddress> known;
    for (uint32_t i{3}; i < UNIVERSE; ++i) {
        known.emplace_back(universe.At(i), ServiceFlags(NODE_NETWORK | NODE_WITNESS), Now<NodeSeconds>());
    }
    BOOST_REQUIRE(listener->addrman->Add(known, source));
    // Not every address necessarily lands: entries sharing a new-table slot are
    // only displaced when the occupant is terrible or multiply referenced, so a
    // few of a batch this size are legitimately dropped.
    const size_t listener_known{listener->addrman->Size()};
    BOOST_REQUIRE_GT(listener_known, known.size() / 2);
    BOOST_REQUIRE_EQUAL(dialer->addrman->Size(), 0U);

    LOCK(NetEventsInterface::g_msgproc_mutex);
    const auto conn{netsim::ConnectPair(*dialer, *listener, ConnectionType::OUTBOUND_FULL_RELAY, /*out_id=*/0, /*in_id=*/1)};

    // The ADDR response is queued against the dialer's m_next_addr_send timer,
    // which is Poisson with a 30 s mean, so step the clock forward between
    // rounds instead of expecting it in the handshake burst.
    for (int step{0}; step < 20; ++step) {
        PumpUntilQuiet(*dialer, *conn.out_side, *listener, *conn.in_side);
        if (dialer->addrman->Size() > 0) break;
        clock.AdvanceTo(clock.Now() + std::chrono::duration_cast<SimTime>(30s));
    }

    BOOST_CHECK(conn.out_side->fSuccessfullyConnected);

    // GetAddr returns 23 percent of the table, capped at 1000, so expect a
    // strict subset of what the listener knows rather than all of it.
    BOOST_CHECK_GT(dialer->addrman->Size(), 0U);
    BOOST_CHECK_LT(dialer->addrman->Size(), listener_known);

    // The listener really did spend bytes on an ADDR message. Per-message-type
    // accounting is how a run will report its address-relay traffic, so it is
    // worth checking that the pump keeps it.
    CNodeStats stats;
    conn.in_side->CopyStats(stats);
    const auto& sent{stats.mapSendBytesPerMsgType};
    BOOST_CHECK(sent.count(NetMsgType::ADDRV2) > 0 || sent.count(NetMsgType::ADDR) > 0);
}

/** The same handshake, but driven entirely by the event queue and the clock. */
BOOST_FIXTURE_TEST_CASE(netsim_network_handshake_over_event_queue, SimTestingSetup)
{
    netsim::Network::Options opts;
    opts.num_nodes = 4;
    opts.num_listening = 2;
    // Isolate the one connection under test: no seeds, so no node can dial on
    // its own, and no outbound tick to do it with.
    opts.bootstrap_addrs = 0;
    opts.open_conn_interval = SimTime::zero();
    netsim::Network net{opts, ctx};

    LOCK(NetEventsInterface::g_msgproc_mutex);

    // Node 2 does not listen; node 0 does.
    BOOST_REQUIRE(net.Connect(2, 0));
    BOOST_CHECK_EQUAL(net.TotalOpened(), 1U);

    // Refused: the target does not listen, the target is the dialer, and the
    // pair is already connected.
    BOOST_CHECK(!net.Connect(3, 2));
    BOOST_CHECK(!net.Connect(2, 2));
    BOOST_CHECK(!net.Connect(2, 0));
    BOOST_CHECK_EQUAL(net.TotalOpened(), 1U);

    net.RunFor(std::chrono::duration_cast<SimTime>(5s));

    const netsim::Link& link{net.Links().at(0)};
    BOOST_CHECK(link.out_side->fSuccessfullyConnected);
    BOOST_CHECK(link.in_side->fSuccessfullyConnected);
    BOOST_CHECK_EQUAL(net.At(2).connman->GetNodeCount(ConnectionDirection::Out), 1U);
    BOOST_CHECK_EQUAL(net.At(0).connman->GetNodeCount(ConnectionDirection::In), 1U);
    BOOST_CHECK_GT(net.BytesTransferred(), 0U);
    BOOST_CHECK_EQUAL(net.InboundRefusals(), 0U);
}

/** Latency has to be real, not decorative. */
BOOST_FIXTURE_TEST_CASE(netsim_network_latency_delays_handshake, SimTestingSetup)
{
    netsim::Network::Options opts;
    opts.num_nodes = 2;
    opts.num_listening = 1;
    // One second each way, no jitter, so the handshake cannot possibly finish
    // before three one-way delays have elapsed.
    opts.latency.intra_region = 1s;
    opts.latency.inter_region = 1s;
    opts.latency.jitter_fraction = 0.0;
    opts.bootstrap_addrs = 0;
    opts.open_conn_interval = SimTime::zero();
    netsim::Network net{opts, ctx};

    LOCK(NetEventsInterface::g_msgproc_mutex);
    BOOST_REQUIRE(net.Connect(1, 0));
    const netsim::Link& link{net.Links().at(0)};

    // VERSION is in flight and nothing has arrived yet.
    net.RunFor(std::chrono::duration_cast<SimTime>(500ms));
    BOOST_CHECK_EQUAL(link.in_side->nVersion.load(), 0);
    BOOST_CHECK(!link.out_side->fSuccessfullyConnected);

    // After one hop the acceptor has the VERSION, but the dialer has not yet
    // had the reply, so neither side is finished.
    net.RunFor(std::chrono::duration_cast<SimTime>(1s));
    BOOST_CHECK_EQUAL(link.in_side->nVersion.load(), PROTOCOL_VERSION);
    BOOST_CHECK(!link.out_side->fSuccessfullyConnected);

    // Given enough hops it completes.
    net.RunFor(std::chrono::duration_cast<SimTime>(10s));
    BOOST_CHECK(link.out_side->fSuccessfullyConnected);
    BOOST_CHECK(link.in_side->fSuccessfullyConnected);
}

/** A run must be replayable, or no measurement taken from it means anything. */
BOOST_FIXTURE_TEST_CASE(netsim_network_is_reproducible, SimTestingSetup)
{
    const auto run{[&](uint8_t seed_byte) {
        netsim::Network::Options opts;
        opts.num_nodes = 8;
        opts.num_listening = 4;
        opts.rng_seed = uint256{seed_byte};
        netsim::Network net{opts, ctx};

        LOCK(NetEventsInterface::g_msgproc_mutex);
        for (uint32_t dialer{4}; dialer < 8; ++dialer) {
            BOOST_REQUIRE(net.Connect(dialer, dialer - 4));
        }
        net.RunFor(std::chrono::duration_cast<SimTime>(120s));

        // Arrival watermarks fingerprint the timing of the run, which the byte
        // count alone does not: jitter moves when things arrive without
        // changing how much arrives.
        uint64_t timing{0};
        for (const netsim::Link& link : net.Links()) {
            timing += static_cast<uint64_t>(link.next_free_to_acceptor.count());
            timing += static_cast<uint64_t>(link.next_free_to_initiator.count());
        }
        return std::pair<uint64_t, uint64_t>{net.BytesTransferred(), timing};
    }};

    BOOST_CHECK(run(1) == run(1));
    // The seed has to matter, or the equality above is vacuous. It shifts the
    // jitter draws, so the timing moves even though the same bytes flow.
    BOOST_CHECK(run(1).second != run(2).second);
}

/** The MVP: 100 nodes, 20 of them listening, forming their own topology.
 *
 * Nothing here tells a node who to connect to. Each starts with a handful of
 * seed addresses, learns the rest from its peers' GETADDR responses, and picks
 * destinations with Core's own TryPickOutboundAddress.
 */
BOOST_FIXTURE_TEST_CASE(netsim_hundred_node_topology, SimTestingSetup)
{
    constexpr uint32_t NODES{100};
    constexpr uint32_t LISTENERS{20};

    // Taken before the population exists, so the shared chainstate and the
    // host process are excluded from the figure below.
    const auto rss_before{netsim::ResidentSetBytes()};

    netsim::Network::Options opts;
    opts.num_nodes = NODES;
    opts.num_listening = LISTENERS;
    opts.bootstrap_addrs = 4;
    netsim::Network net{opts, ctx};

    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        net.RunFor(std::chrono::duration_cast<SimTime>(30min));
    }

    if (rss_before) {
        const auto rss_after{netsim::ResidentSetBytes().value_or(*rss_before)};
        const int64_t delta{static_cast<int64_t>(rss_after) - static_cast<int64_t>(*rss_before)};
        BOOST_TEST_MESSAGE("rss_before_kb=" << *rss_before / 1024 << " rss_after_kb=" << rss_after / 1024
                                            << " sim_delta_kb=" << delta / 1024
                                            << " bytes_per_node=" << delta / static_cast<int64_t>(NODES)
                                            << " peak_kb=" << netsim::PeakResidentSetBytes().value_or(0) / 1024);
    }

    LOCK(NetEventsInterface::g_msgproc_mutex);

    const Saturation sat{CountSaturation(net)};
    size_t total_known{0};
    for (uint32_t id{0}; id < NODES; ++id) {
        total_known += net.At(id).addrman->Size();
    }

    size_t total_inbound{0};
    size_t listeners_with_inbound{0};
    for (uint32_t id{0}; id < LISTENERS; ++id) {
        const size_t inbound{net.At(id).connman->GetNodeCount(ConnectionDirection::In)};
        total_inbound += inbound;
        if (inbound > 0) ++listeners_with_inbound;
    }

    // Where do the addresses the nodes hold actually point? All of them should
    // be listeners. A non-zero stranger count means non-listening nodes are
    // advertising themselves, which is what happens when the listen flag is
    // read from the process-wide fListen instead of per node.
    size_t known_listeners{0};
    size_t known_strangers{0};
    for (uint32_t id{0}; id < NODES; ++id) {
        for (const CAddress& addr : net.At(id).addrman->GetAddr(0, 0, std::nullopt, /*filtered=*/false)) {
            if (net.ListenerAt(addr).has_value()) {
                ++known_listeners;
            } else {
                ++known_strangers;
            }
        }
    }
    BOOST_TEST_MESSAGE("known_listeners=" << known_listeners << " known_strangers=" << known_strangers);

    // Addresses reached nodes that were never seeded with them, so relay works,
    // and nothing unreachable is circulating.
    BOOST_CHECK_GT(known_listeners, 0U);
    BOOST_CHECK_EQUAL(known_strangers, 0U);

    // With only reachable addresses in circulation, no outbound attempt should
    // be aimed at a dead one.
    BOOST_CHECK_EQUAL(net.FailedAttempts(), 0U);

    // Connections that are still up, as opposed to every connection ever made.
    // Feelers close themselves, so the two figures diverge.
    size_t live_links{0};
    size_t live_block_relay{0};
    for (const netsim::Link& link : net.Links()) {
        if (!link.closed) ++live_links;
    }
    for (uint32_t id{0}; id < NODES; ++id) {
        for (const CNode* peer : net.At(id).connman->TestNodes()) {
            if (peer->IsBlockOnlyConn()) ++live_block_relay;
        }
    }

    BOOST_TEST_MESSAGE("opened=" << net.TotalOpened() << " live=" << net.LiveLinks() << " closed=" << net.ClosedLinks()
                                << " full_relay=" << net.OpenedOfType(ConnectionType::OUTBOUND_FULL_RELAY)
                                << " block_relay=" << net.OpenedOfType(ConnectionType::BLOCK_RELAY)
                                << " feeler=" << net.OpenedOfType(ConnectionType::FEELER)
                                << " live_block_relay=" << live_block_relay << " inbound=" << total_inbound
                                << " saturated=" << sat.saturated << " isolated=" << sat.isolated
                                << " addrman_total=" << total_known << " failed=" << net.FailedAttempts()
                                << " rejected=" << net.RejectedAttempts() << " evicted=" << net.Evictions()
                                << " refused=" << net.InboundRefusals() << " bytes=" << net.BytesTransferred());

    // Every live connection is some listener's inbound connection.
    BOOST_CHECK_EQUAL(total_inbound, live_links);
    BOOST_CHECK_EQUAL(net.LiveLinks(), live_links);

    // Core's ladder opened all three kinds without the simulator choosing any
    // of them. Block-relay-only peers persist; feelers do not, because they
    // hang up in the VERSION handler before verack.
    BOOST_CHECK_GT(net.OpenedOfType(ConnectionType::OUTBOUND_FULL_RELAY), 0U);
    BOOST_CHECK_GT(net.OpenedOfType(ConnectionType::BLOCK_RELAY), 0U);
    BOOST_CHECK_GT(net.OpenedOfType(ConnectionType::FEELER), 0U);
    BOOST_CHECK_GT(live_block_relay, 0U);
    BOOST_CHECK_GE(net.ClosedLinks(), net.OpenedOfType(ConnectionType::FEELER));

    // No node keeps more block-relay-only peers than its slot count.
    for (uint32_t id{0}; id < NODES; ++id) {
        size_t block_relay{0};
        for (const CNode* peer : net.At(id).connman->TestNodes()) {
            if (peer->IsBlockOnlyConn()) ++block_relay;
        }
        BOOST_CHECK_LE(block_relay, static_cast<size_t>(MAX_BLOCK_RELAY_ONLY_CONNECTIONS));
    }

    // Nobody is stranded, and the listeners are all carrying traffic.
    BOOST_CHECK_EQUAL(sat.isolated, 0U);
    BOOST_CHECK_EQUAL(listeners_with_inbound, LISTENERS);

    // Most of the population fills all eight slots. It cannot be all of them:
    // a node needs eight listeners in distinct netgroups that it is not already
    // connected to, and there are only twenty listeners in total.
    BOOST_CHECK_GT(sat.saturated, NODES * 4 / 5);

    // Addresses spread past the seed set: four seeds each would be 400 in
    // total, so a materially larger figure means GETADDR responses landed.
    BOOST_CHECK_GT(total_known, NODES * opts.bootstrap_addrs);

    // No node exceeds its slot count, and no listener hit the inbound cap at
    // this population.
    for (uint32_t id{0}; id < NODES; ++id) {
        BOOST_CHECK_LE(net.At(id).connman->GetFullOutboundConnCount(), MAX_OUTBOUND_FULL_RELAY_CONNECTIONS);
    }
    BOOST_CHECK_EQUAL(net.InboundRefusals(), 0U);
}

/** Drive one listener past its inbound capacity and check Core evicts.
 *
 * The 100-node run never reaches the cap, so without a case like this the
 * eviction path would be dead code that merely compiles.
 */
BOOST_FIXTURE_TEST_CASE(netsim_inbound_eviction, SimTestingSetup)
{
    netsim::Network::Options opts;
    // Shrink the connection budget rather than inflating the population. A
    // default node holds 189 inbound, which would need hundreds of dialers,
    // and a population that cannot fill its outbound slots is expensive: every
    // attempt costs up to a hundred AddrMan selections, and selection on a
    // sparse table is some 590 times dearer than on a full one.
    // The cap has to stay well clear of Core's protections, which shield up to
    // 28 candidates outright (4 by netgroup, 8 by ping, 4 by tx time, 8 by
    // block-relay time, 4 by block time) plus a further share by ratio. Below
    // roughly 30 inbound every candidate is protected and Core correctly
    // refuses rather than evicting, which is a different code path.
    opts.max_automatic_connections = 51; // 8 + 2 + 1 outbound, so 40 inbound
    opts.num_nodes = 50;
    // Eight listeners is also eight netgroups, so a node can still fill all
    // eight outbound slots and does not sit there probing a sparse AddrMan.
    opts.num_listening = 8;
    opts.bootstrap_addrs = 8;
    opts.blocks_only = true;
    netsim::Network net{opts, ctx};

    // 8 listeners holding 40 inbound each is 320 slots against 50 nodes
    // wanting 8 outbound apiece, so demand exceeds capacity by a quarter.
    constexpr size_t INBOUND_CAP{40};

    LOCK(NetEventsInterface::g_msgproc_mutex);
    // Short on purpose. Sustained contention is expensive to simulate: each
    // eviction costs a candidate sort plus a fresh handshake, and the loser
    // retries half a second later.
    net.RunFor(std::chrono::duration_cast<SimTime>(2min));

    size_t over_cap{0};
    size_t total_inbound{0};
    for (uint32_t id{0}; id < opts.num_listening; ++id) {
        const size_t inbound{net.At(id).connman->GetNodeCount(ConnectionDirection::In)};
        total_inbound += inbound;
        if (inbound > INBOUND_CAP) ++over_cap;
    }
    BOOST_TEST_MESSAGE("inbound_total=" << total_inbound << " cap=" << INBOUND_CAP << " over_cap=" << over_cap
                                        << " evicted=" << net.Evictions() << " refused=" << net.InboundRefusals());

    // No listener exceeds its cap, the caps were actually reached, and reaching
    // them made Core evict rather than simply turn newcomers away.
    BOOST_CHECK_EQUAL(over_cap, 0U);
    BOOST_CHECK_GT(total_inbound, opts.num_listening * INBOUND_CAP / 2);
    BOOST_CHECK_GT(net.Evictions(), 0U);
}

/** The graph export has to be readable and has to agree with the live state. */
BOOST_FIXTURE_TEST_CASE(netsim_graph_export, SimTestingSetup)
{
    netsim::Network::Options opts;
    opts.num_nodes = 30;
    opts.num_listening = 12;
    opts.bootstrap_addrs = 6;
    opts.blocks_only = true;
    netsim::Network net{opts, ctx};

    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        // Short enough to stay clear of the chain-sync timeout described in §8
        // of the plan, which starts shedding outbound peers at 20 minutes.
        net.RunFor(std::chrono::duration_cast<SimTime>(5min));
    }

    const fs::path prefix{m_path_root / "graph"};
    BOOST_REQUIRE(netsim::WriteGraph(net, prefix));

    const auto read_lines{[](const fs::path& path) {
        std::ifstream in{path.std_path()};
        BOOST_REQUIRE(in.is_open());
        std::vector<std::string> lines;
        std::string line;
        while (std::getline(in, line)) {
            if (!line.empty()) lines.push_back(line);
        }
        return lines;
    }};

    const auto nodes{read_lines(fs::PathFromString(fs::PathToString(prefix) + "-nodes.csv"))};
    const auto edges{read_lines(fs::PathFromString(fs::PathToString(prefix) + "-edges.csv"))};

    // Header plus one row per node, and header plus one row per connection
    // still up. The export is a snapshot: a closed connection is gone from it,
    // which is what keeps short-lived feelers out of the file entirely.
    BOOST_REQUIRE_EQUAL(nodes.size(), opts.num_nodes + 1);
    BOOST_REQUIRE_EQUAL(edges.size(), net.LiveLinks() + 1);
    BOOST_CHECK_EQUAL(nodes[0], netsim::NodeColumns());
    BOOST_CHECK_EQUAL(edges[0], netsim::EdgeColumns());

    const auto fields{[](const std::string& line) {
        std::vector<std::string> out;
        std::string field;
        std::istringstream stream{line};
        while (std::getline(stream, field, ',')) out.push_back(field);
        return out;
    }};

    // Every node row names itself, and the inbound degrees in the file add up
    // to the number of connections still open.
    size_t inbound_sum{0};
    for (size_t i{1}; i < nodes.size(); ++i) {
        const auto row{fields(nodes[i])};
        BOOST_REQUIRE_EQUAL(row.size(), 12U);
        BOOST_CHECK_EQUAL(row[0], util::ToString(i - 1));
        BOOST_CHECK_EQUAL(row[1], net.At(static_cast<uint32_t>(i - 1)).self.ToStringAddrPort());
        inbound_sum += static_cast<size_t>(std::stoul(row[11]));
    }

    for (size_t i{1}; i < edges.size(); ++i) {
        const auto row{fields(edges[i])};
        BOOST_REQUIRE_EQUAL(row.size(), 6U);
        // An initiator is never its own acceptor.
        BOOST_CHECK(row[0] != row[1]);
        // Every row names the instant it was opened.
        BOOST_CHECK(row[3] != "-1");
    }

    // The inbound degrees in the node file account for every exported edge.
    BOOST_CHECK_EQUAL(inbound_sum, edges.size() - 1);
}

/** A withheld listener address reaches the population by relay alone.
 *
 * Nobody is seeded with node 0's address, so the only route it has into any
 * other AddrMan is Core's own machinery: node 0 learns its own address from
 * the `addr_recv` field of a peer's VERSION, self-announces it to the peers it
 * dialled, and each of those gossips it on. If any of that were missing the
 * coverage would stay at zero for the whole run.
 */
BOOST_FIXTURE_TEST_CASE(netsim_addr_relay_reaches_the_population, SimTestingSetup)
{
    netsim::Network::Options opts;
    opts.num_nodes = 40;
    opts.num_listening = 12;
    opts.num_tracked = 1;
    opts.bootstrap_addrs = 6;
    opts.blocks_only = true;
    opts.addr_sample_interval = std::chrono::duration_cast<SimTime>(30s);
    netsim::Network net{opts, ctx};

    // Taken before anything has connected: the withheld address is unknown.
    BOOST_REQUIRE_EQUAL(net.AddrSamples().size(), 1U);
    BOOST_CHECK_EQUAL(net.AddrSamples().front().holders, 0U);
    BOOST_CHECK_EQUAL(net.AddrSamples().front().node, 0U);

    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        net.RunFor(std::chrono::duration_cast<SimTime>(8min));
    }

    const auto& samples{net.AddrSamples()};
    BOOST_REQUIRE_GT(samples.size(), 2U);
    const auto& last{samples.back()};
    BOOST_TEST_MESSAGE("samples=" << samples.size() << " final_holders=" << last.holders
                                   << " in_tried=" << last.in_tried
                                   << " multiplicity=" << last.multiplicity);

    // It got past the peers node 0 dialled itself, which is the part that
    // needs relay rather than a handshake.
    BOOST_CHECK_GT(last.holders, net.At(0).connman->GetNodeCount(ConnectionDirection::Out));
    // Nobody can have tried it without first having been told about it.
    BOOST_CHECK_LE(last.in_tried, last.holders);

    // Coverage is non-decreasing here: nothing is terrible enough to be
    // dropped, and the tables are far from full.
    for (size_t i{1}; i < samples.size(); ++i) {
        BOOST_CHECK_GE(samples[i].holders, samples[i - 1].holders);
        BOOST_CHECK_GT(samples[i].at.count(), samples[i - 1].at.count());
    }

    // And the writer agrees with what the run recorded.
    const fs::path path{m_path_root / "addr-samples.csv"};
    BOOST_REQUIRE(netsim::WriteAddrSamples(net, path));
    std::ifstream in{path.std_path()};
    BOOST_REQUIRE(in.is_open());
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty()) lines.push_back(line);
    }
    BOOST_REQUIRE_EQUAL(lines.size(), samples.size() + 1);
    BOOST_CHECK_EQUAL(lines[0], netsim::AddrSampleColumns());
    BOOST_CHECK_EQUAL(lines[1], "0,0," + net.At(0).self.ToStringAddrPort() + ",0,0,0");
}

/** The address relay tree, read out of AddrMan rather than inferred.
 *
 * A block's sender is known because the simulator is servicing that link when
 * the tip moves. An address has no such instant: it is noticed by sampling,
 * minutes later. But AddrMan stored the peer it first heard the address from
 * when it created the entry, so the edge is recoverable after the fact, and
 * that is what `AddrArrival::from` carries.
 *
 * What makes it worth checking is that nothing forces the stored source to be
 * a peer: it is whatever `ProcessAddrs` passed, and bootstrap seeds are
 * deliberately self-sourced. So every edge here has to be one the topology
 * actually contains, and has to point back in time.
 */
BOOST_FIXTURE_TEST_CASE(netsim_addr_sources_form_a_relay_tree, SimTestingSetup)
{
    netsim::Network::Options opts;
    opts.num_nodes = 40;
    opts.num_listening = 12;
    opts.num_tracked = 1;
    opts.bootstrap_addrs = 6;
    opts.blocks_only = true;
    opts.addr_sample_interval = std::chrono::duration_cast<SimTime>(30s);
    opts.record_addr_sources = true;
    netsim::Network net{opts, ctx};

    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        net.RunFor(std::chrono::duration_cast<SimTime>(8min));
    }

    const auto& arrivals{net.AddrArrivals()};
    BOOST_REQUIRE_GT(arrivals.size(), 1U);

    // When each node first appeared as a holder, so an edge can be checked
    // against the time of the node it points at.
    std::map<uint32_t, SimTime> held;
    for (const auto& a : arrivals) held.emplace(a.node, a.at);

    size_t attributed{0};
    size_t from_the_owner{0};
    for (const auto& a : arrivals) {
        BOOST_CHECK_EQUAL(a.address_of, 0U);
        if (a.from < 0) continue; // a source outside the population
        ++attributed;
        const uint32_t from{static_cast<uint32_t>(a.from)};
        // Not itself, and a node that exists.
        BOOST_CHECK_NE(from, a.node);
        BOOST_CHECK_LT(from, opts.num_nodes);
        if (from == 0) {
            // The owner announcing itself, which is the root of the tree.
            ++from_the_owner;
            continue;
        }
        // Anyone else can only pass on an address they already had, and they
        // must have been seen holding it by this sample or an earlier one.
        const auto it{held.find(from)};
        BOOST_CHECK(it != held.end());
        if (it != held.end()) BOOST_CHECK_LE(it->second.count(), a.at.count());
    }

    BOOST_TEST_MESSAGE("arrivals=" << arrivals.size() << " attributed=" << attributed
                                   << " from_the_owner=" << from_the_owner);
    // The lookup works at all, and the spread is rooted at the node whose
    // address it is rather than appearing from nowhere.
    BOOST_CHECK_GT(attributed, 0U);
    BOOST_CHECK_GT(from_the_owner, 0U);

    // And the writer carries the column.
    const fs::path path{m_path_root / "addr-arrivals.csv"};
    BOOST_REQUIRE(netsim::WriteAddrArrivals(net, path));
    std::ifstream in{path.std_path()};
    BOOST_REQUIRE(in.is_open());
    std::string header;
    BOOST_REQUIRE(std::getline(in, header));
    BOOST_CHECK_EQUAL(header, netsim::AddrArrivalColumns());
    BOOST_CHECK(header.ends_with(",from"));
}

/** A population spread over IPv4, IPv6, Tor and I2P still forms a topology.
 *
 * Two parts of Core only come alive here. `MaybePickPreferredNetwork` exists
 * to put one outbound peer on every reachable network and can never fire in a
 * single-network population. And `CountOutboundSlots` files Tor and I2P peers
 * under `privacy_network_peers` instead of the netgroup set, because
 * `GetGroup` gives those addresses only four bits, so a Tor-heavy population
 * fills its outbound slots on far fewer distinct netgroups than it has peers.
 */
BOOST_FIXTURE_TEST_CASE(netsim_multi_network_topology, SimTestingSetup)
{
    using Net = AddressUniverse::Net;

    netsim::Network::Options opts;
    opts.num_nodes = 120;
    opts.num_listening = 40;
    opts.bootstrap_addrs = 12;
    opts.blocks_only = true;
    opts.addresses.UseMainnetMix();
    opts.addresses.mainnet_netgroups = true;
    netsim::Network net{opts, ctx};

    const auto& universe{net.Addresses()};
    BOOST_REQUIRE_GT(universe.CountOn(Net::IPv4), 0U);
    BOOST_REQUIRE_GT(universe.CountOn(Net::IPv6), 0U);
    BOOST_REQUIRE_GT(universe.CountOn(Net::Onion), 0U);
    BOOST_REQUIRE_GT(universe.CountOn(Net::I2P), 0U);

    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        net.RunFor(std::chrono::duration_cast<SimTime>(5min));
    }

    const Saturation sat{CountSaturation(net)};
    std::set<Network> peer_nets;
    for (uint32_t id{0}; id < opts.num_nodes; ++id) {
        for (const CNode* peer : net.At(id).connman->TestNodes()) {
            peer_nets.insert(peer->addr.GetNetwork());
        }
    }
    BOOST_TEST_MESSAGE("netgroups=" << net.NumNetgroups() << " saturated=" << sat.saturated
                                    << " isolated=" << sat.isolated << " peer_nets=" << peer_nets.size());

    // Connections were actually made on every one of the four networks, not
    // merely offered.
    BOOST_CHECK(peer_nets.contains(NET_IPV4));
    BOOST_CHECK(peer_nets.contains(NET_IPV6));
    BOOST_CHECK(peer_nets.contains(NET_ONION));
    BOOST_CHECK(peer_nets.contains(NET_I2P));

    BOOST_CHECK_EQUAL(sat.isolated, 0U);
    BOOST_CHECK_GT(sat.saturated, opts.num_nodes / 2);
    // Fewer distinct netgroups than nodes, which is the point of the mainnet
    // occupancy, and nodes saturate anyway.
    BOOST_CHECK_LT(net.NumNetgroups(), opts.num_nodes);
}

/** A chain that advances keeps peers from being shed every twenty minutes.
 *
 * `ConsiderEviction` disconnects an outbound peer that has not announced a
 * chain as long as ours within `CHAIN_SYNC_TIMEOUT`, which is 20 minutes. On a
 * static chain nobody ever announces anything, so every node sheds its
 * headers-sync peers on a twenty-minute cycle. This is the honest fix rather
 * than the gate: give them a tip that moves, and the announcements that follow
 * satisfy the timer on their own.
 */
BOOST_FIXTURE_TEST_CASE(netsim_mining_satisfies_the_chain_sync_timer, SimChainTestingSetup)
{
    netsim::Network::Options opts;
    opts.num_nodes = 40;
    opts.num_listening = 16;
    opts.bootstrap_addrs = 8;
    opts.blocks_only = true;
    opts.chain.initial_blocks = 20;
    opts.mine = true;
    // Evenly spaced on purpose. Real arrivals are Poisson, and
    // netsim_block_intervals_are_exponential covers that; here a fixed
    // schedule is what makes "five blocks in fifty minutes" a statement about
    // the chain-sync timer rather than about a lucky draw.
    opts.chain.poisson = false;
    netsim::Network net{opts, ctx};

    // The chain was built before any node existed, and its tip landed on the
    // instant the run starts, which is what keeps the nodes out of initial
    // block download without being told.
    BOOST_REQUIRE_EQUAL(net.ChainHeight(), 20);
    BOOST_REQUIRE_EQUAL(net.GetChain().Mined(), 0U);
    BOOST_CHECK(!WITH_LOCK(cs_main, return m_node.chainman->IsInitialBlockDownload()));

    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        // Well past the twenty-minute timeout, which is the whole point.
        net.RunFor(std::chrono::duration_cast<SimTime>(50min));
    }

    // Five blocks at the ten-minute interval.
    BOOST_CHECK_EQUAL(net.GetChain().Mined(), 5U);
    BOOST_CHECK_EQUAL(net.ChainHeight(), 25);

    const Saturation sat{CountSaturation(net)};
    BOOST_TEST_MESSAGE("height=" << net.ChainHeight() << " saturated=" << sat.saturated
                                  << " isolated=" << sat.isolated << " opened=" << net.TotalOpened()
                                  << " live=" << net.LiveLinks());

    // The nodes are not being told to ignore the timer here, so holding their
    // outbound peers past fifty simulated minutes is the result worth having.
    BOOST_CHECK_EQUAL(sat.isolated, 0U);
    BOOST_CHECK_GT(sat.saturated, opts.num_nodes * 3 / 4);
}

/** Block intervals are exponential, with the asked-for mean.
 *
 * Checked on the Chain alone rather than through a run, because a thousand
 * draws is the smallest sample that says anything about a distribution and a
 * thousand simulated blocks is not.
 */
BOOST_FIXTURE_TEST_CASE(netsim_block_intervals_are_exponential, SimChainTestingSetup)
{
    constexpr size_t DRAWS{20'000};
    netsim::Chain::Options opts;
    opts.spacing = 600s;
    netsim::Chain chain{*m_node.chainman, m_node.block_template_manager.get(),
                        m_node.validation_signals.get(), opts};

    std::vector<int64_t> gaps;
    gaps.reserve(DRAWS);
    int64_t total{0};
    for (size_t i{0}; i < DRAWS; ++i) {
        gaps.push_back(chain.NextInterval().count());
        total += gaps.back();
    }

    const double mean{double(total) / DRAWS};
    // The standard error of the mean of an exponential is mean/sqrt(n), so
    // 600/141 = 4.2 seconds here; ten of those is a wide berth.
    BOOST_TEST_MESSAGE("mean=" << mean);
    BOOST_CHECK_GT(mean, 560.0);
    BOOST_CHECK_LT(mean, 640.0);

    // An exponential has its median at ln(2) times the mean, well below it,
    // and a long tail: a fixed interval would have neither.
    std::ranges::sort(gaps);
    const double median{double(gaps[DRAWS / 2])};
    BOOST_TEST_MESSAGE("median=" << median << " max=" << gaps.back());
    BOOST_CHECK_GT(median, 0.9 * 600.0 * 0.693);
    BOOST_CHECK_LT(median, 1.1 * 600.0 * 0.693);
    BOOST_CHECK_GT(gaps.back(), 3 * 600);

    // And the knob that turns it off, which exists so a test can pin a count.
    opts.poisson = false;
    netsim::Chain fixed{*m_node.chainman, m_node.block_template_manager.get(),
                        m_node.validation_signals.get(), opts};
    BOOST_CHECK(fixed.NextInterval() == 600s);
    BOOST_CHECK(fixed.NextInterval() == 600s);
}

/** A block really travels when every node validates its own chain.
 *
 * The load-bearing test for block relay. With one shared chainstate
 * `AlreadyHaveBlock` answers yes for every node the instant the miner's header
 * is in the index, so no `getdata` is ever sent and nothing propagates. With a
 * chain each, node 1 has to be told the block exists, ask for it, receive it
 * and validate it before its own tip moves.
 */
BOOST_FIXTURE_TEST_CASE(netsim_block_relay_moves_a_block, SimChainTestingSetup)
{
    netsim::Network::Options opts;
    opts.num_nodes = 2;
    opts.num_listening = 2;
    opts.bootstrap_addrs = 1;
    opts.per_node_chain = true;
    opts.datadir = m_path_root / "blockrelay";
    // Enough prefill to put every node's tip inside max_tip_age, so nobody
    // starts in initial block download, where announcements are suppressed.
    opts.chain.initial_blocks = 2;
    opts.chain.poisson = false;
    netsim::Network net{opts, ctx};

    // Both nodes start on the same chain, each in its own index.
    const auto height{[&](uint32_t id) {
        return WITH_LOCK(::cs_main, return net.At(id).chainman->ActiveChain().Height());
    }};
    BOOST_REQUIRE_EQUAL(height(0), 2);
    BOOST_REQUIRE_EQUAL(height(1), 2);
    BOOST_REQUIRE(net.At(0).chainman != net.At(1).chainman);
    BOOST_REQUIRE(!WITH_LOCK(::cs_main, return net.At(1).chainman->IsInitialBlockDownload()));

    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        // Let them find each other first.
        net.RunFor(std::chrono::duration_cast<SimTime>(30s));
        BOOST_REQUIRE_GT(net.LiveLinks(), 0U);

        const uint64_t bytes_before{net.BytesTransferred()};
        BOOST_REQUIRE(net.GetChain().MineOne());
        BOOST_REQUIRE_EQUAL(height(0), 3);
        // Node 1 cannot know yet: nothing has been sent.
        BOOST_CHECK_EQUAL(height(1), 2);

        net.RunFor(std::chrono::duration_cast<SimTime>(60s));
        BOOST_TEST_MESSAGE("heights " << height(0) << "/" << height(1)
                                      << " bytes " << (net.BytesTransferred() - bytes_before));
        // It arrived, by announcement, request and transfer.
        BOOST_CHECK_EQUAL(height(1), 3);
        BOOST_CHECK_GT(net.BytesTransferred(), bytes_before);
    }
}

/** No chain means no announcements, which is why the gate exists. */
BOOST_FIXTURE_TEST_CASE(netsim_static_chain_needs_the_gate, SimTestingSetup)
{
    // SimTestingSetup publishes no tip notifications, so MakeNode turns the
    // chain-sync timeout off. Without that this run would shed peers.
    netsim::Network::Options opts;
    opts.num_nodes = 30;
    opts.num_listening = 10;
    opts.bootstrap_addrs = 8;
    opts.blocks_only = true;
    netsim::Network net{opts, ctx};
    BOOST_CHECK_EQUAL(net.ChainHeight(), 0);

    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        net.RunFor(std::chrono::duration_cast<SimTime>(30min));
    }

    BOOST_CHECK_EQUAL(CountSaturation(net).isolated, 0U);
}

/** An onion listener's address spreads, which needs a per-node address table.
 *
 * `version`'s `addr_recv` field is V1-serialized and
 * `CNetAddr::SerializeV1Array` writes onion and I2P addresses as all-zeros, so
 * a node on either network cannot learn its own address from a peer the way an
 * IPv4 node can. Its only route is `LocalAddresses`, filled in production from
 * the Tor control port or `-i2psam` and here by `MakeNode`. While that table
 * was a process global it could not hold a per-node view, and so every onion
 * and I2P address in a run stayed where it started.
 */
BOOST_FIXTURE_TEST_CASE(netsim_privacy_network_addresses_spread, SimTestingSetup)
{
    using Net = AddressUniverse::Net;

    netsim::Network::Options opts;
    opts.num_nodes = 60;
    opts.num_listening = 20;
    opts.num_tracked = 4;
    opts.bootstrap_addrs = 10;
    opts.blocks_only = true;
    opts.addresses.UseMainnetMix();
    opts.addr_sample_interval = std::chrono::duration_cast<SimTime>(1min);
    netsim::Network net{opts, ctx};

    // The four withheld listeners have to span more than one network for this
    // to be testing anything.
    std::set<Net> tracked_nets;
    for (const uint32_t id : net.TrackedNodes()) tracked_nets.insert(net.Addresses().NetOf(id));
    BOOST_REQUIRE_GT(tracked_nets.size(), 1U);
    BOOST_REQUIRE(tracked_nets.contains(Net::Onion) || tracked_nets.contains(Net::I2P));

    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        net.RunFor(std::chrono::duration_cast<SimTime>(10min));
    }

    // The last sample for each tracked address.
    std::map<uint32_t, uint32_t> final_holders;
    for (const auto& sample : net.AddrSamples()) final_holders[sample.node] = sample.holders;

    for (const uint32_t id : net.TrackedNodes()) {
        const auto net_name{AddressUniverse::NetName(net.Addresses().NetOf(id))};
        BOOST_TEST_MESSAGE("node " << id << " on " << net_name << " reached "
                                    << final_holders[id] << " of " << (opts.num_nodes - 1));
        // Past the peers it dialled itself, which is the part needing relay.
        BOOST_CHECK_MESSAGE(final_holders[id] > MAX_OUTBOUND_FULL_RELAY_CONNECTIONS,
                            std::string{"a withheld "} + net_name + " address reached only " +
                                util::ToString(final_holders[id]) + " nodes");
    }
}

/** Without tracking, nothing is withheld and nothing is sampled. */
BOOST_FIXTURE_TEST_CASE(netsim_addr_sampling_is_opt_in, SimTestingSetup)
{
    netsim::Network::Options opts;
    opts.num_nodes = 8;
    opts.num_listening = 4;
    netsim::Network net{opts, ctx};
    BOOST_CHECK(net.TrackedNodes().empty());
    BOOST_CHECK(net.AddrSamples().empty());

    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        net.RunFor(std::chrono::duration_cast<SimTime>(1min));
    }
    BOOST_CHECK(net.AddrSamples().empty());
}

/* ---------------------------------------------------------------------------
 * Cost probes.
 *
 * Disabled by default, because they measure rather than assert: a number that
 * drifts is a finding to look at, not a build to fail. ctest runs the suite
 * with --run_test=netsim_tests, finds every probe disabled, and skips them.
 *
 * To take a reading, name one explicitly:
 *
 *   TMPDIR=/some/large/tmp build/bin/test_bitcoin \
 *       --run_test=netsim_tests/probe_node_cost -l test_suite
 *
 * §5 of netsim-plan.md records what each of these last returned, on what
 * machine, and what the numbers mean. Update it when you re-measure.
 * ------------------------------------------------------------------------- */

/** Compile-time size of the structures a node carries one of. */
BOOST_AUTO_TEST_CASE(probe_type_sizes, *boost::unit_test::disabled())
{
    // AddrMan is a pimpl, so the 8 bytes of the handle are not the cost. The
    // tables inside are what dominate an idle node.
    BOOST_TEST_MESSAGE("sizeof(AddrManImpl)      = " << sizeof(AddrManImpl));
    BOOST_TEST_MESSAGE("sizeof(CNode)            = " << sizeof(CNode));
    BOOST_TEST_MESSAGE("sizeof(CBlockIndex)      = " << sizeof(CBlockIndex));
    BOOST_TEST_MESSAGE("sizeof(CService)         = " << sizeof(CService));
    BOOST_TEST_MESSAGE("sizeof(netsim::SimNode)  = " << sizeof(netsim::SimNode));
    BOOST_TEST_MESSAGE("sizeof(netsim::Link)     = " << sizeof(netsim::Link));
}

namespace {
/** Build N idle nodes and report what each cost in resident memory.
 *
 * Only ever called once per process, and the three probes below are separate
 * test cases for exactly that reason: glibc does not return a freed arena to
 * the kernel, so a second measurement in the same process sees a resident set
 * that never shrank and reports nearly zero. Run them one at a time.
 *
 * Idle is the other operative word. A node with no peers has no
 * `Peer::TxRelay`, so the 527 KiB per-peer inventory filter that dominates a
 * transaction-relaying run does not appear here, and blocks-only measures the
 * same as tx-relay. This is the fixed floor; §5's whole-run figures are the
 * floor plus what the peers cost.
 */
void ReportNodeCost(const char* label, const netsim::SharedContext& ctx, const fs::path& root,
                    bool blocks_only, bool own_chain)
{
    constexpr size_t N{64};
    const AddressUniverse universe{N, 18444};

    const uint64_t before{netsim::ResidentSetBytes().value_or(0)};
    std::vector<std::unique_ptr<netsim::SimNode>> nodes;
    nodes.reserve(N);
    for (size_t i{0}; i < N; ++i) {
        netsim::NodeOptions opts;
        opts.id = static_cast<uint32_t>(i);
        opts.self = universe.At(static_cast<uint32_t>(i));
        opts.listening = true;
        opts.blocks_only = blocks_only;
        opts.own_chain = own_chain;
        if (own_chain) {
            opts.datadir = root / fs::u8path(std::string{"probe"} + util::ToString(i));
        }
        nodes.push_back(netsim::MakeNode(ctx, opts));
    }
    const uint64_t after{netsim::ResidentSetBytes().value_or(0)};
    BOOST_TEST_MESSAGE(label << " = " << (after - before) / N << " bytes/node");
}
} // namespace

BOOST_FIXTURE_TEST_CASE(probe_node_cost_blocksonly, SimChainTestingSetup, *boost::unit_test::disabled())
{
    ReportNodeCost("idle, blocks-only, shared chain", ctx, m_path_root,
                   /*blocks_only=*/true, /*own_chain=*/false);
}

BOOST_FIXTURE_TEST_CASE(probe_node_cost_txrelay, SimChainTestingSetup, *boost::unit_test::disabled())
{
    ReportNodeCost("idle, tx-relay, shared chain", ctx, m_path_root,
                   /*blocks_only=*/false, /*own_chain=*/false);
}

BOOST_FIXTURE_TEST_CASE(probe_node_cost_own_chain, SimChainTestingSetup, *boost::unit_test::disabled())
{
    ReportNodeCost("idle, blocks-only, own chain", ctx, m_path_root,
                   /*blocks_only=*/true, /*own_chain=*/true);
}

/** The three lazily-allocated rolling bloom filters in TxDownloadManager.
 *
 * Two of them used to be allocated on the first tip change merely to be
 * reset; see the fix in `TxDownloadManagerImpl::ActiveTipChange`. The third is
 * real, because `BlockConnected` inserts the coinbase into it.
 */
BOOST_AUTO_TEST_CASE(probe_rolling_bloom_cost, *boost::unit_test::disabled())
{
    constexpr size_t N{200};
    const auto measure{[](unsigned int elements) {
        const uint64_t before{netsim::ResidentSetBytes().value_or(0)};
        std::vector<std::unique_ptr<CRollingBloomFilter>> filters;
        filters.reserve(N);
        for (size_t i{0}; i < N; ++i) {
            filters.push_back(std::make_unique<CRollingBloomFilter>(elements, 0.000001));
        }
        const uint64_t after{netsim::ResidentSetBytes().value_or(0)};
        return (after - before) / N;
    }};
    BOOST_TEST_MESSAGE("recent_rejects / reconsiderable (120k, 1e-6) = " << measure(120'000) << " bytes each");
    BOOST_TEST_MESSAGE("recent_confirmed_transactions   (48k,  1e-6) = " << measure(48'000) << " bytes each");
}

BOOST_AUTO_TEST_SUITE_END()
