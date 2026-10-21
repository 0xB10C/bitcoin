// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net.h>
#include <net_processing.h>
#include <netaddress.h>
#include <netgroup.h>
#include <netsim/addresses.h>
#include <netsim/clock.h>
#include <netsim/eventqueue.h>
#include <netsim/export.h>
#include <netsim/latency.h>
#include <netsim/metrics.h>
#include <netsim/network.h>
#include <netsim/node.h>
#include <netsim/pump.h>
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
#include <fstream>
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

//! Options a simulation wants from TestingSetup, as opposed to what a test wants.
TestOpts SimTestOpts()
{
    TestOpts opts;
    // Every node builds its own CConnman and PeerManager, so the fixture's
    // single set would just be dead weight.
    opts.setup_net = false;
    // Otherwise ValidationCache eagerly allocates and touches 32.25 MiB.
    opts.min_validation_cache = true;
    return opts;
}

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

    SimTestingSetup()
        : TestingSetup{ChainType::REGTEST, SimTestOpts()},
          ctx{*m_node.chainman, *m_node.mempool, *m_node.warnings, netgroupman}
    {
        // MaybeSendAddr() refuses to advertise a node's own address while the
        // chainstate reports initial block download, and self-announcement is
        // the only thing that propagates addresses more than one hop.
        static_cast<TestChainstateManager&>(*m_node.chainman).JumpOutOfIbd();
    }
};

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

/** The load-bearing test: two real nodes complete a real handshake with no sockets. */
BOOST_FIXTURE_TEST_CASE(netsim_two_node_handshake, SimTestingSetup)
{
    SimClock clock{SIM_START};
    const AddressUniverse universe{2, 8333};

    auto dialer{netsim::MakeNode(ctx, /*id=*/0, universe.At(0), /*listening=*/false)};
    auto listener{netsim::MakeNode(ctx, /*id=*/1, universe.At(1), /*listening=*/true)};

    // One lock for the whole run, as the fuzz driver does. Every
    // ProcessMessages and SendMessages call requires it, and it is a single
    // process-global mutex rather than one per CConnman.
    LOCK(NetEventsInterface::g_msgproc_mutex);

    const auto conn{netsim::ConnectPair(ctx, *dialer, *listener, ConnectionType::OUTBOUND_FULL_RELAY, /*out_id=*/0, /*in_id=*/1)};
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

    auto dialer{netsim::MakeNode(ctx, /*id=*/0, universe.At(0), /*listening=*/false)};
    auto listener{netsim::MakeNode(ctx, /*id=*/1, universe.At(1), /*listening=*/true)};

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
    const auto conn{netsim::ConnectPair(ctx, *dialer, *listener, ConnectionType::OUTBOUND_FULL_RELAY, /*out_id=*/0, /*in_id=*/1)};

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

    [[maybe_unused]] size_t total_outbound{0};
    size_t saturated{0};
    size_t isolated{0};
    size_t total_known{0};
    for (uint32_t id{0}; id < NODES; ++id) {
        const int outbound{net.At(id).connman->GetFullOutboundConnCount()};
        total_outbound += static_cast<size_t>(outbound);
        if (outbound >= MAX_OUTBOUND_FULL_RELAY_CONNECTIONS) ++saturated;
        if (outbound == 0) ++isolated;
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
                                << " saturated=" << saturated << " isolated=" << isolated
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
    BOOST_CHECK_EQUAL(isolated, 0U);
    BOOST_CHECK_EQUAL(listeners_with_inbound, LISTENERS);

    // Most of the population fills all eight slots. It cannot be all of them:
    // a node needs eight listeners in distinct netgroups that it is not already
    // connected to, and there are only twenty listeners in total.
    BOOST_CHECK_GT(saturated, NODES * 4 / 5);

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
        BOOST_REQUIRE_EQUAL(row.size(), 11U);
        BOOST_CHECK_EQUAL(row[0], util::ToString(i - 1));
        BOOST_CHECK_EQUAL(row[1], net.At(static_cast<uint32_t>(i - 1)).self.ToStringAddrPort());
        inbound_sum += static_cast<size_t>(std::stoul(row[10]));
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

BOOST_AUTO_TEST_SUITE_END()
