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
#include <netsim/latency.h>
#include <netsim/node.h>
#include <netsim/pump.h>
#include <node/protocol_version.h>
#include <protocol.h>
#include <random.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <uint256.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <memory>
#include <set>
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

    const auto conn{netsim::ConnectPair(ctx, *dialer, *listener, /*out_id=*/0, /*in_id=*/1)};
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
    BOOST_CHECK_GT(conn.out_side->nSendBytes, 0U);
    BOOST_CHECK_GT(conn.out_side->nRecvBytes, 0U);
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
    const auto conn{netsim::ConnectPair(ctx, *dialer, *listener, /*out_id=*/0, /*in_id=*/1)};

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

BOOST_AUTO_TEST_SUITE_END()
