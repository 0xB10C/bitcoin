// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netaddress.h>
#include <netgroup.h>
#include <netsim/addresses.h>
#include <netsim/clock.h>
#include <netsim/eventqueue.h>
#include <netsim/latency.h>
#include <random.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
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

BOOST_AUTO_TEST_SUITE_END()
