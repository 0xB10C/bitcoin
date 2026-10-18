// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <holepunch.h>
#include <netbase.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>


using namespace holepunch;

BOOST_FIXTURE_TEST_SUITE(holepunch_tests, BasicTestingSetup)

namespace {
const std::vector<unsigned char> GROUP_A{1};
const std::vector<unsigned char> GROUP_B{2};
const std::vector<unsigned char> GROUP_C{3};

CService Addr(const std::string& s)
{
    return LookupNumeric(s, 0);
}
} // namespace

BOOST_AUTO_TEST_CASE(external_address_needs_two_groups)
{
    ExternalAddressTracker tracker;
    const CService ext{Addr("1.2.3.4:8335")};

    BOOST_CHECK(!tracker.Get(NET_IPV4));
    BOOST_CHECK(tracker.AddReport(1, GROUP_A, ext, /*allow_local=*/false));
    // One report is never enough (R-2.2).
    BOOST_CHECK(!tracker.Get(NET_IPV4));
    // Two reports from the same group are not enough either.
    BOOST_CHECK(tracker.AddReport(2, GROUP_A, ext, /*allow_local=*/false));
    BOOST_CHECK(!tracker.Get(NET_IPV4));
    // A second group agreeing yields the external address.
    BOOST_CHECK(tracker.AddReport(3, GROUP_B, ext, /*allow_local=*/false));
    BOOST_REQUIRE(tracker.Get(NET_IPV4));
    BOOST_CHECK_EQUAL(tracker.Get(NET_IPV4)->ToStringAddrPort(), "1.2.3.4:8335");
    const auto info{tracker.GetInfo(NET_IPV4)};
    BOOST_CHECK_EQUAL(info.reporters, 3);
    BOOST_CHECK_EQUAL(info.reports, 3);
    BOOST_CHECK(!info.conflicting);
    // IPv6 is tracked separately.
    BOOST_CHECK(!tracker.Get(NET_IPV6));
}

BOOST_AUTO_TEST_CASE(external_address_single_dissenter_is_ignored)
{
    ExternalAddressTracker tracker;
    const CService ext{Addr("1.2.3.4:8335")};
    BOOST_CHECK(tracker.AddReport(1, GROUP_A, ext, /*allow_local=*/false));
    BOOST_CHECK(tracker.AddReport(2, GROUP_B, ext, /*allow_local=*/false));
    BOOST_REQUIRE(tracker.Get(NET_IPV4));

    // One peer reporting a different port changes nothing (R-2.2).
    BOOST_CHECK(tracker.AddReport(3, GROUP_C, Addr("1.2.3.4:40001"), /*allow_local=*/false));
    BOOST_REQUIRE(tracker.Get(NET_IPV4));
    BOOST_CHECK_EQUAL(tracker.Get(NET_IPV4)->GetPort(), 8335);
    BOOST_CHECK(!tracker.GetInfo(NET_IPV4).conflicting);

    // A second peer in another group agreeing with the dissenter makes two
    // agreeing sets that disagree: no external address (R-2.3).
    BOOST_CHECK(tracker.AddReport(4, GROUP_A, Addr("1.2.3.4:40001"), /*allow_local=*/false));
    BOOST_CHECK(!tracker.Get(NET_IPV4));
    BOOST_CHECK(tracker.GetInfo(NET_IPV4).conflicting);

    // When the dissenters leave, the external address is back (R-2.4).
    tracker.RemovePeer(3);
    tracker.RemovePeer(4);
    BOOST_REQUIRE(tracker.Get(NET_IPV4));
    BOOST_CHECK_EQUAL(tracker.Get(NET_IPV4)->GetPort(), 8335);

    // When one of the two agreeing peers leaves, it is gone.
    tracker.RemovePeer(1);
    BOOST_CHECK(!tracker.Get(NET_IPV4));
}

BOOST_AUTO_TEST_CASE(external_address_report_replaced_per_peer)
{
    ExternalAddressTracker tracker;
    BOOST_CHECK(tracker.AddReport(1, GROUP_A, Addr("1.2.3.4:8335"), /*allow_local=*/false));
    BOOST_CHECK(tracker.AddReport(2, GROUP_B, Addr("1.2.3.4:8335"), /*allow_local=*/false));
    BOOST_REQUIRE(tracker.Get(NET_IPV4));
    // A peer's newer report replaces its older one.
    BOOST_CHECK(tracker.AddReport(2, GROUP_B, Addr("1.2.3.4:40001"), /*allow_local=*/false));
    BOOST_CHECK(!tracker.Get(NET_IPV4));
    BOOST_CHECK_EQUAL(tracker.GetInfo(NET_IPV4).reports, 2);
}

BOOST_AUTO_TEST_CASE(external_address_rejects_unusable_reports)
{
    ExternalAddressTracker tracker;
    // Port 0, non-routable address, and non-IP networks are not reports (R-2.1).
    BOOST_CHECK(!tracker.AddReport(1, GROUP_A, Addr("1.2.3.4:0"), /*allow_local=*/false));
    BOOST_CHECK(!tracker.AddReport(1, GROUP_A, Addr("127.0.0.1:8335"), /*allow_local=*/false));
    BOOST_CHECK(!tracker.AddReport(1, GROUP_A, Addr("10.0.0.1:8335"), /*allow_local=*/false));
    BOOST_CHECK(!tracker.AddReport(1, GROUP_A, CService{}, /*allow_local=*/false));
    BOOST_CHECK_EQUAL(tracker.GetInfo(NET_IPV4).reports, 0);
    BOOST_CHECK(tracker.AddReport(1, GROUP_A, Addr("[2a00:1450::1]:8335"), /*allow_local=*/false));
    BOOST_CHECK_EQUAL(tracker.GetInfo(NET_IPV6).reports, 1);
}

BOOST_AUTO_TEST_CASE(external_address_on_test_networks)
{
    // With allow_local, loopback addresses count and every peer is its own group (R-2.5).
    ExternalAddressTracker tracker;
    BOOST_CHECK(tracker.AddReport(1, GROUP_A, Addr("127.0.0.1:18446"), /*allow_local=*/true));
    BOOST_CHECK(!tracker.Get(NET_IPV4));
    BOOST_CHECK(tracker.AddReport(2, GROUP_A, Addr("127.0.0.1:18446"), /*allow_local=*/true));
    BOOST_REQUIRE(tracker.Get(NET_IPV4));
    BOOST_CHECK_EQUAL(tracker.Get(NET_IPV4)->ToStringAddrPort(), "127.0.0.1:18446");
}

BOOST_AUTO_TEST_CASE(well_formed_endpoint)
{
    BOOST_CHECK(IsWellFormedEndpoint(Addr("1.2.3.4:8333")));
    BOOST_CHECK(IsWellFormedEndpoint(Addr("[2a00:1450::1]:8333")));
    BOOST_CHECK(!IsWellFormedEndpoint(Addr("1.2.3.4:0")));
    BOOST_CHECK(!IsWellFormedEndpoint(Addr("0.0.0.0:8333")));
    BOOST_CHECK(!IsWellFormedEndpoint(Addr("[::]:8333")));
    BOOST_CHECK(!IsWellFormedEndpoint(CService{}));
}

BOOST_AUTO_TEST_CASE(pick_random_punch_port)
{
    FastRandomContext rng;
    const auto port{PickRandomPunchPort(rng)};
    BOOST_REQUIRE(port);
    BOOST_CHECK(*port >= PUNCH_PORT_MIN && *port <= PUNCH_PORT_MAX);
    BOOST_CHECK(!IsBadPort(*port));
    auto sock{CreateSock(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
    BOOST_REQUIRE(sock);
    BOOST_CHECK(BindToSharedPort(*sock, LookupNumeric("127.0.0.1", *port)));
}

BOOST_AUTO_TEST_SUITE_END()
