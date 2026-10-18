// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addrman.h>
#include <holepunch.h>
#include <netbase.h>
#include <netgroup.h>
#include <protocol.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

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

// Test vectors from the draft (vectors.json, punchkey_elements_valid).
struct PunchKeyVector {
    const char* hex;
    size_t addr_len;
    const char* addr_hex;
    uint16_t port;
};
static const PunchKeyVector PUNCHKEY_VECTORS[]{
    {"c09ff068fd0908092601cb00710102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9c3cb", 38,
     "01cb00710102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", 50123},
    {"c09ff068fd0908092601c633640202dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659208f", 38,
     "01c633640202dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", 8335},
    {"c09ff068fd090809320220010db800000000000000000000000102dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8479f", 50,
     "0220010db800000000000000000000000102dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8", 18335},
    {"c09ff068fd090809320220010db800000000000000000000000102dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659479f", 50,
     "0220010db800000000000000000000000102dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", 18335},
};

static CAddress DecodeElement(const std::string& hex)
{
    DataStream ss{ParseHex<std::byte>(hex)};
    CAddress addr;
    ss >> CAddress::V2_NETWORK(addr);
    BOOST_CHECK(ss.empty());
    return addr;
}

BOOST_AUTO_TEST_CASE(punchkey_element_vectors)
{
    for (const auto& v : PUNCHKEY_VECTORS) {
        const CAddress addr{DecodeElement(v.hex)};
        BOOST_CHECK(addr.IsPunchKey());
        BOOST_CHECK(!addr.IsValid());
        BOOST_CHECK(!addr.IsRoutable());
        BOOST_CHECK_EQUAL(addr.GetAddrBytes().size(), v.addr_len);
        BOOST_CHECK_EQUAL(HexStr(addr.GetAddrBytes()), v.addr_hex);
        BOOST_CHECK_EQUAL(addr.GetPort(), v.port);
        BOOST_CHECK_EQUAL(addr.nServices, NODE_NETWORK | NODE_WITNESS | NODE_P2P_V2);
        BOOST_CHECK_EQUAL(TicksSinceEpoch<std::chrono::seconds>(addr.nTime), 1760600000);
        // Round trip.
        DataStream out;
        out << CAddress::V2_NETWORK(addr);
        BOOST_CHECK_EQUAL(HexStr(out), v.hex);
        // The same element built from its bytes.
        BOOST_CHECK(CNetAddr::PunchKey(ParseHex<uint8_t>(v.addr_hex)) == addr);
    }
    BOOST_CHECK_EQUAL(DecodeElement(PUNCHKEY_VECTORS[0].hex).ToStringAddrPort(),
                      "[203.0.113.1/02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9]:50123");
    BOOST_CHECK_EQUAL(DecodeElement(PUNCHKEY_VECTORS[2].hex).ToStringAddrPort(),
                      "[2001:db8::1/02dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8]:18335");
}

BOOST_AUTO_TEST_CASE(punchkey_element_invalid_lengths)
{
    // Lengths 39, 37 and 0 (vectors.json, punchkey_elements_invalid): the element
    // is dropped like one with an unknown network id, and the message goes on.
    for (const char* hex : {
             "c09ff068fd0908092701cb00710102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f900c3cb",
             "c09ff068fd0908092501cb00710102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036c3cb",
             "c09ff068fd09080900c3cb",
         }) {
        const CAddress addr{DecodeElement(hex)};
        BOOST_CHECK(!addr.IsPunchKey());
        BOOST_CHECK(!addr.IsValid());

        // The same element followed by an ordinary one, as an addrv2 payload.
        DataStream ss;
        const std::vector<std::byte> element{ParseHex<std::byte>(hex)};
        ss << COMPACTSIZE(uint64_t{2});
        ss.write(element);
        CAddress ipv4{LookupNumeric("203.0.113.1", 8333), NODE_NETWORK};
        ss << CAddress::V2_NETWORK(ipv4);
        std::vector<CAddress> addrs;
        ss >> CAddress::V2_NETWORK(addrs);
        BOOST_REQUIRE_EQUAL(addrs.size(), 2);
        BOOST_CHECK(!addrs[0].IsValid());
        BOOST_CHECK(addrs[1] == ipv4);
    }
}

BOOST_AUTO_TEST_CASE(punchkey_element_never_in_addrman)
{
    AddrMan addrman{NetGroupManager::NoAsmap(), /*deterministic=*/true, /*consistency_check_ratio=*/0};
    const CAddress element{DecodeElement(PUNCHKEY_VECTORS[0].hex)};
    BOOST_CHECK(!addrman.Add({element}, LookupNumeric("203.0.113.2", 0)));
    BOOST_CHECK_EQUAL(addrman.Size(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
