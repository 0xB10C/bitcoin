// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <holepunch.h>
#include <netbase.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <span>

using namespace holepunch;
using namespace util::hex_literals;

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
    ExternalAddressTracker tracker{/*allow_local=*/false};
    const CService ext{Addr("1.2.3.4:8335")};

    BOOST_CHECK(!tracker.Get(NET_IPV4));
    BOOST_CHECK(tracker.AddReport(1, GROUP_A, ext));
    // One report is never enough (R-2.2).
    BOOST_CHECK(!tracker.Get(NET_IPV4));
    // Two reports from the same group are not enough either.
    BOOST_CHECK(tracker.AddReport(2, GROUP_A, ext));
    BOOST_CHECK(!tracker.Get(NET_IPV4));
    // A second group agreeing yields the external address.
    BOOST_CHECK(tracker.AddReport(3, GROUP_B, ext));
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
    ExternalAddressTracker tracker{/*allow_local=*/false};
    const CService ext{Addr("1.2.3.4:8335")};
    BOOST_CHECK(tracker.AddReport(1, GROUP_A, ext));
    BOOST_CHECK(tracker.AddReport(2, GROUP_B, ext));
    BOOST_REQUIRE(tracker.Get(NET_IPV4));

    // One peer reporting a different port changes nothing (R-2.2).
    BOOST_CHECK(tracker.AddReport(3, GROUP_C, Addr("1.2.3.4:40001")));
    BOOST_REQUIRE(tracker.Get(NET_IPV4));
    BOOST_CHECK_EQUAL(tracker.Get(NET_IPV4)->GetPort(), 8335);
    BOOST_CHECK(!tracker.GetInfo(NET_IPV4).conflicting);

    // A second peer in another group agreeing with the dissenter makes two
    // agreeing sets that disagree: no external address (R-2.3).
    BOOST_CHECK(tracker.AddReport(4, GROUP_A, Addr("1.2.3.4:40001")));
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
    ExternalAddressTracker tracker{/*allow_local=*/false};
    BOOST_CHECK(tracker.AddReport(1, GROUP_A, Addr("1.2.3.4:8335")));
    BOOST_CHECK(tracker.AddReport(2, GROUP_B, Addr("1.2.3.4:8335")));
    BOOST_REQUIRE(tracker.Get(NET_IPV4));
    // A peer's newer report replaces its older one.
    BOOST_CHECK(tracker.AddReport(2, GROUP_B, Addr("1.2.3.4:40001")));
    BOOST_CHECK(!tracker.Get(NET_IPV4));
    BOOST_CHECK_EQUAL(tracker.GetInfo(NET_IPV4).reports, 2);
}

BOOST_AUTO_TEST_CASE(external_address_rejects_unusable_reports)
{
    ExternalAddressTracker tracker{/*allow_local=*/false};
    // Port 0, non-routable address, and non-IP networks are not reports (R-2.1).
    BOOST_CHECK(!tracker.AddReport(1, GROUP_A, Addr("1.2.3.4:0")));
    BOOST_CHECK(!tracker.AddReport(1, GROUP_A, Addr("127.0.0.1:8335")));
    BOOST_CHECK(!tracker.AddReport(1, GROUP_A, Addr("10.0.0.1:8335")));
    BOOST_CHECK(!tracker.AddReport(1, GROUP_A, CService{}));
    BOOST_CHECK_EQUAL(tracker.GetInfo(NET_IPV4).reports, 0);
    BOOST_CHECK(tracker.AddReport(1, GROUP_A, Addr("[2a00:1450::1]:8335")));
    BOOST_CHECK_EQUAL(tracker.GetInfo(NET_IPV6).reports, 1);
}

BOOST_AUTO_TEST_CASE(external_address_on_test_networks)
{
    // With allow_local, loopback addresses count and every peer is its own group (R-2.5).
    ExternalAddressTracker tracker{/*allow_local=*/true};
    BOOST_CHECK(tracker.AddReport(1, GROUP_A, Addr("127.0.0.1:18446")));
    BOOST_CHECK(!tracker.Get(NET_IPV4));
    BOOST_CHECK(tracker.AddReport(2, GROUP_A, Addr("127.0.0.1:18446")));
    BOOST_REQUIRE(tracker.Get(NET_IPV4));
    BOOST_CHECK_EQUAL(tracker.Get(NET_IPV4)->ToStringAddrPort(), "127.0.0.1:18446");
}

// Test vectors from the draft BIP (bip-tcp-holepunch/vectors.json).

template <typename Msg>
static Msg Decode(std::span<const std::byte> bytes)
{
    DataStream s{bytes};
    Msg msg;
    s >> msg;
    BOOST_REQUIRE(s.empty()); // R-4.1: no trailing bytes
    return msg;
}

template <typename Msg>
static std::vector<std::byte> Encode(const Msg& msg)
{
    DataStream s{};
    s << msg;
    return {s.begin(), s.end()};
}

BOOST_AUTO_TEST_CASE(message_vectors_valid)
{
    {
        const auto bytes{"0104cb007101208f0104c6336402c3cb"_hex};
        const auto msg{Decode<RendezvousMsg>(bytes)};
        BOOST_CHECK(msg.IsWellFormed());
        BOOST_CHECK_EQUAL(msg.target.ToStringAddrPort(), "203.0.113.1:8335");
        BOOST_CHECK_EQUAL(msg.requester.ToStringAddrPort(), "198.51.100.2:50123");
        BOOST_CHECK(std::ranges::equal(Encode(msg), bytes));
    }
    {
        const auto bytes{"021020010db8000000000000000000000001208f021020010db8000000000000000000000002479f"_hex};
        const auto msg{Decode<RendezvousMsg>(bytes)};
        BOOST_CHECK(msg.IsWellFormed());
        BOOST_CHECK_EQUAL(msg.target.ToStringAddrPort(), "[2001:db8::1]:8335");
        BOOST_CHECK_EQUAL(msg.requester.ToStringAddrPort(), "[2001:db8::2]:18335");
        BOOST_CHECK(std::ranges::equal(Encode(msg), bytes));
    }
    {
        // Port 0 is encodable; it is rejected when the message is acted on (R-5.1), not when parsed.
        const auto msg{Decode<RendezvousMsg>("0104cb007101208f0104c63364020000"_hex)};
        BOOST_CHECK(msg.IsWellFormed());
        BOOST_CHECK_EQUAL(msg.requester.GetPort(), 0);
    }
    {
        const auto bytes{"010104cb007101208f"_hex};
        const auto msg{Decode<PunchMsg>(bytes)};
        BOOST_CHECK(msg.IsWellFormed());
        BOOST_CHECK_EQUAL(msg.role, static_cast<uint8_t>(Role::INITIATOR));
        BOOST_CHECK_EQUAL(msg.peer.ToStringAddrPort(), "203.0.113.1:8335");
        BOOST_CHECK(std::ranges::equal(Encode(msg), bytes));
    }
    {
        const auto bytes{"000104c6336402c3cb"_hex};
        const auto msg{Decode<PunchMsg>(bytes)};
        BOOST_CHECK(msg.IsWellFormed());
        BOOST_CHECK_EQUAL(msg.role, static_cast<uint8_t>(Role::RESPONDER));
        BOOST_CHECK(std::ranges::equal(Encode(msg), bytes));
    }
    {
        const auto bytes{"01021020010db8000000000000000000000001208f"_hex};
        const auto msg{Decode<PunchMsg>(bytes)};
        BOOST_CHECK(msg.IsWellFormed());
        BOOST_CHECK_EQUAL(msg.peer.ToStringAddrPort(), "[2001:db8::1]:8335");
        BOOST_CHECK(std::ranges::equal(Encode(msg), bytes));
    }
}

//! A malformed message either fails to deserialize, leaves bytes behind, or is not well formed.
template <typename Msg>
static bool Rejected(std::span<const std::byte> bytes)
{
    DataStream s{bytes};
    Msg msg;
    try {
        s >> msg;
    } catch (const std::ios_base::failure&) {
        return true;
    }
    return !s.empty() || !msg.IsWellFormed();
}

BOOST_AUTO_TEST_CASE(message_vectors_invalid)
{
    // rendezvous: family mismatch (R-4.3)
    BOOST_CHECK(Rejected<RendezvousMsg>("0104cb007101208f021020010db8000000000000000000000002479f"_hex));
    // rendezvous: target with TORV3 net (R-4.2)
    BOOST_CHECK(Rejected<RendezvousMsg>("042053cd5648af46a92b5b74b7f8f6bd3bb86e5d9ab77c5f0e03a5b43a1b4bbef6ac208d0104c6336402c3cb"_hex));
    // rendezvous: IPv4 target with addr_len 5 (R-4.2)
    BOOST_CHECK(Rejected<RendezvousMsg>("0105010101010100010104c6336402c3cb"_hex));
    // rendezvous: trailing byte (R-4.1)
    BOOST_CHECK(Rejected<RendezvousMsg>("0104cb007101208f0104c6336402c3cb00"_hex));
    // rendezvous: truncated requester port (R-4.1)
    BOOST_CHECK(Rejected<RendezvousMsg>("0104cb007101208f0104c6336402c3"_hex));
    // rendezvous: non-minimal CompactSize addr_len
    BOOST_CHECK(Rejected<RendezvousMsg>("01fd0400cb007101208f0104c6336402c3cb"_hex));
    // rendezvous: IPv4-mapped IPv6 endpoint (R-1.4)
    BOOST_CHECK(Rejected<RendezvousMsg>("021000000000000000000000ffffcb007101208f0104c6336402c3cb"_hex));
    // punch: role 2 (R-4.2)
    BOOST_CHECK(Rejected<PunchMsg>("020104cb007101208f"_hex));
    // punch: peer with CJDNS net (R-4.2)
    BOOST_CHECK(Rejected<PunchMsg>("010610fc000000000000000000000000000001208f"_hex));
    // punch: unknown BIP 155 network id
    BOOST_CHECK(Rejected<PunchMsg>("010904cb007101208f"_hex));
    // punch: trailing byte (R-4.1)
    BOOST_CHECK(Rejected<PunchMsg>("010104cb007101208f00"_hex));
    // punch: empty payload (R-4.1)
    BOOST_CHECK(Rejected<PunchMsg>(""_hex));
}

BOOST_AUTO_TEST_SUITE_END()
