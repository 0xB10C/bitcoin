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
#include <future>
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

// Session manager tests with real loopback sockets.

namespace {
//! A free TCP port on loopback: bind to port 0 and read back what the kernel chose.
uint16_t FreePort()
{
    auto sock{CreateSock(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
    BOOST_REQUIRE(sock);
    BOOST_REQUIRE(BindToSharedPort(*sock, LookupNumeric("127.0.0.1", 0)));
    return GetBindAddress(*sock).GetPort();
}

//! Collects the results of a SessionManager.
struct Results {
    struct Entry {
        CService peer;
        Role role;
        std::shared_ptr<Sock> sock;
    };
    Mutex mutex;
    std::vector<Entry> entries GUARDED_BY(mutex);

    SessionManager::ResultFn Fn()
    {
        return [this](const CService& peer, Role role, std::shared_ptr<Sock> sock) {
            LOCK(mutex);
            entries.push_back({peer, role, std::move(sock)});
        };
    }
    size_t Count() EXCLUSIVE_LOCKS_REQUIRED(!mutex) { return WITH_LOCK(mutex, return entries.size()); }
    Entry Get(size_t i) EXCLUSIVE_LOCKS_REQUIRED(!mutex) { return WITH_LOCK(mutex, return entries.at(i)); }
};

//! Poll `pred` for up to `timeout`.
template <typename Pred>
bool WaitFor(Pred pred, std::chrono::milliseconds timeout = std::chrono::seconds{10})
{
    const auto end{std::chrono::steady_clock::now() + timeout};
    while (std::chrono::steady_clock::now() < end) {
        if (pred()) return true;
        UninterruptibleSleep(std::chrono::milliseconds{10});
    }
    return pred();
}

//! Mock the clock to now, or move the mocked clock forward by `step`.
void MockClock(std::chrono::seconds step = std::chrono::seconds{0})
{
    SetMockTime(std::chrono::duration_cast<std::chrono::seconds>(NodeClock::now().time_since_epoch()) + step);
}

Options LocalOptions(uint16_t port)
{
    return Options{.enabled = true, .port = port, .allow_local = true};
}

//! Send a few bytes one way and read them on the other side.
void CheckDataFlows(Sock& from, Sock& to)
{
    const std::string msg{"punched"};
    BOOST_REQUIRE_EQUAL(from.Send(msg.data(), msg.size(), 0), static_cast<ssize_t>(msg.size()));
    BOOST_REQUIRE(to.Wait(std::chrono::seconds{5}, Sock::RecvEvent));
    char buf[16];
    BOOST_REQUIRE_EQUAL(to.Recv(buf, sizeof(buf), 0), static_cast<ssize_t>(msg.size()));
    BOOST_CHECK_EQUAL(std::string(buf, msg.size()), msg);
}
} // namespace

BOOST_AUTO_TEST_CASE(session_punch_on_loopback)
{
    const uint16_t port_a{FreePort()};
    const uint16_t port_b{FreePort()};
    const CService endpoint_a{LookupNumeric("127.0.0.1", port_a)};
    const CService endpoint_b{LookupNumeric("127.0.0.1", port_b)};
    Results results_a, results_b;
    SessionManager a{LocalOptions(port_a), results_a.Fn()};
    SessionManager b{LocalOptions(port_b), results_b.Fn()};
    BOOST_REQUIRE(a.Start());
    BOOST_REQUIRE(b.Start());

    // The responder gets its punch first (R-5.13); its connection reaches the
    // initiator's listener before the initiator has a session and is held there.
    BOOST_CHECK(!a.Punch(Role::RESPONDER, endpoint_b));
    BOOST_CHECK(a.HasSession(endpoint_b));
    BOOST_CHECK(!b.Punch(Role::INITIATOR, endpoint_a));

    BOOST_REQUIRE(WaitFor([&] { return results_a.Count() == 1 && results_b.Count() == 1; }));
    const auto result_a{results_a.Get(0)};
    const auto result_b{results_b.Get(0)};
    BOOST_REQUIRE(result_a.sock);
    BOOST_REQUIRE(result_b.sock);
    BOOST_CHECK(result_a.role == Role::RESPONDER);
    BOOST_CHECK(result_b.role == Role::INITIATOR);
    BOOST_CHECK_EQUAL(result_a.peer.ToStringAddrPort(), endpoint_b.ToStringAddrPort());
    BOOST_CHECK_EQUAL(result_b.peer.ToStringAddrPort(), endpoint_a.ToStringAddrPort());
    // Both ends of one connection, each bound to its own punch port (I-2, I-3).
    BOOST_CHECK_EQUAL(GetBindAddress(*result_a.sock).GetPort(), port_a);
    BOOST_CHECK_EQUAL(GetBindAddress(*result_b.sock).GetPort(), port_b);
    CheckDataFlows(*result_b.sock, *result_a.sock);
    CheckDataFlows(*result_a.sock, *result_b.sock);
    BOOST_CHECK(!a.HasSession(endpoint_b));
    BOOST_CHECK(!b.HasSession(endpoint_a));
    BOOST_CHECK(a.GetSessions().empty());
}

BOOST_AUTO_TEST_CASE(session_unmatched_connection_is_closed)
{
    const uint16_t port_a{FreePort()};
    Results results_a;
    SessionManager a{LocalOptions(port_a), results_a.Fn()};
    BOOST_REQUIRE(a.Start());

    // A connection from an endpoint no session expects is accepted, held, and closed (R-5.7, I-2).
    auto sock{ConnectDirectly(LookupNumeric("127.0.0.1", port_a), /*manual_connection=*/false, std::chrono::seconds{5})};
    BOOST_REQUIRE(sock);
    BOOST_REQUIRE(WaitFor([&] {
        Sock::Event occurred{0};
        return sock->Wait(std::chrono::milliseconds{0}, Sock::RecvEvent, &occurred) && occurred != 0;
    }, HOLD + std::chrono::seconds{5}));
    char buf[1];
    BOOST_CHECK_EQUAL(sock->Recv(buf, sizeof(buf), 0), 0); // EOF
    BOOST_CHECK_EQUAL(results_a.Count(), 0);
}

BOOST_AUTO_TEST_CASE(session_fails_after_window_and_grace)
{
    const uint16_t port_a{FreePort()};
    const uint16_t port_dead{FreePort()}; // nothing listens here
    Results results_a;
    SessionManager a{LocalOptions(port_a), results_a.Fn()};
    BOOST_REQUIRE(a.Start());

    MockClock();
    const CService dead{LookupNumeric("127.0.0.1", port_dead)};
    BOOST_CHECK(!a.Punch(Role::RESPONDER, dead));
    // Attempts are refused immediately and retried (R-5.5).
    BOOST_REQUIRE(WaitFor([&] { return !a.GetSessions().empty() && a.GetSessions().front().attempts >= 1; }));
    MockClock(RETRY + std::chrono::seconds{1});
    BOOST_REQUIRE(WaitFor([&] { return !a.GetSessions().empty() && a.GetSessions().front().attempts >= 2; }));
    // After the window plus the grace period the session fails (R-5.11, I-6).
    MockClock(WINDOW + GRACE);
    BOOST_REQUIRE(WaitFor([&] { return results_a.Count() == 1; }));
    BOOST_CHECK(!results_a.Get(0).sock);
    BOOST_CHECK(results_a.Get(0).role == Role::RESPONDER);
    BOOST_CHECK(!a.HasSession(dead));
    SetMockTime(std::chrono::seconds{0});
}

BOOST_AUTO_TEST_CASE(session_limits)
{
    const uint16_t port_a{FreePort()};
    Results results_a;
    SessionManager a{LocalOptions(port_a), results_a.Fn()};
    BOOST_REQUIRE(a.Start());
    MockClock();
    const auto peer{[](uint16_t port) { return LookupNumeric("127.0.0.1", port); }};

    BOOST_CHECK(!a.Punch(Role::INITIATOR, peer(40001)));
    BOOST_CHECK(a.Punch(Role::INITIATOR, peer(40001)).has_value()); // duplicate
    BOOST_CHECK(!a.Punch(Role::INITIATOR, peer(40002)));
    BOOST_CHECK(a.Punch(Role::INITIATOR, peer(40003)).has_value()); // MAX_ACTIVE_SESSIONS (I-5)

    // Let both sessions fail, then two more fit in the per-minute budget but not a fifth.
    MockClock(WINDOW + GRACE);
    BOOST_REQUIRE(WaitFor([&] { return results_a.Count() == 2; }));
    BOOST_CHECK(!a.Punch(Role::INITIATOR, peer(40003)));
    BOOST_CHECK(!a.Punch(Role::INITIATOR, peer(40004)));
    BOOST_CHECK(a.Punch(Role::INITIATOR, peer(40005)).has_value()); // SESSIONS_PER_MIN (I-5)
    MockClock(WINDOW + GRACE);
    BOOST_REQUIRE(WaitFor([&] { return results_a.Count() == 4; }));
    // A minute later the budget is back. The same endpoint again within
    // PER_ADDR_INTERVAL is refused, a new one is fine.
    MockClock(std::chrono::seconds{61});
    BOOST_CHECK(a.Punch(Role::INITIATOR, peer(40001)).has_value());
    BOOST_CHECK(!a.Punch(Role::INITIATOR, peer(40005)));
    MockClock(WINDOW + GRACE);
    BOOST_REQUIRE(WaitFor([&] { return results_a.Count() == 5; }));
    MockClock(std::chrono::duration_cast<std::chrono::seconds>(PER_ADDR_INTERVAL));
    BOOST_CHECK(!a.Punch(Role::INITIATOR, peer(40001)));
    SetMockTime(std::chrono::seconds{0});
}

BOOST_AUTO_TEST_SUITE_END()
