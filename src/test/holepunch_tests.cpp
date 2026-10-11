// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <holepunch.h>
#include <netbase.h>
#include <protocol.h>
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

// HOLEPUNCH address type (BIP 155 network id 8), with the draft's element vectors.

static CAddress DecodeElement(std::span<const std::byte> bytes)
{
    DataStream s{bytes};
    CAddress addr;
    s >> CAddress::V2_NETWORK(addr);
    BOOST_REQUIRE(s.empty());
    return addr;
}

BOOST_AUTO_TEST_CASE(holepunch_address_vectors)
{
    struct Vector {
        std::string_view hex;
        std::string_view coordinator;
        std::string_view target;
        bool valid; // in Core's sense: documentation IPv6 ranges are not valid addresses
    };
    const Vector vectors[]{
        {"a0fee868fd0908080c01c0000203208d01cb007101208f", "192.0.2.3:8333", "203.0.113.1", true},
        {"a0fee868fd090808180220010db8000000000000000000000003208d01cb007101208f", "[2001:db8::3]:8333", "203.0.113.1", false},
        {"a0fee868fd0908081801c0000203208d0220010db8000000000000000000000001208f", "192.0.2.3:8333", "2001:db8::1", false},
        {"a0fee868fd090808240220010db8000000000000000000000003479d0220010db8000000000000000000000001208f", "[2001:db8::3]:18333", "2001:db8::1", false},
        {"a0fee868fd090808280453cd5648af46a92b5b74b7f8f6bd3bb86e5d9ab77c5f0e03a5b43a1b4bbef6ac208d01cb007101208f", "kpgvmsfpi2usww3uw74pnpj3xbxf3gvxprpq4a5fwq5bws5662wbv3ad.onion:8333", "203.0.113.1", true},
        {"a0fee868fd0908082805a2894dabaec4a6e5f84ccaa9c0b5bc64bd4e4e7f8a9f5f8c3f7aa6a4dd7e5e56000001cb007101208f", "ukeu3k5oystol6cmzku4bnn4ms6u4tt7rkpv7db7pktkjxl6lzla.b32.i2p:0", "203.0.113.1", true},
        {"a0fee868fd0908080c01c0000203208d01c6336402c3cb", "192.0.2.3:8333", "198.51.100.2", true},
    };
    for (const auto& v : vectors) {
        const auto bytes{ParseHex<std::byte>(v.hex)};
        const CAddress addr{DecodeElement(bytes)};
        BOOST_CHECK(addr.IsHolePunch());
        BOOST_CHECK_EQUAL(addr.GetNetwork() == NET_HOLEPUNCH, addr.IsRoutable());
        BOOST_CHECK(!addr.IsAddrV1Compatible());
        BOOST_CHECK(addr.IsRelayable());
        BOOST_CHECK_EQUAL(addr.IsValid(), v.valid);
        BOOST_REQUIRE(addr.HolePunchCoordinator());
        BOOST_REQUIRE(addr.HolePunchTarget());
        BOOST_CHECK_EQUAL(addr.HolePunchCoordinator()->ToStringAddrPort(), v.coordinator);
        BOOST_CHECK_EQUAL(addr.HolePunchTarget()->ToStringAddr(), v.target);
        BOOST_CHECK_EQUAL(addr.nServices, ServiceFlags{2057});
        // Byte for byte identical when serialized again.
        DataStream out{};
        out << CAddress::V2_NETWORK(addr);
        BOOST_CHECK(std::ranges::equal(out, bytes));
    }
}

BOOST_AUTO_TEST_CASE(holepunch_address_invalid_vectors)
{
    // Lengths other than 12/24/36/40/52 are rejected when parsing (R-6.1).
    for (const auto hex : {"a0fee868fd0908080d01c0000203208d01cb00710100208f", "a0fee868fd0908080b01c0000203208d01cb0071208f", "a0fee868fd09080800208f"}) {
        const auto bytes{ParseHex<std::byte>(hex)};
        DataStream s{bytes};
        CAddress addr;
        BOOST_CHECK_THROW(s >> CAddress::V2_NETWORK(addr), std::ios_base::failure);
    }
    // Well-sized but inconsistent elements parse as invalid addresses.
    for (const auto hex : {
             "a0fee868fd0908081801c0000203208d01cb007101000000000000000000000000208f", // IPv4 ids in 24 bytes
             "a0fee868fd0908081806fc000000000000000000000000000001208d01cb007101208f", // CJDNS coordinator
             "a0fee868fd0908082801c0000203208d0453cd5648af46a92b5b74b7f8f6bd3bb86e5d9ab77c5f0e03a5b43a1b4bbef6ac208f", // Tor target
             "a0fee868fd0908082805a2894dabaec4a6e5f84ccaa9c0b5bc64bd4e4e7f8a9f5f8c3f7aa6a4dd7e5e56000101cb007101208f", // I2P with port
         }) {
        const CAddress addr{DecodeElement(ParseHex<std::byte>(hex))};
        BOOST_CHECK(addr.IsHolePunch());
        BOOST_CHECK(!addr.IsValid());
        BOOST_CHECK(!addr.IsRoutable());
        BOOST_CHECK(!addr.HolePunchCoordinator());
        BOOST_CHECK_EQUAL(addr.ToStringAddr(), "holepunch:invalid");
    }
}

BOOST_AUTO_TEST_CASE(holepunch_address_make)
{
    const CService coordinator{LookupNumeric("1.2.3.4", 8333)};
    const CNetAddr target{LookupNumeric("5.6.7.8", 0)};
    const auto made{CNetAddr::MakeHolePunch(coordinator, target)};
    BOOST_REQUIRE(made);
    const CService element{*made, 8335};
    BOOST_CHECK(element.IsHolePunch());
    BOOST_CHECK(element.IsValid());
    BOOST_CHECK(element.IsRoutable());
    BOOST_CHECK(element.GetNetwork() == NET_HOLEPUNCH);
    BOOST_CHECK(element.GetNetClass() == NET_HOLEPUNCH);
    BOOST_CHECK_EQUAL(element.ToStringAddrPort(), "holepunch:1.2.3.4:8333/5.6.7.8:8335");
    BOOST_CHECK_EQUAL(element.HolePunchCoordinator()->ToStringAddrPort(), "1.2.3.4:8333");
    BOOST_CHECK_EQUAL(element.HolePunchTarget()->ToStringAddr(), "5.6.7.8");
    BOOST_CHECK_EQUAL(GetNetworkName(element.GetNetwork()), "holepunch");
    // Round trip through BIP 155 serialization.
    DataStream s{};
    s << CNetAddr::V2(element);
    CService back;
    s >> CNetAddr::V2(back);
    BOOST_CHECK(back == element);
    // An IPv6 target is bracketed in the string form.
    const auto made6{CNetAddr::MakeHolePunch(coordinator, LookupNumeric("2a00:1450::1", 0))};
    BOOST_REQUIRE(made6);
    BOOST_CHECK_EQUAL(CService(*made6, 8335).ToStringAddrPort(), "holepunch:1.2.3.4:8333/[2a00:1450::1]:8335");
    // Not allowed: non-IP target, CJDNS coordinator, I2P coordinator with a port.
    BOOST_CHECK(!CNetAddr::MakeHolePunch(coordinator, *made));
    CNetAddr onion;
    BOOST_REQUIRE(onion.SetSpecial("kpgvmsfpi2usww3uw74pnpj3xbxf3gvxprpq4a5fwq5bws5662wbv3ad.onion"));
    BOOST_CHECK(CNetAddr::MakeHolePunch(CService{onion, 8333}, target));
    CNetAddr i2p;
    BOOST_REQUIRE(i2p.SetSpecial("ukeu3k5oystol6cmzku4bnn4ms6u4tt7rkpv7db7pktkjxl6lzla.b32.i2p"));
    BOOST_CHECK(CNetAddr::MakeHolePunch(CService{i2p, 0}, target));
    BOOST_CHECK(!CNetAddr::MakeHolePunch(CService{i2p, 1}, target));
}

// Announcement cache (R-6.2).

namespace {
CAddress Element(const std::string& coordinator, const std::string& target, uint16_t port, NodeSeconds time)
{
    const auto made{CNetAddr::MakeHolePunch(LookupNumeric(coordinator, 8333), LookupNumeric(target, 0))};
    BOOST_REQUIRE(made);
    return CAddress{CService{*made, port}, ServiceFlags(NODE_NETWORK | NODE_P2P_V2), time};
}
} // namespace

BOOST_AUTO_TEST_CASE(announcement_cache)
{
    AnnouncementCache cache;
    FastRandomContext rng{/*fDeterministic=*/true};
    const auto now{NodeClock::now()};
    const auto now_s{std::chrono::time_point_cast<std::chrono::seconds>(now)};

    // A fresh, routable element is added and taken apart.
    const auto added{cache.Add(1, Element("1.2.3.4", "5.6.7.8", 8335, now_s), now, /*allow_local=*/false)};
    BOOST_REQUIRE(added);
    BOOST_CHECK_EQUAL(added->coordinator.ToStringAddrPort(), "1.2.3.4:8333");
    BOOST_CHECK_EQUAL(added->target.ToStringAddrPort(), "5.6.7.8:8335");
    BOOST_CHECK_EQUAL(added->from, 1);
    BOOST_CHECK_EQUAL(cache.Size(), 1);

    // Not a HOLEPUNCH address, stale, from the future, port 0, non-routable: rejected.
    BOOST_CHECK(!cache.Add(1, CAddress{LookupNumeric("1.2.3.4", 8333), NODE_NETWORK, now_s}, now, false));
    BOOST_CHECK(!cache.Add(1, Element("1.2.3.4", "5.6.7.9", 8335, now_s - std::chrono::minutes{11}), now, false));
    BOOST_CHECK(!cache.Add(1, Element("1.2.3.4", "5.6.7.9", 8335, now_s + std::chrono::minutes{11}), now, false));
    BOOST_CHECK(!cache.Add(1, Element("1.2.3.4", "5.6.7.9", 0, now_s), now, false));
    BOOST_CHECK(!cache.Add(1, Element("1.2.3.4", "127.0.0.1", 8335, now_s), now, false));
    BOOST_CHECK(cache.Add(1, Element("1.2.3.4", "127.0.0.1", 8335, now_s), now, /*allow_local=*/true));
    BOOST_CHECK_EQUAL(cache.Size(), 2);

    // The same pair again replaces the old entry (newer time).
    BOOST_CHECK(cache.Add(1, Element("1.2.3.4", "5.6.7.8", 8335, now_s + std::chrono::seconds{1}), now, false));
    BOOST_CHECK_EQUAL(cache.Size(), 2);
    BOOST_CHECK_EQUAL(cache.Get(now).back().time.time_since_epoch().count(), (now_s + std::chrono::seconds{1}).time_since_epoch().count());

    // At most CACHE_PER_PEER from one peer.
    BOOST_CHECK(cache.Add(1, Element("1.2.3.4", "5.6.7.10", 8335, now_s), now, false));
    BOOST_CHECK(cache.Add(1, Element("1.2.3.4", "5.6.7.11", 8335, now_s), now, false));
    BOOST_CHECK(!cache.Add(1, Element("1.2.3.4", "5.6.7.12", 8335, now_s), now, false));
    BOOST_CHECK(cache.Add(2, Element("1.2.3.4", "5.6.7.12", 8335, now_s), now, false));
    BOOST_CHECK_EQUAL(cache.Size(), 5);

    // At most CACHE_MAX in total, the oldest goes first.
    for (int i = 0; i < 40; ++i) {
        cache.Add(100 + i, Element("1.2.3.4", strprintf("9.9.%d.1", i), 8335, now_s), now, false);
    }
    BOOST_CHECK_EQUAL(cache.Size(), CACHE_MAX);
    BOOST_CHECK_EQUAL(cache.Get(now).front().target.ToStringAddrPort(), "9.9.8.1:8335");

    // Taking removes a random eligible entry; nothing eligible means nothing taken.
    BOOST_CHECK(!cache.Take(now, [](const Announcement&) { return false; }, rng));
    const auto taken{cache.Take(now, [](const Announcement& a) { return a.target.ToStringAddr() == "9.9.20.1"; }, rng)};
    BOOST_REQUIRE(taken);
    BOOST_CHECK_EQUAL(taken->target.ToStringAddr(), "9.9.20.1");
    BOOST_CHECK_EQUAL(cache.Size(), CACHE_MAX - 1);

    // Entries expire CACHE_TTL after their time.
    BOOST_CHECK_EQUAL(cache.Get(now + CACHE_TTL + std::chrono::seconds{1}).size(), 0);
    BOOST_CHECK(!cache.Take(now + CACHE_TTL + std::chrono::seconds{1}, [](const Announcement&) { return true; }, rng));
    BOOST_CHECK_EQUAL(cache.Size(), 0);
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
    return Options{.enabled = true, .port = port, .allow_local = true, .coordination_bind = {}, .coordination_service = {}};
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
