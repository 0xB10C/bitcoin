// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addrman.h>
#include <holepunch.h>
#include <key.h>
#include <netbase.h>
#include <netgroup.h>
#include <protocol.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <util/string.h>

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

// Pairing vectors from the draft (vectors.json, pairing): secrets, endpoints and
// the pair value for the genesis block and block 1.
namespace {
struct Party {
    const char* secret;
    const char* pubkey;
    const char* endpoint;
};
const Party PARTY_A{"0000000000000000000000000000000000000000000000000000000000000003", "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", "203.0.113.1:50123"};
const Party PARTY_B{"b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef", "02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "198.51.100.2:8335"};
const Party PARTY_C{"c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9", "02dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8", "192.0.2.3:40000"};
const char* GENESIS{"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"};
const char* BLOCK1{"00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"};

struct PairingVector {
    const Party* a;
    const Party* b;
    const char* sorted_endpoints;
    const char* shared_x;
    const char* block;
    const char* pair;
    const Party* initiator;
};
const PairingVector PAIRING_VECTORS[]{
    {&PARTY_A, &PARTY_B, "0104c6336402208f0104cb007101c3cb", "f549c8c8f9b44c4aab3e352998dd736d1247a3dcac80f5b0360f54f7dafd2bd5", GENESIS, "3f1b2546b9e941cccb758cb5cadb6fb18587ac23b52209f113e6cb673c661513", &PARTY_A},
    {&PARTY_A, &PARTY_B, "0104c6336402208f0104cb007101c3cb", "f549c8c8f9b44c4aab3e352998dd736d1247a3dcac80f5b0360f54f7dafd2bd5", BLOCK1, "ecacc8d072e676b6c9b3ce1bd11a7ad3e76b14d0ab5202a52aeb2035a0d486f8", &PARTY_B},
    {&PARTY_A, &PARTY_C, "0104c00002039c400104cb007101c3cb", "279ed027ae68b70e053737137f620ea14b4c124d5e640636db58d163719e2cc3", GENESIS, "c39b9af0f8dbf9915a7a297f4b3268dc0204ad8b4a7f309fa4ccd4c6e5c678ba", &PARTY_C},
    {&PARTY_A, &PARTY_C, "0104c00002039c400104cb007101c3cb", "279ed027ae68b70e053737137f620ea14b4c124d5e640636db58d163719e2cc3", BLOCK1, "69273df02e226d91dcacc00c1a3094b61423fa0bd9a6a4c6eeb3f1f8414af782", &PARTY_C},
    {&PARTY_B, &PARTY_C, "0104c00002039c400104c6336402208f", "ca77ad739864d3f6f599f93842f48c89d5a9a7d0c867b767d53bf96f03557627", GENESIS, "2737f0431de9ba173d785203ccc491c24ee6a62b13ff643afa0a6474039bfa5b", &PARTY_B},
    {&PARTY_B, &PARTY_C, "0104c00002039c400104c6336402208f", "ca77ad739864d3f6f599f93842f48c89d5a9a7d0c867b767d53bf96f03557627", BLOCK1, "d8b1106f580e89cd84da722ab04a8610a8eb87cf2db9d38fcbfaa9ad15dc4727", &PARTY_B},
};

CKey KeyOf(const Party& party)
{
    CKey key;
    const auto secret{ParseHex<unsigned char>(party.secret)};
    key.Set(secret.begin(), secret.end(), true);
    BOOST_REQUIRE(key.IsValid());
    BOOST_CHECK_EQUAL(HexStr(key.GetPubKey()), party.pubkey);
    return key;
}

CPubKey PubKeyOf(const Party& party)
{
    return CPubKey{ParseHex<unsigned char>(party.pubkey)};
}

CService EndpointOf(const Party& party)
{
    return LookupNumeric(party.endpoint, 0);
}

uint256 Hash(const char* hex)
{
    return *uint256::FromHex(hex);
}

uint256 Bytes32(const char* hex)
{
    return uint256{ParseHex<unsigned char>(hex)};
}
} // namespace

BOOST_AUTO_TEST_CASE(pairing_vectors)
{
    for (const auto& v : PAIRING_VECTORS) {
        const CKey key_a{KeyOf(*v.a)};
        const CKey key_b{KeyOf(*v.b)};
        const CService ep_a{EndpointOf(*v.a)};
        const CService ep_b{EndpointOf(*v.b)};

        // The shared secret is the same from both sides (R-4.4).
        const auto x_ab{key_a.ECDHX(key_b.GetPubKey())};
        const auto x_ba{key_b.ECDHX(key_a.GetPubKey())};
        BOOST_REQUIRE(x_ab && x_ba);
        BOOST_CHECK_EQUAL(HexStr(*x_ab), v.shared_x);
        BOOST_CHECK(*x_ab == *x_ba);

        // The endpoints are sorted into the hash (R-4.5).
        std::vector<uint8_t> enc_a{EncodeEndpoint(ep_a)};
        std::vector<uint8_t> enc_b{EncodeEndpoint(ep_b)};
        if (enc_b < enc_a) std::swap(enc_a, enc_b);
        enc_a.insert(enc_a.end(), enc_b.begin(), enc_b.end());
        BOOST_CHECK_EQUAL(HexStr(enc_a), v.sorted_endpoints);

        const uint256 pair{PairValue(*x_ab, Hash(v.block), ep_a, ep_b)};
        BOOST_CHECK_EQUAL(HexStr(pair), v.pair);
        BOOST_CHECK(PairValue(*x_ba, Hash(v.block), ep_b, ep_a) == pair);

        // The role from the last bit and the key order (R-4.7).
        const Role role_a{RoleFor(pair, PubKeyOf(*v.a), PubKeyOf(*v.b))};
        const Role role_b{RoleFor(pair, PubKeyOf(*v.b), PubKeyOf(*v.a))};
        BOOST_CHECK(role_a != role_b);
        BOOST_CHECK((role_a == Role::INITIATOR) == (v.initiator == v.a));
    }
}

BOOST_AUTO_TEST_CASE(ranking_vectors)
{
    // Node A ranks B and C by pair value: B first for the genesis block, C first for block 1.
    const CKey key_a{KeyOf(PARTY_A)};
    const auto pair_for = [&](const Party& other, const char* block) {
        return PairValue(*key_a.ECDHX(PubKeyOf(other)), Hash(block), EndpointOf(PARTY_A), EndpointOf(other));
    };
    BOOST_CHECK(pair_for(PARTY_B, GENESIS) < pair_for(PARTY_C, GENESIS));
    BOOST_CHECK(pair_for(PARTY_C, BLOCK1) < pair_for(PARTY_B, BLOCK1));
    BOOST_CHECK(RoleFor(pair_for(PARTY_B, GENESIS), PubKeyOf(PARTY_A), PubKeyOf(PARTY_B)) == Role::INITIATOR);
    BOOST_CHECK(RoleFor(pair_for(PARTY_C, GENESIS), PubKeyOf(PARTY_A), PubKeyOf(PARTY_C)) == Role::RESPONDER);
    BOOST_CHECK(RoleFor(pair_for(PARTY_C, BLOCK1), PubKeyOf(PARTY_A), PubKeyOf(PARTY_C)) == Role::RESPONDER);
    BOOST_CHECK(RoleFor(pair_for(PARTY_B, BLOCK1), PubKeyOf(PARTY_A), PubKeyOf(PARTY_B)) == Role::RESPONDER);
}

BOOST_AUTO_TEST_CASE(punchkey_parse_vectors)
{
    const NodeSeconds time{std::chrono::seconds{1760600000}};
    const ServiceFlags services{ServiceFlags(NODE_NETWORK | NODE_WITNESS | NODE_P2P_V2)};
    const struct {
        const PunchKeyVector* element;
        const char* endpoint;
        const char* pubkey;
    } expected[]{
        {&PUNCHKEY_VECTORS[0], "203.0.113.1:50123", PARTY_A.pubkey},
        {&PUNCHKEY_VECTORS[1], "198.51.100.2:8335", PARTY_B.pubkey},
        {&PUNCHKEY_VECTORS[2], "[2001:db8::1]:18335", PARTY_C.pubkey},
        {&PUNCHKEY_VECTORS[3], "[2001:db8::1]:18335", PARTY_B.pubkey},
    };
    for (const auto& e : expected) {
        // The vectors use documentation address ranges, which are not routable
        // here, so they parse only with the test network waiver (R-2.5).
        BOOST_CHECK(!PunchKey::FromAddress(DecodeElement(e.element->hex), /*allow_local=*/false));
        const auto key{PunchKey::FromAddress(DecodeElement(e.element->hex), /*allow_local=*/true)};
        BOOST_REQUIRE(key);
        BOOST_CHECK_EQUAL(key->endpoint.ToStringAddrPort(), e.endpoint);
        BOOST_CHECK_EQUAL(HexStr(key->pubkey), e.pubkey);
        BOOST_CHECK_EQUAL(key->services, services);
        // Building the element again gives the same bytes.
        DataStream out;
        out << CAddress::V2_NETWORK(key->ToAddress(time));
        BOOST_CHECK_EQUAL(HexStr(out), e.element->hex);
    }

    // Rejected elements (vectors.json, punchkey_elements_invalid) with a valid length.
    for (const char* hex : {
             "c09ff068fd0908092602cb00710102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9c3cb", // net IPV6 with a 4-byte address
             "c09ff068fd0908093201cb00710102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9000000000000000000000000c3cb", // net IPV4 with a 16-byte address
             "c09ff068fd090809260453cd5648af46a92b5b74b7f8f6bd3bb86e5d9ab77c5f0e03a5b43a1b4bbef6ac0000000000c3cb", // net TORV3
             "c09ff068fd0908092601cb00710104f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9c3cb", // pubkey prefix 0x04
             "c09ff068fd0908092601cb00710102fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fc3cb", // x not below the field size
             "c09ff068fd0908092601cb007101020000000000000000000000000000000000000000000000000000000000000005c3cb", // x not on the curve
             "c09ff06801092601cb00710102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9c3cb", // services without NODE_P2P_V2
             "c09ff068fd0908092601cb00710102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f90000", // port 0
         }) {
        const CAddress element{DecodeElement(hex)};
        BOOST_CHECK(element.IsPunchKey());
        BOOST_CHECK(!PunchKey::FromAddress(element, /*allow_local=*/false));
        BOOST_CHECK(!PunchKey::FromAddress(element, /*allow_local=*/true));
    }

    // A routable endpoint parses without the waiver; an ordinary address is never an element.
    const PunchKey routable{.endpoint = LookupNumeric("8.8.8.8:50123", 0), .pubkey = PubKeyOf(PARTY_A), .services = services};
    BOOST_CHECK(PunchKey::FromAddress(routable.ToAddress(time), /*allow_local=*/false));
    BOOST_CHECK(!PunchKey::FromAddress(CAddress{LookupNumeric("8.8.8.8:50123", 0), services, time}, /*allow_local=*/true));
}

BOOST_AUTO_TEST_CASE(feature_data_vectors)
{
    const struct {
        const char* hex;
        uint8_t version;
        uint32_t flags;
    } valid[]{
        {"0000000000", 0, 0},
        {"0001000000", 0, FeatureData::FLAG_BOARD},
        {"0002000000", 0, FeatureData::FLAG_VISITOR},
        {"0000000080", 0, 0x80000000},
        {"0100000000", 1, 0},
    };
    for (const auto& v : valid) {
        DataStream ss{ParseHex<std::byte>(v.hex)};
        FeatureData data;
        ss >> data;
        BOOST_CHECK(ss.empty());
        BOOST_CHECK_EQUAL(data.version, v.version);
        BOOST_CHECK_EQUAL(data.flags, v.flags);
        DataStream out;
        out << data;
        BOOST_CHECK_EQUAL(HexStr(out), v.hex);
    }
    // Truncated flags fail to parse; a trailing byte is left in the stream.
    DataStream truncated{ParseHex<std::byte>("0000")};
    FeatureData data;
    BOOST_CHECK_THROW(truncated >> data, std::ios_base::failure);
    DataStream trailing{ParseHex<std::byte>("000000000000")};
    trailing >> data;
    BOOST_CHECK(!trailing.empty());
    BOOST_CHECK_EQUAL(util::Join(FeatureFlagNames(FeatureData::FLAG_BOARD | FeatureData::FLAG_VISITOR), ","), "BOARD,VISITOR");
}

namespace {
const std::vector<unsigned char> BOARD_1{0x11};
const std::vector<unsigned char> BOARD_2{0x22};
const ServiceFlags ENTRY_SERVICES{ServiceFlags(NODE_NETWORK | NODE_P2P_V2)};

PunchKey MakeKey(const std::string& endpoint)
{
    CKey key;
    key.MakeNewKey(true);
    return PunchKey{.endpoint = LookupNumeric(endpoint, 0), .pubkey = key.GetPubKey(), .services = ENTRY_SERVICES};
}

std::string EndpointN(size_t n)
{
    return strprintf("203.0.%d.%d:%d", (n / 250) + 1, (n % 250) + 1, 10000 + n);
}
} // namespace

BOOST_AUTO_TEST_CASE(table_refresh_and_replace)
{
    using namespace std::chrono_literals;
    Table table;
    const NodeClock::time_point t0{NodeClock::now()};
    const uint256 secret{Bytes32(PAIRING_VECTORS[0].shared_x)};

    const PunchKey key{MakeKey("203.0.113.1:50123")};
    BOOST_CHECK(table.Add(BOARD_1, key, secret, t0, /*allow_local=*/false));
    BOOST_CHECK_EQUAL(table.Size(), 1);

    // A refresh keeps received_at (R-6.1): the entry stays eligible for a parent reached after t0.
    BOOST_CHECK(!table.Add(BOARD_1, key, secret, t0 + 10min, false));
    BOOST_CHECK_EQUAL(table.Size(), 1);
    BOOST_REQUIRE_EQUAL(table.Eligible(t0 + 11min, t0 + 1min).size(), 1);
    BOOST_CHECK(table.Eligible(t0 + 11min, t0 + 1min)[0].received_at == t0);
    BOOST_CHECK(table.Eligible(t0 + 11min, t0 + 1min)[0].last_seen == t0 + 10min);
    // Not eligible for a parent reached before it was received (R-7.2).
    BOOST_CHECK_EQUAL(table.Eligible(t0 + 11min, t0).size(), 0);

    // The same board serving another key for the same address replaces the entry (R-6.1).
    PunchKey new_key{MakeKey("203.0.113.1:50124")};
    BOOST_CHECK(table.Add(BOARD_1, new_key, secret, t0 + 20min, false));
    BOOST_CHECK_EQUAL(table.Size(), 1);
    BOOST_CHECK(table.Eligible(t0 + 21min, t0 + 30min)[0].key.pubkey == new_key.pubkey);
    BOOST_CHECK(table.Eligible(t0 + 21min, t0 + 30min)[0].received_at == t0 + 20min);

    // Another board serving the same address does not displace it; the stored key
    // under another address is a distinct entry.
    const PunchKey other_board{MakeKey("203.0.113.1:50125")};
    BOOST_CHECK(table.Add(BOARD_2, other_board, secret, t0 + 20min, false));
    PunchKey moved{new_key};
    moved.endpoint = LookupNumeric("203.0.113.9:50124", 0);
    BOOST_CHECK(table.Add(BOARD_1, moved, secret, t0 + 20min, false));
    BOOST_CHECK_EQUAL(table.Size(), 3);
    BOOST_CHECK_EQUAL(table.SizeBySource().at(BOARD_1), 2);
    BOOST_CHECK_EQUAL(table.SizeBySource().at(BOARD_2), 1);

    // With allow_local, addresses are compared with their port: a different port is another host.
    Table local;
    BOOST_CHECK(local.Add(BOARD_1, MakeKey("127.0.0.1:18444"), secret, t0, true));
    BOOST_CHECK(local.Add(BOARD_1, MakeKey("127.0.0.1:18445"), secret, t0, true));
    BOOST_CHECK_EQUAL(local.Size(), 2);
    BOOST_CHECK(local.Add(BOARD_1, MakeKey("127.0.0.1:18445"), secret, t0, true));
    BOOST_CHECK_EQUAL(local.Size(), 2);

    // A pick removes the entry (R-6.5); expiry drops the rest (R-6.4).
    table.Remove(moved.endpoint, moved.pubkey);
    BOOST_CHECK_EQUAL(table.Size(), 2);
    BOOST_CHECK_EQUAL(table.Eligible(t0 + 20min + ENTRY_TTL, t0 + 2h).size(), 0);
    table.Expire(t0 + 20min + ENTRY_TTL);
    BOOST_CHECK_EQUAL(table.Size(), 0);
}

BOOST_AUTO_TEST_CASE(table_caps)
{
    using namespace std::chrono_literals;
    Table table;
    const NodeClock::time_point t0{NodeClock::now()};
    const uint256 secret{Bytes32(PAIRING_VECTORS[0].shared_x)};

    // One board cannot plant more than SOURCE_CAP entries (R-6.2), and another
    // board's entries are untouched by it.
    const PunchKey from_other{MakeKey("198.51.100.1:8333")};
    BOOST_CHECK(table.Add(BOARD_2, from_other, secret, t0, false));
    for (size_t i = 0; i < SOURCE_CAP + 10; ++i) {
        BOOST_CHECK(table.Add(BOARD_1, MakeKey(EndpointN(i)), secret, t0 + std::chrono::seconds{i}, false));
    }
    BOOST_CHECK_EQUAL(table.SizeBySource().at(BOARD_1), SOURCE_CAP);
    BOOST_CHECK_EQUAL(table.SizeBySource().at(BOARD_2), 1);
    BOOST_CHECK_EQUAL(table.Size(), SOURCE_CAP + 1);

    // The table never exceeds TABLE_MAX (R-6.3): a full table evicts from its largest group.
    Table big;
    for (size_t group = 0; group < 20; ++group) {
        const std::vector<unsigned char> source{static_cast<unsigned char>(group)};
        for (size_t i = 0; i < SOURCE_CAP; ++i) {
            big.Add(source, MakeKey(EndpointN(group * SOURCE_CAP + i)), secret, t0, false);
        }
    }
    BOOST_CHECK_EQUAL(big.Size(), TABLE_MAX);
    for (const auto& [source, size] : big.SizeBySource()) {
        BOOST_CHECK(size <= SOURCE_CAP);
    }
}

BOOST_AUTO_TEST_CASE(board_entries)
{
    using namespace std::chrono_literals;
    Board board;
    const NodeClock::time_point t0{NodeClock::now()};
    const PunchKey v1{MakeKey("203.0.113.1:50001")};
    const PunchKey v2{MakeKey("203.0.113.2:50002")};

    // One entry per connection; a later element replaces it (R-5.6).
    BOOST_CHECK(board.Store(/*visitor=*/1, v1, t0, false));
    PunchKey v1_new{MakeKey("203.0.113.1:50001")};
    BOOST_CHECK(board.Store(1, v1_new, t0 + 1min, false));
    BOOST_REQUIRE_EQUAL(board.LiveEntries().size(), 1);
    BOOST_CHECK(board.LiveEntries()[0].key.pubkey == v1_new.pubkey);
    BOOST_CHECK(board.LiveEntries()[0].time == std::chrono::time_point_cast<std::chrono::seconds>(t0 + 1min));

    // An entry with an open connection is never displaced by another connection (R-5.7).
    BOOST_CHECK(!board.Store(/*visitor=*/3, MakeKey("203.0.113.1:50009"), t0, false));
    BOOST_CHECK(board.Store(2, v2, t0, false));
    BOOST_CHECK_EQUAL(board.LiveEntries().size(), 2);

    // A closed connection's entry is kept for BOARD_GRACE but not served; an element
    // from the same address replaces it meanwhile.
    board.Disconnected(1, t0 + 2min);
    BOOST_CHECK_EQUAL(board.LiveEntries().size(), 1);
    BOOST_CHECK_EQUAL(board.Size(), 2);
    board.Expire(t0 + 2min + BOARD_GRACE - 1s);
    BOOST_CHECK_EQUAL(board.Size(), 2);
    BOOST_CHECK(board.Store(4, MakeKey("203.0.113.1:50010"), t0 + 3min, false));
    BOOST_CHECK_EQUAL(board.Size(), 2);
    BOOST_CHECK_EQUAL(board.LiveEntries().size(), 2);
    board.Disconnected(4, t0 + 4min);
    board.Expire(t0 + 4min + BOARD_GRACE);
    BOOST_CHECK_EQUAL(board.Size(), 1);

    // On test networks addresses are compared with their port (R-2.5).
    Board local;
    BOOST_CHECK(local.Store(1, MakeKey("127.0.0.1:18444"), t0, true));
    BOOST_CHECK(local.Store(2, MakeKey("127.0.0.1:18445"), t0, true));
    BOOST_CHECK(!local.Store(3, MakeKey("127.0.0.1:18445"), t0, true));
    BOOST_CHECK_EQUAL(local.LiveEntries().size(), 2);
}

BOOST_AUTO_TEST_SUITE_END()
