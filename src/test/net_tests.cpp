// Copyright (c) 2012-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <clientversion.h>
#include <compat/compat.h>
#include <crypto/bip324_suite.h>
#include <cstdint>
#include <key.h>
#include <key_io.h>
#include <net.h>
#include <net_processing.h>
#include <netaddress.h>
#include <netbase.h>
#include <netmessagemaker.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <timedata.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/system.h>
#include <validation.h>
#include <version.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <ios>
#include <memory>
#include <optional>
#include <string>

using namespace std::literals;

BOOST_FIXTURE_TEST_SUITE(net_tests, RegTestingSetup)

BOOST_AUTO_TEST_CASE(cnode_listen_port)
{
    // test default
    uint16_t port{GetListenPort()};
    BOOST_CHECK(port == Params().GetDefaultPort());
    // test set port
    uint16_t altPort = 12345;
    BOOST_CHECK(gArgs.SoftSetArg("-port", ToString(altPort)));
    port = GetListenPort();
    BOOST_CHECK(port == altPort);
}

BOOST_AUTO_TEST_CASE(cnode_simple_test)
{
    NodeId id = 0;

    in_addr ipv4Addr;
    ipv4Addr.s_addr = 0xa0b0c001;

    CAddress addr = CAddress(CService(ipv4Addr, 7777), NODE_NETWORK);
    std::string pszDest;

    std::unique_ptr<CNode> pnode1 = std::make_unique<CNode>(id++,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/0,
                                                            /*nLocalHostNonceIn=*/0,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::OUTBOUND_FULL_RELAY,
                                                            /*inbound_onion=*/false);
    BOOST_CHECK(pnode1->IsFullOutboundConn() == true);
    BOOST_CHECK(pnode1->IsManualConn() == false);
    BOOST_CHECK(pnode1->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode1->IsFeelerConn() == false);
    BOOST_CHECK(pnode1->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode1->IsInboundConn() == false);
    BOOST_CHECK(pnode1->m_inbound_onion == false);
    BOOST_CHECK_EQUAL(pnode1->ConnectedThroughNetwork(), Network::NET_IPV4);

    std::unique_ptr<CNode> pnode2 = std::make_unique<CNode>(id++,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/1,
                                                            /*nLocalHostNonceIn=*/1,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::INBOUND,
                                                            /*inbound_onion=*/false);
    BOOST_CHECK(pnode2->IsFullOutboundConn() == false);
    BOOST_CHECK(pnode2->IsManualConn() == false);
    BOOST_CHECK(pnode2->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode2->IsFeelerConn() == false);
    BOOST_CHECK(pnode2->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode2->IsInboundConn() == true);
    BOOST_CHECK(pnode2->m_inbound_onion == false);
    BOOST_CHECK_EQUAL(pnode2->ConnectedThroughNetwork(), Network::NET_IPV4);

    std::unique_ptr<CNode> pnode3 = std::make_unique<CNode>(id++,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/0,
                                                            /*nLocalHostNonceIn=*/0,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::OUTBOUND_FULL_RELAY,
                                                            /*inbound_onion=*/false);
    BOOST_CHECK(pnode3->IsFullOutboundConn() == true);
    BOOST_CHECK(pnode3->IsManualConn() == false);
    BOOST_CHECK(pnode3->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode3->IsFeelerConn() == false);
    BOOST_CHECK(pnode3->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode3->IsInboundConn() == false);
    BOOST_CHECK(pnode3->m_inbound_onion == false);
    BOOST_CHECK_EQUAL(pnode3->ConnectedThroughNetwork(), Network::NET_IPV4);

    std::unique_ptr<CNode> pnode4 = std::make_unique<CNode>(id++,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/1,
                                                            /*nLocalHostNonceIn=*/1,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::INBOUND,
                                                            /*inbound_onion=*/true);
    BOOST_CHECK(pnode4->IsFullOutboundConn() == false);
    BOOST_CHECK(pnode4->IsManualConn() == false);
    BOOST_CHECK(pnode4->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode4->IsFeelerConn() == false);
    BOOST_CHECK(pnode4->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode4->IsInboundConn() == true);
    BOOST_CHECK(pnode4->m_inbound_onion == true);
    BOOST_CHECK_EQUAL(pnode4->ConnectedThroughNetwork(), Network::NET_ONION);
}

BOOST_AUTO_TEST_CASE(cnetaddr_basic)
{
    CNetAddr addr;

    // IPv4, INADDR_ANY
    BOOST_REQUIRE(LookupHost("0.0.0.0", addr, false));
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv4());

    BOOST_CHECK(addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "0.0.0.0");

    // IPv4, INADDR_NONE
    BOOST_REQUIRE(LookupHost("255.255.255.255", addr, false));
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv4());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "255.255.255.255");

    // IPv4, casual
    BOOST_REQUIRE(LookupHost("12.34.56.78", addr, false));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv4());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "12.34.56.78");

    // IPv6, in6addr_any
    BOOST_REQUIRE(LookupHost("::", addr, false));
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());

    BOOST_CHECK(addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "::");

    // IPv6, casual
    BOOST_REQUIRE(LookupHost("1122:3344:5566:7788:9900:aabb:ccdd:eeff", addr, false));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "1122:3344:5566:7788:9900:aabb:ccdd:eeff");

    // IPv6, scoped/link-local. See https://tools.ietf.org/html/rfc4007
    // We support non-negative decimal integers (uint32_t) as zone id indices.
    // Normal link-local scoped address functionality is to append "%" plus the
    // zone id, for example, given a link-local address of "fe80::1" and a zone
    // id of "32", return the address as "fe80::1%32".
    const std::string link_local{"fe80::1"};
    const std::string scoped_addr{link_local + "%32"};
    BOOST_REQUIRE(LookupHost(scoped_addr, addr, false));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK_EQUAL(addr.ToString(), scoped_addr);

    // Test that the delimiter "%" and default zone id of 0 can be omitted for the default scope.
    BOOST_REQUIRE(LookupHost(link_local + "%0", addr, false));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK_EQUAL(addr.ToString(), link_local);

    // TORv2, no longer supported
    BOOST_CHECK(!addr.SetSpecial("6hzph5hv6337r6p2.onion"));

    // TORv3
    const char* torv3_addr = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
    BOOST_REQUIRE(addr.SetSpecial(torv3_addr));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsTor());

    BOOST_CHECK(!addr.IsI2P());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), torv3_addr);

    // TORv3, broken, with wrong checksum
    BOOST_CHECK(!addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscsad.onion"));

    // TORv3, broken, with wrong version
    BOOST_CHECK(!addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscrye.onion"));

    // TORv3, malicious
    BOOST_CHECK(!addr.SetSpecial(std::string{
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd\0wtf.onion", 66}));

    // TOR, bogus length
    BOOST_CHECK(!addr.SetSpecial(std::string{"mfrggzak.onion"}));

    // TOR, invalid base32
    BOOST_CHECK(!addr.SetSpecial(std::string{"mf*g zak.onion"}));

    // I2P
    const char* i2p_addr = "UDHDrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.I2P";
    BOOST_REQUIRE(addr.SetSpecial(i2p_addr));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsI2P());

    BOOST_CHECK(!addr.IsTor());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), ToLower(i2p_addr));

    // I2P, correct length, but decodes to less than the expected number of bytes.
    BOOST_CHECK(!addr.SetSpecial("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jn=.b32.i2p"));

    // I2P, extra unnecessary padding
    BOOST_CHECK(!addr.SetSpecial("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna=.b32.i2p"));

    // I2P, malicious
    BOOST_CHECK(!addr.SetSpecial("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v\0wtf.b32.i2p"s));

    // I2P, valid but unsupported (56 Base32 characters)
    // See "Encrypted LS with Base 32 Addresses" in
    // https://geti2p.net/spec/encryptedleaseset.txt
    BOOST_CHECK(
        !addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscsad.b32.i2p"));

    // I2P, invalid base32
    BOOST_CHECK(!addr.SetSpecial(std::string{"tp*szydbh4dp.b32.i2p"}));

    // Internal
    addr.SetInternal("esffpp");
    BOOST_REQUIRE(!addr.IsValid()); // "internal" is considered invalid
    BOOST_REQUIRE(addr.IsInternal());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "esffpvrt3wpeaygy.internal");

    // Totally bogus
    BOOST_CHECK(!addr.SetSpecial("totally bogus"));
}

BOOST_AUTO_TEST_CASE(cnetaddr_tostring_canonical_ipv6)
{
    // Test that CNetAddr::ToString formats IPv6 addresses with zero compression as described in
    // RFC 5952 ("A Recommendation for IPv6 Address Text Representation").
    const std::map<std::string, std::string> canonical_representations_ipv6{
        {"0000:0000:0000:0000:0000:0000:0000:0000", "::"},
        {"000:0000:000:00:0:00:000:0000", "::"},
        {"000:000:000:000:000:000:000:000", "::"},
        {"00:00:00:00:00:00:00:00", "::"},
        {"0:0:0:0:0:0:0:0", "::"},
        {"0:0:0:0:0:0:0:1", "::1"},
        {"2001:0:0:1:0:0:0:1", "2001:0:0:1::1"},
        {"2001:0db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:db8:85a3::8a2e:370:7334"},
        {"2001:0db8::0001", "2001:db8::1"},
        {"2001:0db8::0001:0000", "2001:db8::1:0"},
        {"2001:0db8::1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:db8:0000:0:1::1", "2001:db8::1:0:0:1"},
        {"2001:db8:0000:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"},
        {"2001:db8:0:0:0:0:2:1", "2001:db8::2:1"},
        {"2001:db8:0:0:0::1", "2001:db8::1"},
        {"2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:db8:0:0:1::1", "2001:db8::1:0:0:1"},
        {"2001:DB8:0:0:1::1", "2001:db8::1:0:0:1"},
        {"2001:db8:0:0::1", "2001:db8::1"},
        {"2001:db8:0:0:aaaa::1", "2001:db8::aaaa:0:0:1"},
        {"2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"},
        {"2001:db8:0::1", "2001:db8::1"},
        {"2001:db8:85a3:0:0:8a2e:370:7334", "2001:db8:85a3::8a2e:370:7334"},
        {"2001:db8::0:1", "2001:db8::1"},
        {"2001:db8::0:1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:DB8::1", "2001:db8::1"},
        {"2001:db8::1", "2001:db8::1"},
        {"2001:db8::1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:db8::1:1:1:1:1", "2001:db8:0:1:1:1:1:1"},
        {"2001:db8::aaaa:0:0:1", "2001:db8::aaaa:0:0:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:0:1", "2001:db8:aaaa:bbbb:cccc:dddd:0:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd::1", "2001:db8:aaaa:bbbb:cccc:dddd:0:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:0001", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:001", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:01", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:1", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:AAAA", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:AaAa", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa"},
    };
    for (const auto& [input_address, expected_canonical_representation_output] : canonical_representations_ipv6) {
        CNetAddr net_addr;
        BOOST_REQUIRE(LookupHost(input_address, net_addr, false));
        BOOST_REQUIRE(net_addr.IsIPv6());
        BOOST_CHECK_EQUAL(net_addr.ToString(), expected_canonical_representation_output);
    }
}

BOOST_AUTO_TEST_CASE(cnetaddr_serialize_v1)
{
    CNetAddr addr;
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);

    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000000000000000");
    s.clear();

    BOOST_REQUIRE(LookupHost("1.2.3.4", addr, false));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000ffff01020304");
    s.clear();

    BOOST_REQUIRE(LookupHost("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b", addr, false));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "1a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b");
    s.clear();

    // TORv2, no longer supported
    BOOST_CHECK(!addr.SetSpecial("6hzph5hv6337r6p2.onion"));

    BOOST_REQUIRE(addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000000000000000");
    s.clear();

    addr.SetInternal("a");
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "fd6b88c08724ca978112ca1bbdcafac2");
    s.clear();
}

BOOST_AUTO_TEST_CASE(cnetaddr_serialize_v2)
{
    CNetAddr addr;
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    // Add ADDRV2_FORMAT to the version so that the CNetAddr
    // serialize method produces an address in v2 format.
    s.SetVersion(s.GetVersion() | ADDRV2_FORMAT);

    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "021000000000000000000000000000000000");
    s.clear();

    BOOST_REQUIRE(LookupHost("1.2.3.4", addr, false));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "010401020304");
    s.clear();

    BOOST_REQUIRE(LookupHost("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b", addr, false));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "02101a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b");
    s.clear();

    // TORv2, no longer supported
    BOOST_CHECK(!addr.SetSpecial("6hzph5hv6337r6p2.onion"));

    BOOST_REQUIRE(addr.SetSpecial("kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaid.onion"));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "042053cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88");
    s.clear();

    BOOST_REQUIRE(addr.SetInternal("a"));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "0210fd6b88c08724ca978112ca1bbdcafac2");
    s.clear();
}

BOOST_AUTO_TEST_CASE(cnetaddr_unserialize_v2)
{
    CNetAddr addr;
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    // Add ADDRV2_FORMAT to the version so that the CNetAddr
    // unserialize method expects an address in v2 format.
    s.SetVersion(s.GetVersion() | ADDRV2_FORMAT);

    // Valid IPv4.
    s << Span{ParseHex("01"          // network type (IPv4)
                       "04"          // address length
                       "01020304")}; // address
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsIPv4());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "1.2.3.4");
    BOOST_REQUIRE(s.empty());

    // Invalid IPv4, valid length but address itself is shorter.
    s << Span{ParseHex("01"      // network type (IPv4)
                       "04"      // address length
                       "0102")}; // address
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure, HasReason("end of data"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv4, with bogus length.
    s << Span{ParseHex("01"          // network type (IPv4)
                       "05"          // address length
                       "01020304")}; // address
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 IPv4 address with length 5 (should be 4)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv4, with extreme length.
    s << Span{ParseHex("01"          // network type (IPv4)
                       "fd0102"      // address length (513 as CompactSize)
                       "01020304")}; // address
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("Address too long: 513 > 512"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid IPv6.
    s << Span{ParseHex("02"                                  // network type (IPv6)
                       "10"                                  // address length
                       "0102030405060708090a0b0c0d0e0f10")}; // address
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsIPv6());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "102:304:506:708:90a:b0c:d0e:f10");
    BOOST_REQUIRE(s.empty());

    // Valid IPv6, contains embedded "internal".
    s << Span{ParseHex(
        "02"                                  // network type (IPv6)
        "10"                                  // address length
        "fd6b88c08724ca978112ca1bbdcafac2")}; // address: 0xfd + sha256("bitcoin")[0:5] +
                                              // sha256(name)[0:10]
    s >> addr;
    BOOST_CHECK(addr.IsInternal());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "zklycewkdo64v6wc.internal");
    BOOST_REQUIRE(s.empty());

    // Invalid IPv6, with bogus length.
    s << Span{ParseHex("02"    // network type (IPv6)
                       "04"    // address length
                       "00")}; // address
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 IPv6 address with length 4 (should be 16)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv6, contains embedded IPv4.
    s << Span{ParseHex("02"                                  // network type (IPv6)
                       "10"                                  // address length
                       "00000000000000000000ffff01020304")}; // address
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Invalid IPv6, contains embedded TORv2.
    s << Span{ParseHex("02"                                  // network type (IPv6)
                       "10"                                  // address length
                       "fd87d87eeb430102030405060708090a")}; // address
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // TORv2, no longer supported.
    s << Span{ParseHex("03"                      // network type (TORv2)
                       "0a"                      // address length
                       "f1f2f3f4f5f6f7f8f9fa")}; // address
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Valid TORv3.
    s << Span{ParseHex("04"                               // network type (TORv3)
                       "20"                               // address length
                       "79bcc625184b05194975c28b66b66b04" // address
                       "69f7f6556fb1ac3189a79b40dda32f1f"
                       )};
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsTor());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(),
                      "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion");
    BOOST_REQUIRE(s.empty());

    // Invalid TORv3, with bogus length.
    s << Span{ParseHex("04" // network type (TORv3)
                       "00" // address length
                       "00" // address
                       )};
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 TORv3 address with length 0 (should be 32)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid I2P.
    s << Span{ParseHex("05"                               // network type (I2P)
                       "20"                               // address length
                       "a2894dabaec08c0051a481a6dac88b64" // address
                       "f98232ae42d4b6fd2fa81952dfe36a87")};
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsI2P());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(),
                      "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p");
    BOOST_REQUIRE(s.empty());

    // Invalid I2P, with bogus length.
    s << Span{ParseHex("05" // network type (I2P)
                       "03" // address length
                       "00" // address
                       )};
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 I2P address with length 3 (should be 32)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid CJDNS.
    s << Span{ParseHex("06"                               // network type (CJDNS)
                       "10"                               // address length
                       "fc000001000200030004000500060007" // address
                       )};
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsCJDNS());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "fc00:1:2:3:4:5:6:7");
    BOOST_REQUIRE(s.empty());

    // Invalid CJDNS, wrong prefix.
    s << Span{ParseHex("06"                               // network type (CJDNS)
                       "10"                               // address length
                       "aa000001000200030004000500060007" // address
                       )};
    s >> addr;
    BOOST_CHECK(addr.IsCJDNS());
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Invalid CJDNS, with bogus length.
    s << Span{ParseHex("06" // network type (CJDNS)
                       "01" // address length
                       "00" // address
                       )};
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 CJDNS address with length 1 (should be 16)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Unknown, with extreme length.
    s << Span{ParseHex("aa"             // network type (unknown)
                       "fe00000002"     // address length (CompactSize's MAX_SIZE)
                       "01020304050607" // address
                       )};
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("Address too long: 33554432 > 512"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Unknown, with reasonable length.
    s << Span{ParseHex("aa"       // network type (unknown)
                       "04"       // address length
                       "01020304" // address
                       )};
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Unknown, with zero length.
    s << Span{ParseHex("aa" // network type (unknown)
                       "00" // address length
                       ""   // address
                       )};
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());
}

// prior to PR #14728, this test triggers an undefined behavior
BOOST_AUTO_TEST_CASE(ipv4_peer_with_ipv6_addrMe_test)
{
    // set up local addresses; all that's necessary to reproduce the bug is
    // that a normal IPv4 address is among the entries, but if this address is
    // !IsRoutable the undefined behavior is easier to trigger deterministically
    in_addr raw_addr;
    raw_addr.s_addr = htonl(0x7f000001);
    const CNetAddr mapLocalHost_entry = CNetAddr(raw_addr);
    {
        LOCK(g_maplocalhost_mutex);
        LocalServiceInfo lsi;
        lsi.nScore = 23;
        lsi.nPort = 42;
        mapLocalHost[mapLocalHost_entry] = lsi;
    }

    // create a peer with an IPv4 address
    in_addr ipv4AddrPeer;
    ipv4AddrPeer.s_addr = 0xa0b0c001;
    CAddress addr = CAddress(CService(ipv4AddrPeer, 7777), NODE_NETWORK);
    std::unique_ptr<CNode> pnode = std::make_unique<CNode>(/*id=*/0,
                                                           /*sock=*/nullptr,
                                                           addr,
                                                           /*nKeyedNetGroupIn=*/0,
                                                           /*nLocalHostNonceIn=*/0,
                                                           CAddress{},
                                                           /*pszDest=*/std::string{},
                                                           ConnectionType::OUTBOUND_FULL_RELAY,
                                                           /*inbound_onion=*/false);
    pnode->fSuccessfullyConnected.store(true);

    // the peer claims to be reaching us via IPv6
    in6_addr ipv6AddrLocal;
    memset(ipv6AddrLocal.s6_addr, 0, 16);
    ipv6AddrLocal.s6_addr[0] = 0xcc;
    CAddress addrLocal = CAddress(CService(ipv6AddrLocal, 7777), NODE_NETWORK);
    pnode->SetAddrLocal(addrLocal);

    // before patch, this causes undefined behavior detectable with clang's -fsanitize=memory
    GetLocalAddrForPeer(*pnode);

    // suppress no-checks-run warning; if this test fails, it's by triggering a sanitizer
    BOOST_CHECK(1);

    // Cleanup, so that we don't confuse other tests.
    {
        LOCK(g_maplocalhost_mutex);
        mapLocalHost.erase(mapLocalHost_entry);
    }
}

BOOST_AUTO_TEST_CASE(get_local_addr_for_peer_port)
{
    // Test that GetLocalAddrForPeer() properly selects the address to self-advertise:
    //
    // 1. GetLocalAddrForPeer() calls GetLocalAddress() which returns an address that is
    //    not routable.
    // 2. GetLocalAddrForPeer() overrides the address with whatever the peer has told us
    //    he sees us as.
    // 2.1. For inbound connections we must override both the address and the port.
    // 2.2. For outbound connections we must override only the address.

    // Pretend that we bound to this port.
    const uint16_t bind_port = 20001;
    m_node.args->ForceSetArg("-bind", strprintf("3.4.5.6:%u", bind_port));

    // Our address:port as seen from the peer, completely different from the above.
    in_addr peer_us_addr;
    peer_us_addr.s_addr = htonl(0x02030405);
    const CService peer_us{peer_us_addr, 20002};

    // Create a peer with a routable IPv4 address (outbound).
    in_addr peer_out_in_addr;
    peer_out_in_addr.s_addr = htonl(0x01020304);
    CNode peer_out{/*id=*/0,
                   /*sock=*/nullptr,
                   /*addrIn=*/CAddress{CService{peer_out_in_addr, 8333}, NODE_NETWORK},
                   /*nKeyedNetGroupIn=*/0,
                   /*nLocalHostNonceIn=*/0,
                   /*addrBindIn=*/CAddress{},
                   /*addrNameIn=*/std::string{},
                   /*conn_type_in=*/ConnectionType::OUTBOUND_FULL_RELAY,
                   /*inbound_onion=*/false};
    peer_out.fSuccessfullyConnected = true;
    peer_out.SetAddrLocal(peer_us);

    // Without the fix peer_us:8333 is chosen instead of the proper peer_us:bind_port.
    auto chosen_local_addr = GetLocalAddrForPeer(peer_out);
    BOOST_REQUIRE(chosen_local_addr);
    const CService expected{peer_us_addr, bind_port};
    BOOST_CHECK(*chosen_local_addr == expected);

    // Create a peer with a routable IPv4 address (inbound).
    in_addr peer_in_in_addr;
    peer_in_in_addr.s_addr = htonl(0x05060708);
    CNode peer_in{/*id=*/0,
                  /*sock=*/nullptr,
                  /*addrIn=*/CAddress{CService{peer_in_in_addr, 8333}, NODE_NETWORK},
                  /*nKeyedNetGroupIn=*/0,
                  /*nLocalHostNonceIn=*/0,
                  /*addrBindIn=*/CAddress{},
                  /*addrNameIn=*/std::string{},
                  /*conn_type_in=*/ConnectionType::INBOUND,
                  /*inbound_onion=*/false};
    peer_in.fSuccessfullyConnected = true;
    peer_in.SetAddrLocal(peer_us);

    // Without the fix peer_us:8333 is chosen instead of the proper peer_us:peer_us.GetPort().
    chosen_local_addr = GetLocalAddrForPeer(peer_in);
    BOOST_REQUIRE(chosen_local_addr);
    BOOST_CHECK(*chosen_local_addr == peer_us);

    m_node.args->ForceSetArg("-bind", "");
}

BOOST_AUTO_TEST_CASE(LimitedAndReachable_Network)
{
    BOOST_CHECK(IsReachable(NET_IPV4));
    BOOST_CHECK(IsReachable(NET_IPV6));
    BOOST_CHECK(IsReachable(NET_ONION));
    BOOST_CHECK(IsReachable(NET_I2P));
    BOOST_CHECK(IsReachable(NET_CJDNS));

    SetReachable(NET_IPV4, false);
    SetReachable(NET_IPV6, false);
    SetReachable(NET_ONION, false);
    SetReachable(NET_I2P, false);
    SetReachable(NET_CJDNS, false);

    BOOST_CHECK(!IsReachable(NET_IPV4));
    BOOST_CHECK(!IsReachable(NET_IPV6));
    BOOST_CHECK(!IsReachable(NET_ONION));
    BOOST_CHECK(!IsReachable(NET_I2P));
    BOOST_CHECK(!IsReachable(NET_CJDNS));

    SetReachable(NET_IPV4, true);
    SetReachable(NET_IPV6, true);
    SetReachable(NET_ONION, true);
    SetReachable(NET_I2P, true);
    SetReachable(NET_CJDNS, true);

    BOOST_CHECK(IsReachable(NET_IPV4));
    BOOST_CHECK(IsReachable(NET_IPV6));
    BOOST_CHECK(IsReachable(NET_ONION));
    BOOST_CHECK(IsReachable(NET_I2P));
    BOOST_CHECK(IsReachable(NET_CJDNS));
}

BOOST_AUTO_TEST_CASE(LimitedAndReachable_NetworkCaseUnroutableAndInternal)
{
    BOOST_CHECK(IsReachable(NET_UNROUTABLE));
    BOOST_CHECK(IsReachable(NET_INTERNAL));

    SetReachable(NET_UNROUTABLE, false);
    SetReachable(NET_INTERNAL, false);

    BOOST_CHECK(IsReachable(NET_UNROUTABLE)); // Ignored for both networks
    BOOST_CHECK(IsReachable(NET_INTERNAL));
}

CNetAddr UtilBuildAddress(unsigned char p1, unsigned char p2, unsigned char p3, unsigned char p4)
{
    unsigned char ip[] = {p1, p2, p3, p4};

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sockaddr_in)); // initialize the memory block
    memcpy(&(sa.sin_addr), &ip, sizeof(ip));
    return CNetAddr(sa.sin_addr);
}


BOOST_AUTO_TEST_CASE(LimitedAndReachable_CNetAddr)
{
    CNetAddr addr = UtilBuildAddress(0x001, 0x001, 0x001, 0x001); // 1.1.1.1

    SetReachable(NET_IPV4, true);
    BOOST_CHECK(IsReachable(addr));

    SetReachable(NET_IPV4, false);
    BOOST_CHECK(!IsReachable(addr));

    SetReachable(NET_IPV4, true); // have to reset this, because this is stateful.
}


BOOST_AUTO_TEST_CASE(LocalAddress_BasicLifecycle)
{
    CService addr = CService(UtilBuildAddress(0x002, 0x001, 0x001, 0x001), 1000); // 2.1.1.1:1000

    SetReachable(NET_IPV4, true);

    BOOST_CHECK(!IsLocal(addr));
    BOOST_CHECK(AddLocal(addr, 1000));
    BOOST_CHECK(IsLocal(addr));

    RemoveLocal(addr);
    BOOST_CHECK(!IsLocal(addr));
}

BOOST_AUTO_TEST_CASE(initial_advertise_from_version_message)
{
    // Tests the following scenario:
    // * -bind=3.4.5.6:20001 is specified
    // * we make an outbound connection to a peer
    // * the peer reports he sees us as 2.3.4.5:20002 in the version message
    //   (20002 is a random port assigned by our OS for the outgoing TCP connection,
    //   we cannot accept connections to it)
    // * we should self-advertise to that peer as 2.3.4.5:20001

    // Pretend that we bound to this port.
    const uint16_t bind_port = 20001;
    m_node.args->ForceSetArg("-bind", strprintf("3.4.5.6:%u", bind_port));
    m_node.args->ForceSetArg("-capturemessages", "1");

    // Our address:port as seen from the peer - 2.3.4.5:20002 (different from the above).
    in_addr peer_us_addr;
    peer_us_addr.s_addr = htonl(0x02030405);
    const CService peer_us{peer_us_addr, 20002};

    // Create a peer with a routable IPv4 address.
    in_addr peer_in_addr;
    peer_in_addr.s_addr = htonl(0x01020304);
    CNode peer{/*id=*/0,
               /*sock=*/nullptr,
               /*addrIn=*/CAddress{CService{peer_in_addr, 8333}, NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0,
               /*nLocalHostNonceIn=*/0,
               /*addrBindIn=*/CAddress{},
               /*addrNameIn=*/std::string{},
               /*conn_type_in=*/ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false};

    const uint64_t services{NODE_NETWORK | NODE_WITNESS};
    const int64_t time{0};
    const CNetMsgMaker msg_maker{PROTOCOL_VERSION};

    // Force CChainState::IsInitialBlockDownload() to return false.
    // Otherwise PushAddress() isn't called by PeerManager::ProcessMessage().
    TestChainState& chainstate =
        *static_cast<TestChainState*>(&m_node.chainman->ActiveChainstate());
    chainstate.JumpOutOfIbd();

    m_node.peerman->InitializeNode(peer, NODE_NETWORK);

    std::atomic<bool> interrupt_dummy{false};
    std::chrono::microseconds time_received_dummy{0};

    const auto msg_version =
        msg_maker.Make(NetMsgType::VERSION, PROTOCOL_VERSION, services, time, services, peer_us);
    CDataStream msg_version_stream{msg_version.data, SER_NETWORK, PROTOCOL_VERSION};

    m_node.peerman->ProcessMessage(
        peer, NetMsgType::VERSION, msg_version_stream, time_received_dummy, interrupt_dummy);

    const auto msg_verack = msg_maker.Make(NetMsgType::VERACK);
    CDataStream msg_verack_stream{msg_verack.data, SER_NETWORK, PROTOCOL_VERSION};

    // Will set peer.fSuccessfullyConnected to true (necessary in SendMessages()).
    m_node.peerman->ProcessMessage(
        peer, NetMsgType::VERACK, msg_verack_stream, time_received_dummy, interrupt_dummy);

    // Ensure that peer_us_addr:bind_port is sent to the peer.
    const CService expected{peer_us_addr, bind_port};
    bool sent{false};

    const auto CaptureMessageOrig = CaptureMessage;
    CaptureMessage = [&sent, &expected](const CAddress& addr,
                                        const std::string& msg_type,
                                        Span<const unsigned char> data,
                                        bool is_incoming) -> void {
        if (!is_incoming && msg_type == "addr") {
            CDataStream s(data, SER_NETWORK, PROTOCOL_VERSION);
            std::vector<CAddress> addresses;

            s >> addresses;

            for (const auto& addr : addresses) {
                if (addr == expected) {
                    sent = true;
                    return;
                }
            }
        }
    };

    {
        LOCK(peer.cs_sendProcessing);
        m_node.peerman->SendMessages(&peer);
    }

    BOOST_CHECK(sent);

    CaptureMessage = CaptureMessageOrig;
    chainstate.ResetIbd();
    m_node.args->ForceSetArg("-capturemessages", "0");
    m_node.args->ForceSetArg("-bind", "");
    // PeerManager::ProcessMessage() calls AddTimeData() which changes the internal state
    // in timedata.cpp and later confuses the test "timedata_tests/addtimedata". Thus reset
    // that state as it was before our test was run.
    TestOnlyResetTimeData();
}

void message_serialize_deserialize_test(bool v2, const std::vector<CSerializedNetMsg>& test_msgs)
{
    // use keys with all zeros
    BIP324Key key_l, key_p, rekey_salt;
    memset(key_l.data(), 1, BIP324_KEY_LEN);
    memset(key_p.data(), 2, BIP324_KEY_LEN);
    memset(rekey_salt.data(), 3, BIP324_KEY_LEN);

    // construct the serializers
    std::unique_ptr<TransportSerializer> serializer;
    std::unique_ptr<TransportDeserializer> deserializer;

    if (v2) {
        serializer = std::make_unique<V2TransportSerializer>(V2TransportSerializer(key_l, key_p, rekey_salt));
        deserializer = std::make_unique<V2TransportDeserializer>(V2TransportDeserializer((NodeId)0, key_l, key_p, rekey_salt));
    } else {
        serializer = std::make_unique<V1TransportSerializer>(V1TransportSerializer());
        deserializer = std::make_unique<V1TransportDeserializer>(V1TransportDeserializer(Params(), (NodeId)0, SER_NETWORK, INIT_PROTO_VERSION));
    }
    // run 100 times through all messages with the same cipher suite instances
    for (unsigned int i = 0; i < 100; i++) {
        for (size_t msg_index = 0; msg_index < test_msgs.size(); msg_index++) {
            const CSerializedNetMsg& msg_orig = test_msgs[msg_index];
            // bypass the copy protection
            CSerializedNetMsg msg;
            msg.data = msg_orig.data;
            msg.m_type = msg_orig.m_type;

            std::vector<unsigned char> serialized_header;
            serializer->prepareForTransport(msg, serialized_header);

            // read two times
            //  first: read header
            size_t read_bytes{0};
            Span<const uint8_t> span_header(serialized_header.data(), serialized_header.size());
            if (serialized_header.size() > 0) read_bytes += deserializer->Read(span_header);
            //  second: read the encrypted payload (if required)
            Span<const uint8_t> span_msg(msg.data.data(), msg.data.size());
            if (msg.data.size() > 0) read_bytes += deserializer->Read(span_msg);
            if (msg.data.size() > read_bytes) {
                Span<const uint8_t> span_msg(msg.data.data() + read_bytes, msg.data.size() - read_bytes);
                read_bytes += deserializer->Read(span_msg);
            }
            // message must be complete
            BOOST_CHECK(deserializer->Complete());
            BOOST_CHECK_EQUAL(read_bytes, msg.data.size() + serialized_header.size());

            bool reject_message{true};
            bool disconnect{true};
            CNetMessage result{deserializer->GetMessage(GetTime<std::chrono::microseconds>(), reject_message, disconnect, {})};
            // The first v2 message is reject by V2TransportDeserializer as a placeholder for transport version messages
            BOOST_CHECK(!v2 || (i == 0 && msg_index == 0) || !reject_message);
            BOOST_CHECK(!disconnect);
            if (reject_message) continue;
            BOOST_CHECK_EQUAL(result.m_type, msg_orig.m_type);
            BOOST_CHECK_EQUAL(result.m_message_size, msg_orig.data.size());
            if (!msg_orig.data.empty()) {
                BOOST_CHECK_EQUAL(0, memcmp(result.m_recv.data(), msg_orig.data.data(), msg_orig.data.size()));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(net_v2)
{
    // create some messages where we perform serialization and deserialization
    std::vector<CSerializedNetMsg> test_msgs;
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERACK));
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERSION, PROTOCOL_VERSION, (int)NODE_NETWORK, 123, CAddress(CService(), NODE_NONE), CAddress(CService(), NODE_NONE), 123, "foobar", 500000, true));
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::PING, 123456));
    CDataStream stream(ParseHex("020000000001013107ca31e1950a9b44b75ce3e8f30127e4d823ed8add1263a1cc8adcc8e49164000000001716001487835ecf51ea0351ef266d216a7e7a3e74b84b4efeffffff02082268590000000017a9144a94391b99e672b03f56d3f60800ef28bc304c4f8700ca9a3b0000000017a9146d5df9e79f752e3c53fc468db89cafda4f7d00cb87024730440220677de5b11a5617d541ba06a1fa5921ab6b4509f8028b23f18ab8c01c5eb1fcfb02202fe382e6e87653f60ff157aeb3a18fc888736720f27ced546b0b77431edabdb0012102608c772598e9645933a86bcd662a3b939e02fb3e77966c9713db5648d5ba8a0006010000"), SER_NETWORK, PROTOCOL_VERSION);
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::TX, CTransaction(deserialize, stream)));
    std::vector<CInv> vInv;
    for (unsigned int i = 0; i < 1000; i++) {
        vInv.push_back(CInv(MSG_BLOCK, Params().GenesisBlock().GetHash()));
    }
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::INV, vInv));

    // add a dummy message
    std::string dummy;
    for (unsigned int i = 0; i < 100; i++) {
        dummy += "020000000001013107ca31e1950a9b44b75ce3e8f30127e4d823ed8add1263a1cc8adcc8e49164000000001716001487835ecf51ea0351ef266d216a7e7a3e74b84b4efeffffff02082268590000000017a9144a94391b99e672b03f56d3f60800ef28bc304c4f8700ca9a3b0000000017a9146d5df9e79f752e3c53fc468db89cafda4f7d00cb87024730440220677de5b11a5617d541ba06a1fa5921ab6b4509f8028b23f18ab8c01c5eb1fcfb02202fe382e6e87653f60ff157aeb3a18fc888736720f27ced546b0b77431edabdb0012102608c772598e9645933a86bcd662a3b939e02fb3e77966c9713db5648d5ba8a0006010000";
    }
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make("foobar", dummy));

    message_serialize_deserialize_test(true, test_msgs);
    message_serialize_deserialize_test(false, test_msgs);
}

BOOST_AUTO_TEST_CASE(bip324_derivation_test)
{
    // BIP324 key derivation uses network magic in the HKDF process. We use mainnet
    // params here to make it easier for other implementors to use this test as a test vector.
    SelectParams(CBaseChainParams::MAIN);
    static const std::string strSecret1 = "5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj";
    static const std::string strSecret2C = "L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g";
    static const std::string initiator_ellswift_str = "b654960dff0ba8808a34337f46cc68ba7619c9df76d0550639dea62de07d17f9cb61b85f2897834ce12c50b1aefa281944abf2223a5fcf0a2a7d8c022498db35";
    static const std::string responder_ellswift_str = "ea57aae33e8dd38380c303fb561b741293ef97c780445184cabdb5ef207053db628f2765e5d770f666738112c94714991362f6643d9837e1c89cbd9710b80929";

    auto initiator_ellswift = ParseHex(initiator_ellswift_str);
    auto responder_ellswift = ParseHex(responder_ellswift_str);

    CKey initiator_key = DecodeSecret(strSecret1);
    CKey responder_key = DecodeSecret(strSecret2C);

    auto initiator_secret = initiator_key.ComputeBIP324ECDHSecret(MakeByteSpan(responder_ellswift), MakeByteSpan(initiator_ellswift), true);
    BOOST_CHECK(initiator_secret.has_value());
    auto responder_secret = responder_key.ComputeBIP324ECDHSecret(MakeByteSpan(initiator_ellswift), MakeByteSpan(responder_ellswift), false);
    BOOST_CHECK(responder_secret.has_value());
    BOOST_CHECK(initiator_secret.value() == responder_secret.value());
    BOOST_CHECK_EQUAL("ae1b0c44c3c38aa5206899c0928ca51f637e3ec05771b4a6c0662b46b76049d8", HexStr(initiator_secret.value()));
    BOOST_CHECK_EQUAL("ae1b0c44c3c38aa5206899c0928ca51f637e3ec05771b4a6c0662b46b76049d8", HexStr(responder_secret.value()));

    BIP324Keys initiator_keys, responder_keys;

    DeriveBIP324Keys(std::move(initiator_secret.value()), initiator_keys);
    DeriveBIP324Keys(std::move(responder_secret.value()), responder_keys);

    BOOST_CHECK_EQUAL(BIP324_KEY_LEN, initiator_keys.initiator_L.size());
    BOOST_CHECK(initiator_keys.initiator_L == responder_keys.initiator_L);
    BOOST_CHECK_EQUAL("98b1a948d70374db8078475fd2b573789989a57d5394ecc229a3f2ec336c4d18", HexStr(initiator_keys.initiator_L));

    BOOST_CHECK_EQUAL(BIP324_KEY_LEN, initiator_keys.initiator_P.size());
    BOOST_CHECK(initiator_keys.initiator_P == responder_keys.initiator_P);
    BOOST_CHECK_EQUAL("95bdf50958c46ad24c7646cd7bf7579ffafb2f032d2c5356fc8341e198d0bb51", HexStr(initiator_keys.initiator_P));

    BOOST_CHECK_EQUAL(BIP324_KEY_LEN, initiator_keys.responder_L.size());
    BOOST_CHECK(initiator_keys.responder_L == responder_keys.responder_L);
    BOOST_CHECK_EQUAL("0dec3e671918898ce5472b161ddfcc6f765bf459e8cdeb86825fa704a58546e5", HexStr(initiator_keys.responder_L));

    BOOST_CHECK_EQUAL(BIP324_KEY_LEN, initiator_keys.responder_P.size());
    BOOST_CHECK(initiator_keys.responder_P == responder_keys.responder_P);
    BOOST_CHECK_EQUAL("af8b74244dd43c5921e2449a125d669f6d82a23250fa040eafc3ba2373067de5", HexStr(initiator_keys.responder_P));

    BOOST_CHECK_EQUAL(BIP324_KEY_LEN, initiator_keys.session_id.size());
    BOOST_CHECK(initiator_keys.session_id == responder_keys.session_id);
    BOOST_CHECK_EQUAL("ae605e623a8f710f4f0c99454d74cdfb8861cad1f8f6dd2eb86390d615efab01", HexStr(initiator_keys.session_id));

    BOOST_CHECK_EQUAL(BIP324_KEY_LEN, initiator_keys.rekey_salt.size());
    BOOST_CHECK(initiator_keys.rekey_salt == responder_keys.rekey_salt);
    BOOST_CHECK_EQUAL("e46620b5e10052931401606ccbb4c810c4f9afa9db948e3acfbeaa65b0cc8199", HexStr(initiator_keys.rekey_salt));

    BOOST_CHECK_EQUAL(BIP324_GARBAGE_TERMINATOR_LEN, initiator_keys.garbage_terminator.size());
    BOOST_CHECK(initiator_keys.garbage_terminator == responder_keys.garbage_terminator);
    BOOST_CHECK_EQUAL("73d7412ff3b42a01", HexStr(Span{initiator_keys.garbage_terminator}));

    SelectParams(CBaseChainParams::REGTEST);
}

struct P2PV2Peer {
    CKey key;
    std::array<uint8_t, 32> ellswift_r32;
    EllSwiftPubKey expected_ellswift;
    std::vector<uint8_t> plaintext;
    std::vector<uint8_t> ciphertext_mac_0;
    std::vector<uint8_t> ciphertext_mac_999;
};

struct P2PV2TestVector {
    P2PV2Peer initiator;
    P2PV2Peer responder;
    ECDHSecret expected_ecdh_secret;
    BIP324Keys expected_bip324_keys;
};

#define PARSE_HEX_COPY(X, Y) \
    parsed_hex = ParseHex(X); \
    memcpy(Y.data(), parsed_hex.data(), parsed_hex.size())

P2PV2TestVector parse_test_vector(const char* initiator_privkey, const char* responder_privkey,
        const char* initiator_ellswift_r32, const char* responder_ellswift_r32,
        const char* initiator_ellswift, const char* responder_ellswift,
        const char* shared_ecdh_secret,
        const char* initiator_L, const char* initiator_P,
        const char* responder_L, const char* responder_P,
        const char* session_id,
        const char* rekey_salt,
        const char* garbage_terminator,
        const char* initiator_plaintext,
        const char* initiator_ciphertext_mac_0, const char* initiator_ciphertext_mac_999,
        const char* responder_plaintext,
        const char* responder_ciphertext_mac_0, const char* responder_ciphertext_mac_999) {
    P2PV2TestVector ret;
    auto parsed_hex = ParseHex(initiator_privkey);
    ret.initiator.key.Set(parsed_hex.begin(), parsed_hex.end(), false);
    parsed_hex = ParseHex(responder_privkey);
    ret.responder.key.Set(parsed_hex.begin(), parsed_hex.end(), false);

    PARSE_HEX_COPY(initiator_ellswift_r32, ret.initiator.ellswift_r32);
    PARSE_HEX_COPY(responder_ellswift_r32, ret.responder.ellswift_r32);
    PARSE_HEX_COPY(initiator_ellswift, ret.initiator.expected_ellswift);
    PARSE_HEX_COPY(responder_ellswift, ret.responder.expected_ellswift);
    PARSE_HEX_COPY(shared_ecdh_secret, ret.expected_ecdh_secret);
    PARSE_HEX_COPY(initiator_L, ret.expected_bip324_keys.initiator_L);
    PARSE_HEX_COPY(initiator_P, ret.expected_bip324_keys.initiator_P);
    PARSE_HEX_COPY(responder_L, ret.expected_bip324_keys.responder_L);
    PARSE_HEX_COPY(responder_P, ret.expected_bip324_keys.responder_P);
    PARSE_HEX_COPY(session_id, ret.expected_bip324_keys.session_id);
    PARSE_HEX_COPY(rekey_salt, ret.expected_bip324_keys.rekey_salt);
    ret.expected_bip324_keys.garbage_terminator.resize(BIP324_GARBAGE_TERMINATOR_LEN);
    PARSE_HEX_COPY(garbage_terminator, ret.expected_bip324_keys.garbage_terminator);
    ret.initiator.plaintext = ParseHex(initiator_plaintext);
    ret.initiator.ciphertext_mac_0 = ParseHex(initiator_ciphertext_mac_0);
    ret.initiator.ciphertext_mac_999 = ParseHex(initiator_ciphertext_mac_999);
    ret.responder.plaintext = ParseHex(responder_plaintext);
    ret.responder.ciphertext_mac_0 = ParseHex(responder_ciphertext_mac_0);
    ret.responder.ciphertext_mac_999 = ParseHex(responder_ciphertext_mac_999);

    return ret;
}

void bip324_assert_test_vector(const P2PV2TestVector& tv) {
    auto initiator_ellswift = tv.initiator.key.EllSwiftEncode(tv.initiator.ellswift_r32).value();
    BOOST_CHECK_EQUAL(HexStr(initiator_ellswift), HexStr(tv.initiator.expected_ellswift));

    auto responder_ellswift = tv.responder.key.EllSwiftEncode(tv.responder.ellswift_r32).value();
    BOOST_CHECK_EQUAL(HexStr(responder_ellswift), HexStr(tv.responder.expected_ellswift));

    auto initiator_ecdh_secret = tv.initiator.key.ComputeBIP324ECDHSecret(
            MakeByteSpan(responder_ellswift), MakeByteSpan(initiator_ellswift), true).value();
    auto responder_ecdh_secret = tv.responder.key.ComputeBIP324ECDHSecret(
            MakeByteSpan(initiator_ellswift), MakeByteSpan(responder_ellswift), false).value();
    BOOST_CHECK_EQUAL(HexStr(initiator_ecdh_secret), HexStr(responder_ecdh_secret));
    BOOST_CHECK_EQUAL(HexStr(initiator_ecdh_secret), HexStr(tv.expected_ecdh_secret));

    BIP324Keys v2_keys;
    DeriveBIP324Keys(std::move(initiator_ecdh_secret), v2_keys);

    BOOST_CHECK_EQUAL(HexStr(v2_keys.initiator_L), HexStr(tv.expected_bip324_keys.initiator_L));
    BOOST_CHECK_EQUAL(HexStr(v2_keys.initiator_P), HexStr(tv.expected_bip324_keys.initiator_P));
    BOOST_CHECK_EQUAL(HexStr(v2_keys.responder_L), HexStr(tv.expected_bip324_keys.responder_L));
    BOOST_CHECK_EQUAL(HexStr(v2_keys.responder_P), HexStr(tv.expected_bip324_keys.responder_P));
    BOOST_CHECK_EQUAL(HexStr(v2_keys.session_id), HexStr(tv.expected_bip324_keys.session_id));
    BOOST_CHECK_EQUAL(HexStr(v2_keys.rekey_salt), HexStr(tv.expected_bip324_keys.rekey_salt));
    BOOST_CHECK_EQUAL(HexStr(v2_keys.garbage_terminator), HexStr(tv.expected_bip324_keys.garbage_terminator));

    auto initiator_suite = BIP324CipherSuite(v2_keys.initiator_L, v2_keys.initiator_P, v2_keys.rekey_salt);
    BIP324HeaderFlags flags{BIP324_NONE};
    std::vector<std::byte> ciphertext_mac;
    ciphertext_mac.resize(BIP324_LENGTH_FIELD_LEN + BIP324_HEADER_LEN + tv.initiator.plaintext.size() + RFC8439_TAGLEN);
    for (int i = 0; i < 1000; i++) {
        BOOST_CHECK(initiator_suite.Crypt({}, MakeByteSpan(tv.initiator.plaintext), MakeWritableByteSpan(ciphertext_mac), flags, true));
        if (i == 0) {
            BOOST_CHECK_EQUAL(HexStr(ciphertext_mac), HexStr(tv.initiator.ciphertext_mac_0));
        } else if (i == 999) {
            BOOST_CHECK_EQUAL(HexStr(ciphertext_mac), HexStr(tv.initiator.ciphertext_mac_999));
        }
    }

    auto responder_suite = BIP324CipherSuite(v2_keys.responder_L, v2_keys.responder_P, v2_keys.rekey_salt);
    ciphertext_mac.resize(BIP324_LENGTH_FIELD_LEN + BIP324_HEADER_LEN + tv.responder.plaintext.size() + RFC8439_TAGLEN);
    for (int i = 0; i < 1000; i++) {
        BOOST_CHECK(responder_suite.Crypt({}, MakeByteSpan(tv.responder.plaintext), MakeWritableByteSpan(ciphertext_mac), flags, true));
        if (i == 0) {
            BOOST_CHECK_EQUAL(HexStr(ciphertext_mac), HexStr(tv.responder.ciphertext_mac_0));
        } else if (i == 999) {
            BOOST_CHECK_EQUAL(HexStr(ciphertext_mac), HexStr(tv.responder.ciphertext_mac_999));
        }
    }
}

BOOST_AUTO_TEST_CASE(bip324_vectors_test)
{
    // BIP324 key derivation uses network magic in the HKDF process. We use mainnet
    // params here to make it easier for other implementors to use this test as a test vector.
    SelectParams(CBaseChainParams::MAIN);
    std::array<P2PV2TestVector, 5> vectors{
        parse_test_vector(
            /* initiator_privkey */ "9cdfc7df74056ddebee98e3310026ecb11578cad9c5d09457194cc2162a1973b",
            /* responder_privkey */ "2030aaaf44a1437c07c938aa33c58751a6aee0c0e48e285f8031b137f498921d",
            /* initiator_ellswift_r32*/ "c1efb3a6738a6d612f5f27dc35959c7e5c7d3ec15ffae3ca3159abd1582e8db7",
            /* responder_ellswift_r32 */ "cb9dfe3802ae4caf320971d52f36f284ad88ddb976976cc2deb6bb39d0a79fde",
            /* initiator_ellswift */ "9b006371b8ceab1a95e87de3e24022c22946f1949a19baee6de14f3abf2d559a95c385732c3d4cf345d158bf72dfc142093a7708c02e96355c010f456f47422d",
            /* responder_ellswift */ "19a4af4fa003a1ea67c0d25771ba90a81a92490a9a19690eab1b8598744c35aa1ade90c6ce36f122ea909c539115e95907488312e30e90d3c519018f5693b664",
            /* shared_ecdh_secret */ "8b600f8ae431a60eee4a2b05c26a800520d646d9e29dcbb6e1d1a1a53600744a",
            /* initiator_L */ "d8ffa7bda251a12ad9ada805519e32d557f302143962482411e7abe21b294668",
            /* initiator_P */ "528a7be429d8f6438b5c0b42ee29fd2cedc093a835be99756b425c5acfd2b4fe",
            /* responder_L */ "f168b2a7d711ef4383fb7a80ddb14bc1f80e6abaaec7c117c90536c493e4e612",
            /* responder_P */ "ead72c65c396e0e25e6846ebe73ddaa0b0a409e5349017efab5e405a9fe49490",
            /* session_id */ "27a1be3718d33a47dcd1c77fe4dfd2b51d1e446058917c6ebff0ef59a4ac5f95",
            /* rekey_salt */ "a0e1ac15dab27892ac9e269c58cd0ee500d6b90609a8b3b3f8ca507c0a7c6964",
            /* garbage_terminator */ "1fc511513b51f156",
            /* initiator_plaintext */ "9bc0f24442a76af47b9daa9f0c99d41381c0c06698ffc4ad069acf3d20928277433818565904cdd66ea93b1b755a3293d1d154110faa8add3dcafed2328fffea",
            /* initiator_ciphertext_mac_0 */ "bc446b0bcc0cc24e5bdb2fe71d4c9cda282ffb67b347af24da6f76531b13c5cfdbb879ca9f2c0256aa5789915eab0f68ea73c6b8fb76f999d9386bb5d7f065187a89e5e8f647f3f64d7517fefb6b15706b22173c",
            /* initiator_ciphertext_mac_999 */ "b2ed5c643b40dd34258c7f36b5343a34cd6bf34865f7b59ff025595c4738f2abae1e32ecd5c903c5b7a5f1eef96fb36c6903fb4cafa2a55542bf476be92635fba13d776d617dda2e7f5ad1b45b7a10490d7c970a",
            /* responder_plaintext */ "2822acbe87f9e1a284f2eaa9a56f948fc0de0c91f342ae541722b758d7956c9a8fe25b082789a2fb5b23da639d05e438461e7fcf92262dbeaeebbacbf01dcfb2",
            /* responder_ciphertext_mac_0 */ "fc8f3f53dadab408b5b75de9bcfc1705a11320389bcb434d2c03098b6ab69bc694ee27140197174f7ffb7da1c9e672ffe9d93b03424ca115cbbe135603c027f995b8b35941f849336f415da9d69e8a1ea39225fe",
            /* responder_ciphertext_mac_999 */ "ca5ab7cb233eb4cf4bc7ea2096c589288f5b1e415d619a2e5c92c8a7279064bf8b55130431a0c51e7ad0f96892e1caec65ae41663a729e5feef34dd3e438f1d7ea79bf640136c0cbca0f8ddc02e336ee6ca48605"),

        parse_test_vector(
            /* initiator_privkey */ "44e5fe764c43d1f7a60ead0acd0e74a4b14f7b7fc056984a993dede99e04c743",
            /* responder_privkey */ "fe6065b12cdfd53b9cd9b55c491063d60abdccc3090d2cdba17bf093fe363f09",
            /* initiator_ellswift_r32*/ "f54a836324dcb9c5701c3f73edf96ebfea053a2af1be4e7bb178bf721bad5e4d",
            /* responder_ellswift_r32 */ "ef7cd5de28f2b6b77f59ef3b4d00939841e0ab9ab5fdd351e83ce0626c90e866",
            /* initiator_ellswift */ "bd439a4b0cdf1a6ec5a3f10acb97ac2fe11d4c10266c24008f8d963ec40c5468b113ab984858531ecd134d716e31ca6f536bc23b4c56439bfd253f3c74c71883",
            /* responder_ellswift */ "c6eac141d4740187069e62a07c3549f5e179f676d90a8e333cda843c53127843aa3c5272baae373b3548d2e414c818aeaabc74938059b34c36c915d0e2f08840",
            /* shared_ecdh_secret */ "54544f05ecf53c938449da8337f09a8d7308bc5d2a7c0b25b50d69eeb2fecca9",
            /* initiator_L */ "e3213a978520d67d9eb91bbe62f793dd042831f17343633ee9ff2e95adc7f36a",
            /* initiator_P */ "6f7f4ab1bd8437fa0cda558a35eeb377d82706e2fe3ceb5629be20dfb5efdaac",
            /* responder_L */ "bf69e7cb6206ff00958f7a5997bee97b45e112d1ee6c76e7b19c682b5167589b",
            /* responder_P */ "cc17d8d043cb2420243c3a6490670d0d226d34839a7ccd0fc522e78ca45e0a55",
            /* session_id */ "669d32460f569ef03a33a097ab168ebb5bd6f5b7239220f9eaab2096b5582f55",
            /* rekey_salt */ "f2cf0c46db5fd85d2da7eb8b5d588cc6a87c95cb539864f6a7531a12659510b8",
            /* garbage_terminator */ "eed4061343f306fa",
            /* initiator_plaintext */ "a4874343279f3ca57427a8649833a7d276023e1035f85a7bfe19597055657192b9d2c102c69f0c8b2fdaeb064cc7432e549614e5aef603f9cf41e44a2f0b41b0",
            /* initiator_ciphertext_mac_0 */ "5e85ca64a2afa0006971bca2ae1becc2118662474e98ff02aed09e3d6a1e2c7d3adca02d39b31d6a0393ba6ca2585c9e51abd67f2f6bb8a073e59dd9d799ccd7867a88aa49df72e121c967ff915a2a40c8be90da",
            /* initiator_ciphertext_mac_999 */ "1a57cceb2dc5d95702f08da1dab19454a9a23be90361f4f0b91f90c24b364bc1a7a259e6f5a766a3285f0df6b895c7eb344f9f4124b8f086ca53c072f8304628d209bc1eb9590a93c2daa144370141d10438b1ab",
            /* responder_plaintext */ "dc77639158727bd733b8accc7c4bd27d329653bceace8be353b02fa56dda8598ff52c833e6aa826c9b7458d978490b24e6cd267afe6f4f1f47edf732e6d08beb",
            /* responder_ciphertext_mac_0 */ "82428cfd8a1c1b0e728f8f0d92ac01aa6a15045efbda0c41f6aca6b295f67281cf7c17fa83723c99ce8aeaf0163c501f12c82b12aa4c37939fa15ac5c802285aac4cb86a09f9096e2726a63a6aeda2e0e353387a",
            /* responder_ciphertext_mac_999 */ "826e8652c46bef3a003a7705d7ab917166b66c5a7f9b54b9eefe2e2e6fc2b47506957746249efd9f099ec6d71a3c8f81d5185cdbb4b9a7082c8bb166a81524637d81ee990eba877ded727fc1093dada2b5121252"),

        parse_test_vector(
            /* initiator_privkey */ "2e26264ea126f08b8baa90f394defc2af8e5e1a3392c1cf6456ba7879494cc29",
            /* responder_privkey */ "9fc639ee5a340b6d646d3c0ab35e634c565d25d8dde5fa2ca2e79fad07c9a6d5",
            /* initiator_ellswift_r32*/ "794d7f24d16def675f37c41277349fc7186bfa38943f3e349fb98a9c28cd92a8",
            /* responder_ellswift_r32 */ "2b8e3b215a08098a43604a9f0305a2ec5f5dc0cc624293fc285c6e5f1ad412f9",
            /* initiator_ellswift */ "2a5ec3ace440508588d706cbd08ea7bf04b46df6c5bb41c9ca7b07e30fdefc0fb124bb825a4004a56d570860996faba49ad53dd731b27f8482c8eaccc495fcc1",
            /* responder_ellswift */ "e979b78addd7cf3534214c67a4e11edc772166162bad7ac5eb4f903300e401f7e85189a75aeb741ce5d8812d7be79c514748018123ee3e5a0f0aa34e1515517a",
            /* shared_ecdh_secret */ "ff194f30feb14c325ffd7b7d56d7b5840d3af0433f071a33b0481c32787e17dd",
            /* initiator_L */ "215e3d0f94cda45100498e3e6504cbcba71e5734b42ec99f7b02b182c42c6535",
            /* initiator_P */ "c48ca23b4d66e44085d421095d23a4dbd47c2ed093befff923c60898fa257423",
            /* responder_L */ "dce61c527e093c22c9ce9d7dcd4fc30ea24a0dcccdc6c8f4fe3727d64721af26",
            /* responder_P */ "3216f5ceb8faba0c7c87af2f864a4e0ef4e6ed64d7a1ba14c0ad64e6f7a658fb",
            /* session_id */ "ae970a5ac60e42ff725e0e808ce13cd5c94d1d3449b2e7870834d65ce59bcf8b",
            /* rekey_salt */ "76b46f4e51010daf55f8c750ae005da2a20198627a29812d58aa68d9ea46a6e1",
            /* garbage_terminator */ "b7d9880ef42e3447",
            /* initiator_plaintext */ "868d3648fbd816c72c54c12f403127503ba305eeb1a65a144009fae2b6e3bea4c76034a88ccee3a3396c69a970b4fff2f381097d33943a0d455f6f3303a4d3dd",
            /* initiator_ciphertext_mac_0 */ "eb31090aaf915a0abe1b7c67ca0a763a092bfb18a7defc166daab613c1143889f555ef4a983ba72ada5ce6d3568f4b100603b9571164d83d2a166f64cca050bdb0d3bd219541b1efdf4608f35dcfadad64b3c67a",
            /* initiator_ciphertext_mac_999 */ "0f87c83e1e8ae04fbce8fd01a74d6b7e5db7deba40b3a24070454be4517bd146517fb138200118bbd5ac123e2e59cc5d5505b9f7e7fd3060f7fd94dccf3abe117a0e6ceb287868c653293e20a0ee8a059cea083f",
            /* responder_plaintext */ "ba67e844fa8d7aa6b77dbb1737c3080da7b65c36b219d91da499b2fb58b6e6e711e7d2960ce744d1e15351badf205a829f7b55b74e971e0a9547d88ec3c30686",
            /* responder_ciphertext_mac_0 */ "72c8661bc4b88bbe442672c42e95530b385e5c3721cad06c00e11435365096dbf06863fe1d6a65ac915b2f5dd94cd39ad0d802806748d89eb4d8b1e62890c91a57230b725d44c711f87b5673ac57028daa3e168c",
            /* responder_ciphertext_mac_999 */ "859cb87f8720208c1f095b2a3e8d9d58569b73ba35c266cd0d17ebc821f200d12141dc892b5240d59f78ecf62fdec655e8e01592d7bc26ed074bf487f24f539ccb58462b1c00505ed91f959a8d93114278623bd8"),

        parse_test_vector(
            /* initiator_privkey */ "a371e20223e60e967233fe079f052aeabd30f6c6781314f3e7c44e049c648b7d",
            /* responder_privkey */ "8063aec031db643874c6629942c402e48f7d74abaf97a8faf8d4628010e46ba4",
            /* initiator_ellswift_r32*/ "ec23b3eab32028a9981ff20851abdd10846951b88989950cc31565bd9a3cda79",
            /* responder_ellswift_r32 */ "546bfd88292d90a9bbf697380c68f017fdf911d20acad6c3c7e900eff0205a83",
            /* initiator_ellswift */ "141cbda0eb0435e5a7c7317dc5360eb37932951373f3df0d87ec293f859da12c5cfe0c2271b40669388556825f74cb1d8cb1511831230a388dc27dcc1fb51ee6",
            /* responder_ellswift */ "1c8d9559b0ebebf6e6c7a65f21c4aa1db33ece37cae8affab4150894470b2ffcfe2b80be24710896b47e8c47566e652e4a433fea997fbc06d41f2359a47e2fd4",
            /* shared_ecdh_secret */ "845d7f86858317bd631acbfd3fd10f16af9eff159e7ae82f5de72b0ff57c5b73",
            /* initiator_L */ "cd9e390a2aa3efa0d32c8f038d3a3b6cbfa00e411ff1c86be9801e8ab11f9a78",
            /* initiator_P */ "9fbea2fdb2dd6fa72e4917268b87a16c95c60f3164cea63b67fef2e48e5ca3e5",
            /* responder_L */ "7a556942d9390e553650ea23055b03ad490e5f0ef5a833b1ed7685b03b5377c6",
            /* responder_P */ "a52ce07c1a31bfb195ca6c5e8270aed07ae1555b22c640b2f12cf3b02d98601c",
            /* session_id */ "0e0afc3f05cd2c2f908a84affe0f12f39af0e169bd111372b0423a3349e5c948",
            /* rekey_salt */ "d225cfa43918d9f555a0e76494a828cf864abf4575178fb5c09b140d3b3ca8d2",
            /* garbage_terminator */ "b9b851235209c73f",
            /* initiator_plaintext */ "3e7443578c300b7210860c17168c9e11414781f6168710968777b567f1c27165bc8118ef402150549c18de9b567b85d4046fbef91f502f8cf4c298888ddd434b",
            /* initiator_ciphertext_mac_0 */ "3f3ef829998035e52a182c603fbd4497314d6b0b4c90e75ccabbf18df2e2e9c7aa6d75b9e3197b292fb00a0cbae6b0c9d278db6ca15f8f6bc823c566618804c669ae782f50f69facd6d8a3846f93ddc897770954",
            /* initiator_ciphertext_mac_999 */ "8c82408e024e092f2918c0f5253b0417179dad57d9de145436297fc7366e9e947d51f10b955d56aed282055740686a3c8e5c4b0b8f17456d97ffcc5ffa5eff69664d93b060cc1d88dbfbcbe7b9788d74dfa22b38",
            /* responder_plaintext */ "7f6c9fbae0c003bb38ee2e73c31b248d639cc63b0d5d57b05f57c8b82122d61e401af33d481304a7d956b9ca730500890908682b14933cde958bf497cbcbbd45",
            /* responder_ciphertext_mac_0 */ "fd9de83f982b9bfe23a13fee03daf2a41ed68921c7e2ddd3b7301abd038a7980607f283f21a75527e708d771501b662661cd9481dbe9b105221aa29443f98019d2b17a8ca777c0e6f6fa2c1e833c1c8246a8f7c8",
            /* responder_ciphertext_mac_999 */ "b9517532e70c7d84b58df95412b5167ea51ae9c8412136a454d3d827e31e856d6cf76bb7a958295018e7346400daaf8bd46d80949f86d0cc65719a54a9b605edb8635f6f6295ee646cebd2f73c439bed9890ea5a"),

        parse_test_vector(
            /* initiator_privkey */ "928861cf12421b8174bce71bdbdf4397213e17977e40116d79fd42372dfce856",
            /* responder_privkey */ "1b06ce10bfdeb76e002d370df40120eb0472b432c5f6535d6a47cff44e126255",
            /* initiator_ellswift_r32*/ "1f909dc3ba59acbc6d24f589712cba5ac3926d7c8bc79f02316f4d1adb4f1b26",
            /* responder_ellswift_r32 */ "8bc6a59833a8e94810665ac0360b8c976d3f6dfec9573ae8333759e7d5fa8af8",
            /* initiator_ellswift */ "762f4b6ea5069f5ed6ee7abe37cb6f2c05487412413895cdd4b5c6ded9dade9e9c11019949cbb4ae4a109fca90de116010327c5b863dae85b1b85d2694656e2e",
            /* responder_ellswift */ "ad041b394e0819c9da64559351d09405cd434081d9d43137e1dd6727e5f8c7a85b64b19af0a0e401af0daab8928ef3a26634f28b325586d5c9dccd4fa51a70d7",
            /* shared_ecdh_secret */ "5f84b6a0f812483cafb1ca619ce74dab2bf9a416c5a968471ea36ed8beed4e39",
            /* initiator_L */ "07fddf134082b9154c82369da01a5cec36624daba6ca06dc5e83a5960eb71802",
            /* initiator_P */ "76c155b9d6bb36faf086ec05ac6b9a7688737ed511cce7d7ec401aef965368a6",
            /* responder_L */ "8471d6698c10f7ede90db30a646736627d09e088d20eec1e67abd232cd8285d9",
            /* responder_P */ "c2a045440f03831399e375a25dd0c1d547b6b330832ba4a9af13aac964bb5a57",
            /* session_id */ "3c979f5aa0038c69fac82010c444231ae28e72d6f872233161f4f8269355e7ab",
            /* rekey_salt */ "8b3ca80d9aa33d48c7ee1428f5412116bd3fc5b1b81421d1fc52449dc0fbc734",
            /* garbage_terminator */ "aafe5f09c47b08e5",
            /* initiator_plaintext */ "7ab5826761ecf971d0aeff4c14eed091a206d29ddd84681c206b333bf0e121fcc5f8d45a266ce9ded4f7476edd0ab941c59cf4bca47f9327cf26a78ab4c9e7d6",
            /* initiator_ciphertext_mac_0 */ "b48ef2f2dff7ec7e570a5dcab720c1d8dc62993b1ce4dd7293a04ae6c7015c9870d5911a4191f5f803e78c599cc44f4167ade69c71b27237d66b20c3c8f868d9087b70ea0370a8f70b747f48bbca7cfcf8e63222",
            /* initiator_ciphertext_mac_999 */ "52370177648f04d9a3c971b7e5e94552892a8fc09c5cd38f0ddb26b7c434539f2235847a6de04b6c98fb5b13009ae4fb1b626729b0b8261052f26d22feeabae8100c961f0e9722ecaf6864bad8396557e3808e78",
            /* responder_plaintext */ "dee314b076651a31f0e7451f4e0c3cebddeb6ce82d937b14e036cfa8ae8a91d3afd2760351c0c146fe8740874a3e281fb298cb00a1d9e58a1081f173466ceed6",
            /* responder_ciphertext_mac_0 */ "0845058d886b9de79f3281aaa74572059ab47531bd131013b0149bdc0651bf528cfc9e366fbfacab47989cbd7e99db2abfb4dbfd1ec179f4cc06cd6b01765c867642ebfcf86fc27a12b5782d870c25d7ca3517d9",
            /* responder_ciphertext_mac_999 */ "911015cda051a69784f7a62b4fcf5da4d3d490ed3e64dc784927e6381a9275a20e0e83c1b2912184238ba1aba43b61d6615df5411a8a30ef078efb99b740eb802c80bc8bb809ef5cfc62bfbc6f034c5d9fac7793"),
    };

    for (const auto& tv: vectors) {
        bip324_assert_test_vector(tv);
    }
    SelectParams(CBaseChainParams::REGTEST);
}
BOOST_AUTO_TEST_SUITE_END()
