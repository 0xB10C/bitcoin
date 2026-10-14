// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <holepunch.h>
#include <netbase.h>
#include <test/util/setup_common.h>
#include <util/sock.h>

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <future>

BOOST_FIXTURE_TEST_SUITE(holepunch_tests, BasicTestingSetup)

//! A loopback port that was free a moment ago.
static uint16_t FreeLoopbackPort()
{
    auto sock = CreateSock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    BOOST_REQUIRE(sock);
    BOOST_REQUIRE(BindToSharedPort(*sock, LookupNumeric("127.0.0.1", 0)));
    const uint16_t port{GetBindAddress(*sock).GetPort()};
    BOOST_REQUIRE(port != 0);
    return port;
}

BOOST_AUTO_TEST_CASE(simultaneous_open_on_loopback)
{
    const uint16_t port_a{FreeLoopbackPort()};
    const uint16_t port_b{FreeLoopbackPort()};
    BOOST_REQUIRE(port_a != port_b);
    const CService addr_a{LookupNumeric("127.0.0.1", port_a)};
    const CService addr_b{LookupNumeric("127.0.0.1", port_b)};
    const auto never{[] { return false; }};
    const auto window{std::chrono::seconds{10}};

    // Each side punches towards the other at the same time.
    auto future_a = std::async(std::launch::async, [&] { return holepunch::Punch(addr_b, port_a, window, never); });
    auto future_b = std::async(std::launch::async, [&] { return holepunch::Punch(addr_a, port_b, window, never); });
    const auto outcome_a{future_a.get()};
    const auto outcome_b{future_b.get()};
    BOOST_REQUIRE_MESSAGE(outcome_a.sock, outcome_a.error);
    BOOST_REQUIRE_MESSAGE(outcome_b.sock, outcome_b.error);
    BOOST_CHECK_EQUAL(outcome_a.peer.ToStringAddrPort(), addr_b.ToStringAddrPort());
    BOOST_CHECK_EQUAL(outcome_b.peer.ToStringAddrPort(), addr_a.ToStringAddrPort());
    BOOST_CHECK_EQUAL(GetBindAddress(*outcome_a.sock).GetPort(), port_a);
    BOOST_CHECK_EQUAL(GetBindAddress(*outcome_b.sock).GetPort(), port_b);

    // The two sockets are the two ends of one connection.
    const char ping{'x'};
    BOOST_REQUIRE_EQUAL(outcome_a.sock->Send(&ping, 1, 0), 1);
    BOOST_REQUIRE(outcome_b.sock->Wait(std::chrono::seconds{5}, Sock::RecvEvent));
    char pong{0};
    BOOST_REQUIRE_EQUAL(outcome_b.sock->Recv(&pong, 1, 0), 1);
    BOOST_CHECK_EQUAL(pong, ping);
}

BOOST_AUTO_TEST_CASE(nobody_on_the_other_side)
{
    const uint16_t port_a{FreeLoopbackPort()};
    const uint16_t port_b{FreeLoopbackPort()};
    const CService addr_b{LookupNumeric("127.0.0.1", port_b)};

    // Nothing listens on port_b: every attempt is refused, and attempts are repeated until the window is over.
    const auto outcome{holepunch::Punch(addr_b, port_a, std::chrono::milliseconds{1500}, [] { return false; })};
    BOOST_CHECK(!outcome.sock);
    BOOST_CHECK_EQUAL(outcome.error, "no connection within 1500 ms");
    BOOST_CHECK_EQUAL(outcome.attempts, 2);

    // An interrupted punch stops right away.
    const auto interrupted{holepunch::Punch(addr_b, port_a, std::chrono::seconds{10}, [] { return true; })};
    BOOST_CHECK(!interrupted.sock);
    BOOST_CHECK_EQUAL(interrupted.error, "interrupted");
    BOOST_CHECK_EQUAL(interrupted.attempts, 0);
}

BOOST_AUTO_TEST_SUITE_END()
