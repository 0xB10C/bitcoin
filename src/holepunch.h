// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HOLEPUNCH_H
#define BITCOIN_HOLEPUNCH_H

#include <netaddress.h>
#include <random.h>
#include <util/sock.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

/**
 * TCP hole punching: two nodes that both cannot accept incoming connections
 * connect to each other at the same time, from a port each of them uses for
 * all its outbound connections (the punch port), so that the NAT in front of
 * each already has a mapping for it. The two SYNs cross and the TCP
 * simultaneous open produces one connection.
 */
namespace holepunch {

/** The range the default punch port is chosen from: the dynamic port range. */
inline constexpr uint16_t PUNCH_PORT_MIN{49152};
inline constexpr uint16_t PUNCH_PORT_MAX{65535};

/** The wildcard address of `family` (IPv4 or IPv6) with `port`. */
CService WildcardAddress(Network family, uint16_t port);

/**
 * Pick a punch port at random from the dynamic range: one that is not a bad
 * port and that can be bound. Nothing depends on the number; a fixed
 * well-known port would mark the node's connections behind a port-preserving
 * NAT and collide with other nodes behind the same NAT. Returns nullopt if no
 * such port was found in a few tries.
 */
std::optional<uint16_t> PickRandomPunchPort(FastRandomContext& rng);

/** A connection attempt that failed is repeated after this long. */
inline constexpr auto RETRY{std::chrono::seconds{1}};

/** What a punch ended with. */
struct PunchOutcome {
    /** The connection with the peer, null if none was made. */
    std::shared_ptr<Sock> sock;
    /** The peer's address and port as seen on the connection (the port may differ from the one asked for). */
    CService peer;
    /** How often connect() was called. */
    int attempts{0};
    /** Why no connection was made, when `sock` is null. */
    std::string error;
};

/**
 * Make a connection with `peer` by TCP simultaneous open: listen on the punch
 * port and connect to the peer from the punch port, again whenever an attempt
 * fails, until a connection with the peer's address exists one way or the
 * other, `window` is over or `interrupted()` returns true. The peer has to do
 * the same towards this node at about the same time. Blocks until then.
 */
PunchOutcome Punch(const CService& peer, uint16_t punch_port, std::chrono::milliseconds window, const std::function<bool()>& interrupted);

} // namespace holepunch

#endif // BITCOIN_HOLEPUNCH_H
