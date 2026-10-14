// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HOLEPUNCH_H
#define BITCOIN_HOLEPUNCH_H

#include <netaddress.h>
#include <random.h>

#include <cstdint>
#include <optional>

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

} // namespace holepunch

#endif // BITCOIN_HOLEPUNCH_H
