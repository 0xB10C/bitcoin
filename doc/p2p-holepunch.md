# TCP hole punching through boards

Hole punching lets two nodes that both cannot accept incoming connections,
typically because each sits behind a home NAT, connect to each other
directly. Both nodes connect to each other at the same time from a port
each of them has used before, so that the NAT in front of each already has
a mapping for it; the two connection attempts cross and TCP's simultaneous
open produces one connection. This implements the draft BIP
"Coordinator-less TCP Hole Punching for Peer Connections"; rule numbers in
the source refer to it.

This is experimental.

## Before enabling it

Hole punching only works if the NAT in front of the node keeps one local
port mapped to one external address and port whatever the destination is.
`contrib/holepunch/nat-check.py` measures that from the host itself, by
asking a few reachable nodes what address they see it at. Its exit code is
the verdict: zero if punching can work, one if the NAT maps per
destination, two if too few peers answered.

## Visitors

A node that cannot accept incoming connections takes part with

    -holepunch=1

It needs `-v2transport` (the default). It picks a *punch port* at random
from the dynamic port range at startup, or uses `-holepunchport=<port>`,
and makes every board connection and every punch attempt from that port.

It keeps two *board connections* per address family open, to reachable
nodes that advertise the board service bit, found in its address manager.
A board connection is a standing, limited-purpose connection: after the
handshake it carries nothing but pings and hole punching announcements.
The boards report the address and port they see the node at, which is the
endpoint its punch attempts will be seen from; once two boards in distinct
network groups agree, the node has an *external address* for that family.

The node then announces its external address and a per-family public key
on its board connections. The boards hand out such announcements to all
their visitors, so every visitor learns the entries of the others.

On every new block, the node ranks the entries it knows by a value that
only it and the entry's node can compute (a hash of their shared secret,
the block hash and both endpoints), and starts a punch session with the
lowest few. The entry's node does the same and, since the value is the
same on both sides, picks it too; the value's last bit decides which side
sends the first bytes. A session makes connection attempts from the punch
port for two minutes, and the connection, if one is made, uses the v2
transport only.

The initiator side holds the connection as an outbound beyond its
automatic outbound slots, at most one at a time. The responder side holds
it as an ordinary inbound connection.

## Boards

A reachable node helps nodes behind NATs with

    -holepunchboard=1

It needs `-listen` and `-v2transport`. A board accepts up to 32 visitors,
kept apart from its ordinary inbound limit, at most 4 from one network
group and 1 from one address, stores one announcement per visitor and only
if it names the endpoint the visitor connected from, and serves its live
entries to its visitors. Entries live only in memory. A board that is
also behind a NAT can set both options.

## Inspecting

`getholepunchinfo` shows, per address family, the external address and
how many boards report it, the open board connections, the key and the
address announced under it, and the entries learned from boards; the
rounds held and the sessions they started; and, for a board, the entries
it holds. `getpeerinfo` marks board connections with the connection type
`holepunch-board`, punched connections with `hole_punched`, and shows the
hole punching feature flags a peer sent.

## Testing

On regtest every node has the same address, so the implementation waives
routability, counts every endpoint as its own network group, and compares
endpoints instead of addresses where the draft compares addresses. Boards
can be named with `-holepunchboardseed=<ip:port>`, since the address
manager keeps no local addresses, and the hidden `holepunchsession` RPC
starts a session by hand. See `test/functional/p2p_holepunch_nodes.py`.
