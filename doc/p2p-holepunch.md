# TCP hole punching

Two nodes that both sit behind a NAT, or behind a stateful firewall, cannot
normally connect to each other: neither accepts incoming TCP connections.
With `-holepunch=1` they can, by TCP simultaneous open ("hole punching"),
as specified in the draft BIP "TCP Hole Punching for Peer Connections".
This is experimental and off by default.

## How it works

- The node reserves one local port, the *punch port* (`-holepunchport`,
  default: the P2P port plus two), and makes every outbound connection to an
  IPv4 or IPv6 peer that does not go through a proxy from that port. Every
  peer then reports the same NAT mapping back in `version.addr_recv`, which
  is how the node learns its *external address*: at least two peers in
  different network groups have to agree on it.
- Support is negotiated per connection with a BIP 434 `feature` message.
  Peers that have hole punching on act as *coordinator* for each other.
- A node with an external address and a free inbound slot *announces*
  itself to its peers: an `addrv2` element of the new HOLEPUNCH address type
  names a coordinator it is connected to and its own external address.
  Announcements are relayed like other addresses but kept only in a small,
  short-lived cache; they never enter the address manager.
- A node with such an announcement in its cache asks the coordinator with a
  `rendezvous` message. The coordinator sends `punch` to both nodes, each
  connects to the other from its punch port, and the simultaneous open
  produces one TCP connection. It uses the v2 transport only.
- The side that asked (the initiator) accounts the connection as an
  outbound peer in one extra slot, beyond the automatic outbound slots; the
  other side accounts it as inbound. Both show `"hole_punched": true` in
  `getpeerinfo`.

NATs with endpoint-independent mapping (most home routers) and stateful
firewalls work; symmetric NATs (most carrier-grade and mobile NATs) do not,
and a node behind one detects that from disagreeing reports and stays out.

## Options and RPCs

- `-holepunch=1`: enable hole punching (needs `-v2transport`).
- `-holepunchport=<port>`: the punch port (default: `-port` plus two).
- `getholepunchinfo`: the punch port, the external address per address
  family with the number of peers reporting it, cached announcements, and
  punch sessions in progress.
- `getpeerinfo`: `hole_punched` and `holepunch_caps` per peer.
- `-debug=holepunch`: log every step, including why a request or a
  `punch` was ignored.

For testing by hand, the hidden RPCs `holepunchaddannouncement` and
`holepunchrendezvous` put an announcement into the cache and ask a
connected coordinator for a rendezvous, and `sendmsgtopeer` can send a
raw `punch`.

## Limits

One hole-punched outbound at a time, two punch sessions at a time, four
per minute, one per remote address per ten minutes, one coordination
attempt per five minutes, announcements at most every ten minutes per
peer, a cache of 32 announcements with at most four per peer.
