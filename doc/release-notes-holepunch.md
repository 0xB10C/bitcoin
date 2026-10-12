P2P and network changes
-----------------------

- EXPERIMENTAL: With `-holepunch=1`, nodes behind a NAT or a stateful
  firewall can connect to each other by TCP hole punching, as specified in
  the draft BIP "TCP Hole Punching for Peer Connections". All outbound
  clearnet connections are then made from the punch port
  (`-holepunchport`, default: a random port chosen at startup), peers negotiate the
  feature with BIP 434, and a new BIP 155 address type (network id 8)
  announces nodes reachable this way. A node with `-listenonion` also runs
  a second onion service, never advertised and replaced whenever the
  node's external address changes and at least daily, through which it
  coordinates punches to itself; connectors reach it through their Tor
  proxy. Off by
  default; needs `-v2transport`. See `doc/p2p-holepunch.md`.
- A new connection type, `holepunch-coordination`, is used for the
  short-lived connections that arrange a hole punch. The node sends only
  the handshake and the hole punching messages on them, and they take no
  connection slot.
  `-holepunchcoordbind` sets where such connections are accepted.

New RPCs
--------

- `getholepunchinfo` reports the state of hole punching.

Updated RPCs
------------

- `getpeerinfo` has two new fields: `hole_punched`, whether the connection
  was made by hole punching, and `holepunch_caps`, the hole punching
  capabilities a peer announced; `connection_type` can be
  `holepunch-coordination`.
- `addconnection` accepts `holepunch-coordination` as connection type.
