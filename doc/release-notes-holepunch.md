P2P and network changes
-----------------------

- EXPERIMENTAL: With `-holepunch=1`, nodes behind a NAT or a stateful
  firewall can connect to each other by TCP hole punching, as specified in
  the draft BIP "TCP Hole Punching for Peer Connections". All outbound
  clearnet connections are then made from the punch port
  (`-holepunchport`, default: the P2P port plus two), peers negotiate the
  feature with BIP 434, and a new BIP 155 address type (network id 8)
  announces nodes reachable this way. Off by default; needs
  `-v2transport`. See `doc/p2p-holepunch.md`.

New RPCs
--------

- `getholepunchinfo` reports the state of hole punching.

Updated RPCs
------------

- `getpeerinfo` has two new fields: `hole_punched`, whether the connection
  was made by hole punching, and `holepunch_caps`, the hole punching
  capabilities a peer announced.
