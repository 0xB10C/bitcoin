P2P and network changes
-----------------------

- EXPERIMENTAL: With `-holepunch=1`, all outbound IPv4 and IPv6 connections
  are made from one local port, the punch port (`-holepunchport`, default:
  a random port chosen at startup), so that every peer reports this node's
  NAT mapping of it (`getpeerinfo` `addrlocal`). Two such nodes can then
  connect to each other by TCP hole punching with the new `holepunch` RPC.
  Off by default; needs `-v2transport`. See `doc/p2p-holepunch.md`.

New RPCs
--------

- `holepunch` connects to another node behind a NAT by TCP hole punching.
  Both nodes call it at about the same time, each with the other's address
  as its peers see it, one as `"outbound"` and the other as `"inbound"`.

Updated RPCs
------------

- `getpeerinfo` has a new field `hole_punched`, whether the connection was
  made by hole punching.
