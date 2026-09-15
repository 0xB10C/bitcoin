P2P and network changes
-----------------------

- Addresses in IANA special-purpose ranges that can never identify a reachable
  peer are now treated as unroutable (or, for multicast, as invalid). They are
  no longer relayed to other peers or stored in the address manager. This
  affects the IPv4 reserved range 240.0.0.0/4 and multicast range 224.0.0.0/4,
  and the IPv6 multicast range ff00::/8, discard-only prefix 100::/64,
  benchmarking range 2001:2::/48, local-use NAT64 prefix 64:ff9b:1::/48 and
  SRv6 SID block 5f00::/16. Entries in these ranges that are already present
  in `peers.dat` are dropped on load if they are multicast, and otherwise age
  out because they are never attempted or refreshed.
