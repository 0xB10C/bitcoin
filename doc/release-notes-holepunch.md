P2P
---

- Nodes that cannot accept incoming connections can connect to each other
  directly by TCP hole punching through *boards*, reachable nodes that report
  their external addresses and hand out their announcements. Set `-holepunch=1`
  to take part, `-holepunchboard=1` to act as a board. This is experimental;
  see `doc/p2p-holepunch.md`.
