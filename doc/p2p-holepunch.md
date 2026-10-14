# TCP hole punching by hand

Two nodes that both sit behind a NAT, or behind a stateful firewall, cannot
normally connect to each other: neither accepts incoming TCP connections.
With `-holepunch=1` and the `holepunch` RPC they can, by TCP simultaneous
open ("hole punching"), with a human doing the coordination. This is
experimental and off by default.

## How it works

- With `-holepunch=1` the node reserves one local port, the *punch port*
  (`-holepunchport`, default: a random port from the dynamic range, chosen
  at startup and kept for the run), and makes every outbound connection to
  an IPv4 or IPv6 peer that does not go through a proxy from that port.
  Every peer then sees the same NAT mapping of the punch port and reports it
  back in `version.addr_recv`, which `getpeerinfo` shows as `addrlocal`.
  As long as the node has outbound peers, the mapping stays alive.
- A NAT with endpoint-independent mapping (most home routers) forwards
  anything that arrives at that mapped address and port to the punch port,
  as long as something went out through it first. So if two such nodes
  connect to each other's mapped address from their punch ports at about
  the same time, each one's SYN opens its own NAT for the other's SYN, the
  two SYNs cross, and the TCP simultaneous open produces one connection.
- The `holepunch` RPC does exactly that: it listens on the punch port and
  connects to the given address from the punch port, again a second after
  an attempt fails, until a connection with that address exists one way or
  the other, or the time is up. The listener takes the peer's SYN if it
  arrives before an attempt of our own is pending.
- Which side is which is decided by the humans: the node called with
  `"outbound"` makes the connection a manual outbound peer with the v2
  transport, the node called with `"inbound"` puts it through the normal
  inbound path. Both show `"hole_punched": true` in `getpeerinfo`.

Symmetric NATs (most carrier-grade and mobile NATs) map every destination
differently, so the address a peer reports is of no use to a third party,
and this does not work behind them.

## Doing it

On both nodes, with `-v2transport` (the default) on:

```
bitcoind -holepunch=1
```

Once each node has a few outbound peers, read the address that the peers
report, which should be the same for all of them:

```
bitcoin-cli getpeerinfo | grep addrlocal
```

Exchange the two addresses, then call at the same time, say on the phone:

```
# node A, with node B's address
bitcoin-cli holepunch "<ip:port of B>" outbound
# node B, with node A's address
bitcoin-cli holepunch "<ip:port of A>" inbound
```

The calls return once the connection is made (with the peer id, the number
of attempts, and how long it took) or after the timeout, 30 seconds by
default. `-debug=holepunch` logs every attempt and why it failed.

## Options and RPCs

- `-holepunch=1`: enable hole punching (needs `-v2transport`).
- `-holepunchport=<port>`: the punch port (default: random from the
  dynamic range at startup; nothing depends on the number, and a fixed one
  would mark the node's connections behind a port-preserving NAT).
- `holepunch "<ip:port>" "outbound"|"inbound" ( timeout )`: connect by hole
  punching, blocking for up to `timeout` seconds (default 30). One at a
  time.
- `getpeerinfo`: `hole_punched` per peer.
- `-debug=holepunch`: log every step.
