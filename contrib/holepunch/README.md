# TCP hole punching helpers

## nat-check.py

Tells you whether TCP hole punching can work from this host, before you
enable `-holepunch`. Hole punching needs the NAT in front of the host to
keep one local port mapped to one external address and port whatever the
destination is, which RFC 4787 calls an endpoint-independent mapping.

The script measures exactly that, with the Bitcoin P2P protocol itself. It
opens connections to several reachable nodes from one local port and reads
the address each of them reports back in its `version` message. That is the
same signal a node with `-holepunch` uses to learn its external address, so
a good result here predicts that the node will find one.

```
contrib/holepunch/nat-check.py
contrib/holepunch/nat-check.py --count 4 --port 49999
contrib/holepunch/nat-check.py --chain regtest --peers 127.0.0.1:29310,127.0.0.1:29320
```

Without `--peers` it asks the chain's DNS seeds for addresses in distinct
network groups. The connections are plain v1 and are closed as soon as the
version message has arrived; nothing else is sent.

The exit code is the verdict:

| code | meaning |
|------|---------|
| 0 | every peer reported the same endpoint, so hole punching can work |
| 1 | the peers disagreed, so this NAT maps per destination and punching cannot work |
| 2 | fewer than two peers in distinct network groups answered |

Run it on the host that cannot accept incoming connections. It cannot say
anything useful through a proxy, since the peers then see the proxy. Two
peers in distinct network groups are the minimum, because one peer alone
cannot tell a stable mapping from a coincidence.
