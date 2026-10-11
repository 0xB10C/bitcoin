#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test a TCP hole punch between real nodes.

Four nodes, none connected to each other at the start:
  A (node 0) is the advertiser, C (node 1) the coordinator, B (node 2) the
  connector, D (node 3) a second peer for A and B, so that both learn their
  external address from two reporting peers.

A and B connect to C from their punch ports; C sees them at those ports and
they announce ADVERTISED and PUNCHPORT. B then asks C for a rendezvous with
A's endpoint. C sends punch to both, they connect to each other by TCP
simultaneous open, and the result is an inbound peer at A and a hole-punched
outbound peer at B that relays blocks like any other peer.
"""

import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    holepunch_port,
)

A, C, B, D = 0, 1, 2, 3


class HolePunchNodesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.extra_args = [[
            "-v2transport=1",
            "-holepunch=1",
            f"-holepunchport={holepunch_port(i)}",
        ] for i in range(self.num_nodes)]

    def setup_network(self):
        self.setup_nodes()

    def peer_id(self, node, other):
        """The id under which `other` appears in `node`'s getpeerinfo."""
        subver = other.getnetworkinfo()["subversion"]
        return next(p["id"] for p in node.getpeerinfo() if p["subver"] == subver)

    def external(self, node):
        return next(e for e in node.getholepunchinfo()["external"] if e["network"] == "ipv4")

    def punched_peers(self, node):
        return [p for p in node.getpeerinfo() if p["hole_punched"]]

    def run_test(self):
        a, c, b, d = self.nodes

        self.log.info("A and B connect to the coordinator C and to D from their punch ports")
        self.connect_nodes(A, C)
        self.connect_nodes(B, C)
        self.connect_nodes(A, D)
        self.connect_nodes(B, D)
        for node, index in ((a, A), (b, B)):
            self.wait_until(lambda: "address" in self.external(node))
            assert_equal(self.external(node)["address"], f"127.0.0.1:{holepunch_port(index)}")
        c_at_b = self.peer_id(b, c)
        a_at_c = next(p for p in c.getpeerinfo() if p["id"] == self.peer_id(c, a))
        assert_equal(a_at_c["addr"], f"127.0.0.1:{holepunch_port(A)}")
        assert_equal(a_at_c["holepunch_caps"], ["COORDINATOR", "ADVERTISED", "PUNCHPORT"])

        self.log.info("B asks C for a rendezvous with A; C punches both")
        with a.assert_debug_log([f"session with 127.0.0.1:{holepunch_port(B)} started as responder"], timeout=10), \
             b.assert_debug_log([f"session with 127.0.0.1:{holepunch_port(A)} started as initiator (answers our rendezvous)"], timeout=10), \
             c.assert_debug_log(["punch sent to it as initiator"], timeout=10):
            b.holepunchrendezvous(c_at_b, f"127.0.0.1:{holepunch_port(A)}")

        self.log.info("A and B are connected to each other through the punched connection")
        self.wait_until(lambda: len(self.punched_peers(a)) == 1 and self.punched_peers(a)[0]["version"] != 0)
        self.wait_until(lambda: len(self.punched_peers(b)) == 1 and self.punched_peers(b)[0]["version"] != 0)
        at_a = self.punched_peers(a)[0]
        at_b = self.punched_peers(b)[0]
        assert_equal(at_a["inbound"], True)
        assert_equal(at_a["addr"], f"127.0.0.1:{holepunch_port(B)}")
        assert_equal(at_a["addrbind"], f"127.0.0.1:{holepunch_port(A)}")
        assert_equal(at_a["transport_protocol_type"], "v2")
        assert_equal(at_b["inbound"], False)
        assert_equal(at_b["connection_type"], "outbound-full-relay")
        assert_equal(at_b["addr"], f"127.0.0.1:{holepunch_port(A)}")
        assert_equal(at_b["addrbind"], f"127.0.0.1:{holepunch_port(B)}")
        assert_equal(at_b["transport_protocol_type"], "v2")
        assert_equal(at_a["subver"], b.getnetworkinfo()["subversion"])
        assert_equal(at_b["subver"], a.getnetworkinfo()["subversion"])
        assert_equal(a.getholepunchinfo()["sessions"], [])
        assert_equal(b.getholepunchinfo()["sessions"], [])

        self.log.info("C refuses a second request for the same pair within the window")
        with c.assert_debug_log(["a punch was sent to the requester recently"], timeout=10):
            b.holepunchrendezvous(c_at_b, f"127.0.0.1:{holepunch_port(A)}")

        self.log.info("After the window: B's hole punch slot is taken and A refuses a repeat session")
        mocktime = int(time.time()) + 30
        for node in self.nodes:
            node.setmocktime(mocktime)
        with b.assert_debug_log(["the hole punch slot is taken"], timeout=10), \
             a.assert_debug_log(["a session with this address was started recently"], timeout=10):
            b.holepunchrendezvous(c_at_b, f"127.0.0.1:{holepunch_port(A)}")

        self.log.info("The punched connection relays blocks")
        self.disconnect_nodes(A, C)
        self.disconnect_nodes(A, D)
        self.generate(a, 1, sync_fun=lambda: self.sync_blocks([a, b]))


if __name__ == '__main__':
    HolePunchNodesTest(__file__).main()
