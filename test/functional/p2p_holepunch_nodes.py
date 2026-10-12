#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test a TCP hole punch between real nodes.

Five nodes, none connected to each other at the start:
  A (node 0) is the advertiser, C (node 1) the coordinator, B (node 2) the
  connector, D (node 3) a second peer for A and B, so that both learn their
  external address from two reporting peers, and E (node 4) a second
  connector that has no connection to C.

A and B connect to C from their punch ports; C sees them at those ports and
they announce ADVERTISED and PUNCHPORT. A announces itself through C, C
relays the announcement to B, B asks C for a rendezvous with A's endpoint,
C sends punch to both, and they connect to each other by TCP simultaneous
open. The result is an inbound peer at A and a hole-punched outbound peer
at B that relays blocks like any other peer. The limits are then checked
with the manual rendezvous RPC. E then connects to A and D, gets A's
announcement, and has to open a coordination connection to C to ask for
its rendezvous.
"""

import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    holepunch_coord_port,
    holepunch_port,
    p2p_port,
)

A, C, B, D, E = 0, 1, 2, 3, 4


class HolePunchNodesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 5
        self.extra_args = [[
            "-v2transport=1",
            "-holepunch=1",
            f"-holepunchport={holepunch_port(i)}",
            f"-holepunchcoordbind=127.0.0.1:{holepunch_coord_port(i)}",
        ] for i in range(self.num_nodes)]
        # B and E get no inbound slots, so they never announce themselves and
        # the punches always go to A.
        self.extra_args[B].append("-maxconnections=10")
        self.extra_args[E].append("-maxconnections=10")

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
        a, c, b, d, e = self.nodes

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

        self.log.info("Without Tor there is no coordination service")
        assert_equal(a.getholepunchinfo()["coordination"], {"bind": f"127.0.0.1:{holepunch_coord_port(A)}"})

        self.log.info("A announces itself through C; C relays it to B; B asks C; both get punched")
        with c.assert_debug_log(["punch sent to it as initiator"], timeout=90):
            self.wait_until(lambda: len(self.punched_peers(b)) == 1 and self.punched_peers(b)[0]["version"] != 0, timeout=90)
        self.wait_until(lambda: len(self.punched_peers(a)) == 1 and self.punched_peers(a)[0]["version"] != 0)

        self.log.info("A and B are connected to each other through the punched connection")
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
        with c.assert_debug_log(["ignoring rendezvous from peer=", "recently"], timeout=10):
            b.holepunchrendezvous(c_at_b, f"127.0.0.1:{holepunch_port(A)}")

        self.log.info("After the window: B's hole punch slot is taken and A refuses a repeat session")
        mocktime = int(time.time()) + 30
        for node in self.nodes:
            node.setmocktime(mocktime)
        with b.assert_debug_log(["the hole punch slot is taken"], timeout=10), \
             a.assert_debug_log(["a session with this address was started recently"], timeout=10):
            b.holepunchrendezvous(c_at_b, f"127.0.0.1:{holepunch_port(A)}")

        self.log.info("E connects to A and D, and gets A's announcement; it has no connection to C")
        # Past the window of the punch C just sent to A.
        mocktime += 30
        for node in self.nodes:
            node.setmocktime(mocktime)
        self.connect_nodes(E, A)
        self.connect_nodes(E, D)
        self.wait_until(lambda: "address" in self.external(e))
        assert_equal(self.external(e)["address"], f"127.0.0.1:{holepunch_port(E)}")
        assert_equal([p["id"] for p in e.getpeerinfo() if p["subver"] == c.getnetworkinfo()["subversion"]], [])

        self.log.info("E opens a coordination connection to C, which treats it as an ordinary peer, and gets punched")
        coordinator = f"127.0.0.1:{p2p_port(C)}"
        with e.assert_debug_log([f"opening a coordination connection to {coordinator}", "ignoring getheaders on the coordination connection", "answers our rendezvous"], timeout=90):
            self.wait_until(lambda: len(self.punched_peers(e)) == 1 and self.punched_peers(e)[0]["version"] != 0, timeout=90)
        self.wait_until(lambda: len(self.punched_peers(a)) == 2)
        at_e = self.punched_peers(e)[0]
        assert_equal(at_e["addr"], f"127.0.0.1:{holepunch_port(A)}")
        assert_equal(at_e["addrbind"], f"127.0.0.1:{holepunch_port(E)}")
        assert_equal(at_e["connection_type"], "outbound-full-relay")
        coordination = [p for p in e.getpeerinfo() if p["connection_type"] == "holepunch-coordination"]
        assert_equal([p["addr"] for p in coordination], [coordinator])
        assert_equal(coordination[0]["holepunch_caps"], ["COORDINATOR"])
        assert_equal(coordination[0]["addrbind"], f"127.0.0.1:{holepunch_port(E)}")
        # A, D and the punched connection; the coordination connection is not counted.
        assert_equal(e.getnetworkinfo()["connections_out"], 3)

        self.log.info("The coordination connection is kept through the punch window and closed after it")
        mocktime += 20
        with e.assert_debug_log(["punch window over"], timeout=10):
            for node in self.nodes:
                node.setmocktime(mocktime)
            self.wait_until(lambda: not [p for p in e.getpeerinfo() if p["connection_type"] == "holepunch-coordination"])

        self.log.info("The counters add up")
        counters = {n: node.getholepunchinfo()["counters"] for n, node in zip("acbde", self.nodes)}
        assert_equal(counters["a"]["sessions"]["responder"], {"started": 2, "established": 2, "failed": 0})
        assert_equal(counters["b"]["sessions"]["initiator"], {"started": 1, "established": 1, "failed": 0})
        assert_equal(counters["e"]["sessions"]["initiator"], {"started": 1, "established": 1, "failed": 0})
        assert_equal(counters["b"]["rendezvous_sent"], 3)  # one by the connector, two by hand
        assert_equal(counters["c"]["rendezvous_answered"], 3)
        assert_equal(counters["c"]["rendezvous_rejected"], 1)
        assert_equal(counters["a"]["punches_accepted"], 2)
        assert_equal(counters["a"]["punches_rejected"], 1)
        assert_equal(counters["b"]["punches_rejected"], 1)
        assert_equal(counters["e"]["coordination_opened"], 1)
        assert counters["a"]["announcements_sent"] >= 2
        assert counters["b"]["announcements_received"] >= 1

        self.log.info("The punched connection relays blocks")
        self.disconnect_nodes(A, C)
        self.disconnect_nodes(A, D)
        # Only the regular connection from E to A, not the punched one.
        a_subver = a.getnetworkinfo()["subversion"]
        e.disconnectnode(nodeid=next(p["id"] for p in e.getpeerinfo() if p["subver"] == a_subver and not p["hole_punched"]))
        self.wait_until(lambda: len([p for p in e.getpeerinfo() if p["subver"] == a_subver]) == 1)
        self.disconnect_nodes(E, D)
        self.generate(a, 1, sync_fun=lambda: self.sync_blocks([a, b, e]))


if __name__ == '__main__':
    HolePunchNodesTest(__file__).main()
