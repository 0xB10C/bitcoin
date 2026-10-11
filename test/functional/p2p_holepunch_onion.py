#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test a TCP hole punch coordinated through the advertiser's own onion service.

Three nodes, none connected to each other at the start:
  A (node 0) is the advertiser, with a coordination service set by hand
  (-holepunchcoordonion) since there is no Tor on regtest; B (node 1) the
  connector, whose Tor proxy is a fake SOCKS5 server that redirects the
  onion address to A's coordination bind; D (node 2) relays A's
  announcement to B. Test peers that only report the node's address serve
  as reporting peers, so that A has no coordinator among its peers and
  announces nothing but its onion service.

A announces itself to D, D relays the element to B, B opens a coordination
connection to the onion address, asks A for a rendezvous, A answers with
punch and both connect to each other by TCP simultaneous open. No third
node takes part in the coordination.
"""

from test_framework.p2p import P2PInterface
from test_framework.socks5 import start_socks5_server
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    holepunch_coord_port,
    holepunch_port,
)

A, B, D = 0, 1, 2
ONION = "kpgvmsfpi2usww3uw74pnpj3xbxf3gvxprpq4a5fwq5bws5662wbv3ad.onion"


class ReportingPeer(P2PInterface):
    """A test peer that reports the node's address in version.addr_recv, as a real peer does."""

    def connection_made(self, transport):
        them = transport.get_extra_info("socket").getpeername()
        if self.on_connection_send_msg is not None:
            self.on_connection_send_msg.addrTo.ip = them[0]
            self.on_connection_send_msg.addrTo.port = them[1]
        super().connection_made(transport)


class HolePunchOnionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.extra_args = [[
            "-v2transport=1",
            "-holepunch=1",
            f"-holepunchport={holepunch_port(i)}",
            f"-holepunchcoordbind=127.0.0.1:{holepunch_coord_port(i)}",
        ] for i in range(self.num_nodes)]
        self.extra_args[A].append(f"-holepunchcoordonion={ONION}")
        # B gets no inbound slots, so it never announces itself.
        self.extra_args[B].append("-maxconnections=10")

    def setup_nodes(self):
        def destinations_factory(requested_to_addr, requested_to_port, proxy_client):
            if requested_to_addr != ONION:
                return None
            return {"actual_to_addr": "127.0.0.1", "actual_to_port": holepunch_coord_port(A)}

        self.socks5_server = start_socks5_server(destinations_factory)
        self.extra_args[B].append(f"-onion={self.socks5_server.conf.addr[0]}:{self.socks5_server.conf.addr[1]}")
        super().setup_nodes()

    def setup_network(self):
        self.setup_nodes()

    def external(self, node):
        return next(e for e in node.getholepunchinfo()["external"] if e["network"] == "ipv4")

    def punched_peers(self, node):
        return [p for p in node.getpeerinfo() if p["hole_punched"]]

    def run_test(self):
        a, b, d = self.nodes

        self.log.info("A and B learn their external addresses from two reporting peers each; D is A's peer")
        a.add_outbound_p2p_connection(ReportingPeer(), p2p_idx=0)
        a.add_outbound_p2p_connection(ReportingPeer(), p2p_idx=1)
        b.add_outbound_p2p_connection(ReportingPeer(), p2p_idx=2)
        self.connect_nodes(B, D)
        self.connect_nodes(D, A)
        for node, index in ((a, A), (b, B)):
            self.wait_until(lambda: "address" in self.external(node))
            assert_equal(self.external(node)["address"], f"127.0.0.1:{holepunch_port(index)}")

        self.log.info("A announces its onion service; D relays it; B asks A through the onion; both get punched")
        with a.assert_debug_log(["on our coordination service: punch sent to it as initiator"], timeout=90), \
             b.assert_debug_log([f"opened a coordination connection to {ONION}:18444", "coordination finished"], timeout=90):
            self.wait_until(lambda: len(self.punched_peers(b)) == 1 and self.punched_peers(b)[0]["version"] != 0, timeout=90)
        self.wait_until(lambda: len(self.punched_peers(a)) == 1 and self.punched_peers(a)[0]["version"] != 0)
        assert_equal([p for p in d.getpeerinfo() if p["connection_type"] == "holepunch-coordination"], [])
        assert "rendezvous" not in d.getpeerinfo()[0]["bytesrecv_per_msg"]

        self.log.info("A and B are connected to each other through the punched connection")
        at_a = self.punched_peers(a)[0]
        at_b = self.punched_peers(b)[0]
        assert_equal(at_a["inbound"], True)
        assert_equal(at_a["addr"], f"127.0.0.1:{holepunch_port(B)}")
        assert_equal(at_a["addrbind"], f"127.0.0.1:{holepunch_port(A)}")
        assert_equal(at_b["inbound"], False)
        assert_equal(at_b["connection_type"], "outbound-full-relay")
        assert_equal(at_b["addr"], f"127.0.0.1:{holepunch_port(A)}")
        assert_equal(at_b["addrbind"], f"127.0.0.1:{holepunch_port(B)}")
        assert_equal(at_b["transport_protocol_type"], "v2")
        assert_equal(at_a["subver"], b.getnetworkinfo()["subversion"])
        assert_equal(at_b["subver"], a.getnetworkinfo()["subversion"])

        self.log.info("The coordination connection is gone on both sides")
        self.wait_until(lambda: not [p for p in a.getpeerinfo() + b.getpeerinfo() if p["connection_type"] == "holepunch-coordination"])
        assert_equal(a.getholepunchinfo()["sessions"], [])
        assert_equal(b.getholepunchinfo()["sessions"], [])

        self.log.info("The punched connection relays blocks")
        a.disconnect_p2ps()
        self.disconnect_nodes(D, A)
        self.generate(a, 1, sync_fun=lambda: self.sync_blocks([a, b]))
        self.socks5_server.stop()


if __name__ == '__main__':
    HolePunchOnionTest(__file__).main()
