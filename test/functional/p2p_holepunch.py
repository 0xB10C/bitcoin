#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test TCP hole punching (-holepunch)."""

from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    holepunch_port,
)


class ReportingPeer(P2PInterface):
    """A test peer that reports the node's address in version.addr_recv.

    By default it reports what it sees on the socket, which is what a real
    peer does. A different report can be given to play a lying peer."""

    def __init__(self, report=None):
        super().__init__()
        self.report = report

    def connection_made(self, transport):
        # The version message is prepared before the socket exists; fill in the
        # node's address as seen from this side before it is sent.
        them = transport.get_extra_info("socket").getpeername()
        ip, port = self.report or (them[0], them[1])
        if self.on_connection_send_msg is not None:
            self.on_connection_send_msg.addrTo.ip = ip
            self.on_connection_send_msg.addrTo.port = port
        super().connection_made(transport)


class HolePunchTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[
            "-v2transport=1",
            "-holepunch=1",
            f"-holepunchport={holepunch_port(0)}",
        ]]

    def test_outbound_from_punch_port(self):
        node = self.nodes[0]
        punch_port = holepunch_port(0)

        # For a connection accepted by a test peer, dstport is the node's source port as
        # the peer sees it: the port that version.addr_recv will report back.
        self.log.info("Outbound connections are made from the punch port")
        peer1 = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=0)
        assert_equal(peer1.dstport, punch_port)
        outbound = [p for p in node.getpeerinfo() if not p["inbound"]]
        assert_equal(len(outbound), 1)
        assert_equal(outbound[0]["addrbind"], f"127.0.0.1:{punch_port}")

        self.log.info("Several outbound connections share the punch port")
        peer2 = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=1)
        assert_equal(peer2.dstport, punch_port)

        self.log.info("Inbound connections are not affected")
        node.add_p2p_connection(P2PInterface())
        inbound = [p for p in node.getpeerinfo() if p["inbound"]]
        assert_equal(len(inbound), 1)
        assert inbound[0]["addrbind"] != f"127.0.0.1:{punch_port}"

        node.disconnect_p2ps()

    def external(self, node, network="ipv4"):
        return next(e for e in node.getholepunchinfo()["external"] if e["network"] == network)

    def test_external_address(self):
        node = self.nodes[0]
        punch_port = holepunch_port(0)
        info = node.getholepunchinfo()
        assert_equal(info["enabled"], True)
        assert_equal(info["port"], punch_port)
        assert_equal(self.external(node)["reports"], 0)
        assert "address" not in self.external(node)

        self.log.info("One peer reporting our address is not enough")
        node.add_outbound_p2p_connection(ReportingPeer(), p2p_idx=0)
        assert_equal(self.external(node)["reports"], 1)
        assert "address" not in self.external(node)

        self.log.info("Two peers agreeing on our address yield the external address")
        node.add_outbound_p2p_connection(ReportingPeer(), p2p_idx=1)
        assert_equal(self.external(node)["address"], f"127.0.0.1:{punch_port}")
        assert_equal(self.external(node)["reporters"], 2)

        self.log.info("A single peer reporting a different port is ignored")
        liar1 = node.add_outbound_p2p_connection(ReportingPeer(report=("127.0.0.1", 40001)), p2p_idx=2)
        assert_equal(self.external(node)["address"], f"127.0.0.1:{punch_port}")
        assert_equal(self.external(node)["reports"], 3)
        assert_equal(self.external(node)["conflicting"], False)

        self.log.info("Two peers agreeing on a different port rule out an external address")
        liar2 = node.add_outbound_p2p_connection(ReportingPeer(report=("127.0.0.1", 40001)), p2p_idx=3)
        assert "address" not in self.external(node)
        assert_equal(self.external(node)["conflicting"], True)

        self.log.info("Reports of disconnected peers are dropped")
        liar1.peer_disconnect()
        liar2.peer_disconnect()
        self.wait_until(lambda: self.external(node)["reports"] == 2)
        assert_equal(self.external(node)["address"], f"127.0.0.1:{punch_port}")

        self.log.info("Reports from inbound peers do not count")
        node.add_p2p_connection(ReportingPeer(report=("127.0.0.1", 40001)))
        assert_equal(self.external(node)["reports"], 2)

        node.disconnect_p2ps()
        self.wait_until(lambda: self.external(node)["reports"] == 0)

    def test_options(self):
        node = self.nodes[0]
        self.log.info("-holepunch needs -v2transport")
        self.stop_node(0)
        node.assert_start_raises_init_error(
            ["-holepunch=1", "-v2transport=0"], "Error: -holepunch requires -v2transport")
        node.assert_start_raises_init_error(
            ["-holepunch=1", "-v2transport=1", "-holepunchport=70000"],
            "Error: Invalid port specified in -holepunchport: '70000'")
        self.log.info("Without -holepunch, outbound connections use an ephemeral port")
        self.start_node(0, extra_args=["-v2transport=1"])
        peer = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=0)
        assert peer.dstport != holepunch_port(0)

    def run_test(self):
        self.test_outbound_from_punch_port()
        self.test_external_address()
        self.test_options()


if __name__ == '__main__':
    HolePunchTest(__file__).main()
