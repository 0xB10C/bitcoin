#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test TCP hole punching through boards: options and board connections."""

from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    holepunch_port,
)


class HolePunchTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [
            # A visitor: it opens board connections from its punch port.
            ["-v2transport=1", "-holepunch=1", f"-holepunchport={holepunch_port(0)}"],
            # A board.
            ["-v2transport=1", "-holepunchboard=1"],
        ]

    def setup_network(self):
        self.setup_nodes()

    def test_options(self):
        self.log.info("Bad options are refused at startup")
        node = self.nodes[0]
        self.stop_node(0)
        node.assert_start_raises_init_error(
            ["-holepunch=1", "-v2transport=0"],
            "Error: -holepunch requires -v2transport")
        node.assert_start_raises_init_error(
            ["-v2transport=1", "-holepunch=1", "-holepunchport=70000"],
            "Error: Invalid port specified in -holepunchport: '70000'")
        node.assert_start_raises_init_error(
            ["-v2transport=1", "-holepunch=1", "-holepunchport=22"],
            "Error: Port 22 in -holepunchport is one other nodes refuse to connect to, choose another")
        node.assert_start_raises_init_error(
            ["-holepunchboard=1", "-v2transport=0"],
            "Error: -holepunchboard requires -v2transport")
        node.assert_start_raises_init_error(
            ["-v2transport=1", "-holepunchboard=1", "-listen=0"],
            "Error: -holepunchboard requires -listen")
        self.start_node(0)

        self.log.info("A board advertises the service bit, a visitor does not")
        assert "HOLEPUNCH_BOARD" not in self.nodes[0].getnetworkinfo()["localservicesnames"]
        assert "HOLEPUNCH_BOARD" in self.nodes[1].getnetworkinfo()["localservicesnames"]

    def test_board_connection_port(self):
        node = self.nodes[0]
        punch_port = holepunch_port(0)

        # For a connection accepted by a test peer, dstport is the node's source port as
        # the peer sees it: the port that version.addr_recv will report back.
        self.log.info("Board connections are made from the punch port")
        board = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=0, connection_type="holepunch-board")
        assert_equal(board.dstport, punch_port)
        peers = node.getpeerinfo()
        assert_equal(len(peers), 1)
        assert_equal(peers[0]["connection_type"], "holepunch-board")
        assert_equal(peers[0]["addrbind"], f"127.0.0.1:{punch_port}")

        self.log.info("Ordinary outbound connections are not")
        full = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=1)
        assert full.dstport != punch_port

        self.log.info("Several board connections share the punch port")
        board2 = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=2, connection_type="holepunch-board")
        assert_equal(board2.dstport, punch_port)
        assert_equal(len([p for p in node.getpeerinfo() if p["connection_type"] == "holepunch-board"]), 2)

        node.disconnect_p2ps()

    def run_test(self):
        self.test_options()
        self.test_board_connection_port()


if __name__ == '__main__':
    HolePunchTest(__file__).main()
