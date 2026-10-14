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

    def test_options(self):
        node = self.nodes[0]
        self.log.info("-holepunch needs -v2transport and a usable port")
        self.stop_node(0)
        node.assert_start_raises_init_error(
            ["-holepunch=1", "-v2transport=0"], "Error: -holepunch requires -v2transport")
        node.assert_start_raises_init_error(
            ["-holepunch=1", "-v2transport=1", "-holepunchport=70000"],
            "Error: Invalid port specified in -holepunchport: '70000'")
        node.assert_start_raises_init_error(
            ["-holepunch=1", "-v2transport=1", "-holepunchport=22"],
            "Error: Port 22 in -holepunchport is one other nodes refuse to connect to, choose another")

        self.log.info("Without -holepunchport, a random port is chosen")
        with node.assert_debug_log(["Hole punching enabled, punch port "]):
            self.start_node(0, extra_args=["-v2transport=1", "-holepunch=1"])
        peer = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=0)
        assert 49152 <= peer.dstport <= 65535
        node.disconnect_p2ps()

        self.log.info("Without -holepunch, outbound connections use an ephemeral port")
        self.restart_node(0, extra_args=["-v2transport=1"])
        peer = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=0)
        assert peer.dstport != holepunch_port(0)

    def run_test(self):
        self.test_outbound_from_punch_port()
        self.test_options()


if __name__ == '__main__':
    HolePunchTest(__file__).main()
