#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test TCP hole punching (-holepunch and the holepunch RPC)."""

from concurrent.futures import ThreadPoolExecutor

from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    holepunch_port,
)


class HolePunchTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [[
            "-v2transport=1",
            "-holepunch=1",
            f"-holepunchport={holepunch_port(i)}",
        ] for i in range(self.num_nodes)]

    def setup_network(self):
        # The nodes start unconnected: the test connects them by hole punching.
        self.setup_nodes()

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

    def test_punch(self):
        node0, node1 = self.nodes
        addr0 = f"127.0.0.1:{holepunch_port(0)}"
        addr1 = f"127.0.0.1:{holepunch_port(1)}"

        self.log.info("Two nodes punching to each other at the same time connect")
        with ThreadPoolExecutor(max_workers=2) as pool:
            punch0 = pool.submit(node0.holepunch, addr1, "outbound", 20)
            punch1 = pool.submit(node1.holepunch, addr0, "inbound", 20)
            result0 = punch0.result()
            result1 = punch1.result()
        assert_equal(result0["address"], addr1)
        assert_equal(result0["role"], "outbound")
        assert_equal(result1["address"], addr0)
        assert_equal(result1["role"], "inbound")
        assert result0["attempts"] >= 1
        assert result1["attempts"] >= 1

        self.log.info("The connection is a manual outbound on one side and an inbound on the other")
        self.wait_until(lambda: node0.getpeerinfo()[0]["version"] != 0 and node1.getpeerinfo()[0]["version"] != 0)
        peer_of_0 = node0.getpeerinfo()
        peer_of_1 = node1.getpeerinfo()
        assert_equal(len(peer_of_0), 1)
        assert_equal(len(peer_of_1), 1)
        assert_equal(peer_of_0[0]["id"], result0["id"])
        assert_equal(peer_of_1[0]["id"], result1["id"])
        assert_equal(peer_of_0[0]["inbound"], False)
        assert_equal(peer_of_0[0]["connection_type"], "manual")
        assert_equal(peer_of_0[0]["hole_punched"], True)
        assert_equal(peer_of_0[0]["addr"], addr1)
        assert_equal(peer_of_0[0]["addrbind"], addr0)
        assert_equal(peer_of_0[0]["transport_protocol_type"], "v2")
        assert_equal(peer_of_1[0]["inbound"], True)
        assert_equal(peer_of_1[0]["connection_type"], "inbound")
        assert_equal(peer_of_1[0]["hole_punched"], True)
        assert_equal(peer_of_1[0]["addr"], addr0)
        assert_equal(peer_of_1[0]["addrbind"], addr1)
        assert_equal(peer_of_1[0]["transport_protocol_type"], "v2")

        self.log.info("The connection works: blocks are relayed over it")
        self.generate(node0, 1, sync_fun=lambda: self.sync_blocks(self.nodes))

        self.log.info("A punch to a node we are connected to is refused")
        assert_raises_rpc_error(-1, "already connected to this address", node0.holepunch, addr1, "outbound", 5)

        self.disconnect_nodes(0, 1)
        assert_equal(node0.getpeerinfo(), [])
        assert_equal(node1.getpeerinfo(), [])

    def test_errors(self):
        node0 = self.nodes[0]
        addr1 = f"127.0.0.1:{holepunch_port(1)}"

        self.log.info("Bad arguments are rejected")
        assert_raises_rpc_error(-5, "Address must be an IP address with a port", node0.holepunch, "127.0.0.1", "outbound")
        assert_raises_rpc_error(-5, "Address must be an IP address with a port", node0.holepunch, "example.com:8333", "outbound")
        assert_raises_rpc_error(-8, 'Role must be "outbound" or "inbound"', node0.holepunch, addr1, "sideways")
        assert_raises_rpc_error(-8, "Timeout must be between 1 and 600 seconds", node0.holepunch, addr1, "outbound", 0)

        self.log.info("A punch nobody answers fails when the time is up")
        with node0.assert_debug_log(["punching to " + addr1, "attempt 1 to " + addr1, "failed: no connection within 1000 ms"]):
            assert_raises_rpc_error(-1, "no connection within 1000 ms after", node0.holepunch, addr1, "outbound", 1)

        self.log.info("Only one punch runs at a time")
        # A second RPC connection, since the first one is busy with the blocking call.
        other_connection = node0.create_new_rpc_connection()
        started = "Hole punching to " + addr1
        punches_so_far = node0.debug_log_path.read_text().count(started)
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(other_connection.holepunch, addr1, "outbound", 3)
            self.wait_until(lambda: node0.debug_log_path.read_text().count(started) > punches_so_far)
            assert_raises_rpc_error(-1, "a hole punch is in progress", node0.holepunch, "127.0.0.1:1", "inbound", 1)
            assert_raises_rpc_error(-1, "no connection within 3000 ms", first.result)

        self.log.info("Without -holepunch, the RPC is refused")
        self.restart_node(0, extra_args=["-v2transport=1"])
        assert_raises_rpc_error(-1, "hole punching is off, start with -holepunch=1", node0.holepunch, addr1, "outbound", 1)

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
        self.test_punch()
        self.test_errors()
        self.test_options()


if __name__ == '__main__':
    HolePunchTest(__file__).main()
