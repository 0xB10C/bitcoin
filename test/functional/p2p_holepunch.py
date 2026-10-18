#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test TCP hole punching through boards: options, board connections and the feature exchange."""

from test_framework.messages import msg_feature
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    holepunch_port,
)

HOLEPUNCH_FEATURE_ID = "https://delvingbitcoin.org/t/2497/22"
FLAG_BOARD = 1 << 0
FLAG_VISITOR = 1 << 1


def feature_data(flags, version=0):
    return version.to_bytes(1, "little") + flags.to_bytes(4, "little")


class HolePunchPeer(P2PInterface):
    """A test peer that sends the hole punching feature with `flags` before verack, or nothing if None.
    `data` replaces the feature payload, to send a malformed one."""

    def __init__(self, flags=None, data=None):
        super().__init__()
        self.flags = flags
        self.data = data
        self.features = []

    def peer_connect_send_version(self, services):
        super().peer_connect_send_version(services)
        # A visitor's version has transaction relay disabled (R-3.5). The other test
        # peers do the same, so that the cap on tx-relaying inbound peers stays out
        # of the way when inbound slots are counted.
        self.on_connection_send_msg.relay = 0

    def on_feature(self, message):
        self.features.append(message)

    def on_version(self, message):
        # Our version has to go out before the feature. P2PInterface sends it in
        # on_version for accepted connections; doing it here first makes its own
        # call a no-op.
        if not self.p2p_connected_to_node:
            self.send_version()
        if self.data is not None:
            self.send_without_ping(msg_feature(HOLEPUNCH_FEATURE_ID, self.data))
        elif self.flags is not None:
            self.send_without_ping(msg_feature(HOLEPUNCH_FEATURE_ID, feature_data(self.flags)))
        super().on_version(message)

    def holepunch_flags(self):
        """The flags the node sent in its hole punching feature, None if it sent none."""
        for m in self.features:
            if m.feature_id == HOLEPUNCH_FEATURE_ID:
                return int.from_bytes(m.feature_data[1:5], "little")
        return None


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
        board = node.add_outbound_p2p_connection(HolePunchPeer(flags=FLAG_BOARD), p2p_idx=0, connection_type="holepunch-board")
        assert_equal(board.dstport, punch_port)
        peers = node.getpeerinfo()
        assert_equal(len(peers), 1)
        assert_equal(peers[0]["connection_type"], "holepunch-board")
        assert_equal(peers[0]["addrbind"], f"127.0.0.1:{punch_port}")

        self.log.info("Ordinary outbound connections are not")
        full = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=1)
        assert full.dstport != punch_port

        self.log.info("Several board connections share the punch port")
        board2 = node.add_outbound_p2p_connection(HolePunchPeer(flags=FLAG_BOARD), p2p_idx=2, connection_type="holepunch-board")
        assert_equal(board2.dstport, punch_port)
        assert_equal(len([p for p in node.getpeerinfo() if p["connection_type"] == "holepunch-board"]), 2)

        node.disconnect_p2ps()

    def test_feature_exchange(self):
        visitor, board = self.nodes

        self.log.info("A visitor sends VISITOR on a board connection and keeps it when the board answers BOARD")
        peer = visitor.add_outbound_p2p_connection(HolePunchPeer(flags=FLAG_BOARD), p2p_idx=0, connection_type="holepunch-board")
        assert_equal(peer.holepunch_flags(), FLAG_VISITOR)
        assert_equal(visitor.getpeerinfo()[0]["holepunch_flags"], ["BOARD"])
        visitor.disconnect_p2ps()

        self.log.info("A visitor closes a board connection whose peer does not answer BOARD")
        for flags in [None, 0, FLAG_VISITOR]:
            peer = visitor.add_outbound_p2p_connection(HolePunchPeer(flags=flags), p2p_idx=0, connection_type="holepunch-board", wait_for_disconnect=True)
            assert_equal(peer.holepunch_flags(), FLAG_VISITOR)

        self.log.info("A visitor sends no feature on an ordinary outbound connection")
        peer = visitor.add_outbound_p2p_connection(HolePunchPeer(flags=FLAG_BOARD), p2p_idx=0)
        assert_equal(peer.holepunch_flags(), None)
        assert_equal(visitor.getpeerinfo()[0]["holepunch_flags"], ["BOARD"])
        visitor.disconnect_p2ps()

        self.log.info("A board answers BOARD to a visitor, and sends it on every other connection too")
        peer = board.add_p2p_connection(HolePunchPeer(flags=FLAG_VISITOR))
        assert_equal(peer.holepunch_flags(), FLAG_BOARD)
        assert_equal(board.getpeerinfo()[0]["holepunch_flags"], ["VISITOR"])
        peer2 = board.add_p2p_connection(HolePunchPeer(flags=None))
        assert_equal(peer2.holepunch_flags(), FLAG_BOARD)
        assert_equal(board.getpeerinfo()[1]["holepunch_flags"], [])
        board.disconnect_p2ps()

        self.log.info("Malformed feature data disconnects")
        peer = board.add_p2p_connection(HolePunchPeer(data=b"\x00\x01"), wait_for_verack=False)
        peer.wait_for_disconnect()

    def test_visitors_outside_inbound_limit(self):
        board = self.nodes[1]
        self.log.info("Visitors do not take inbound slots at a board")
        # Room for two inbound connections next to the automatic outbound ones.
        self.restart_node(1, extra_args=self.extra_args[1] + ["-maxconnections=13"])
        for _ in range(2):
            board.add_p2p_connection(HolePunchPeer(flags=FLAG_VISITOR))
        for _ in range(2):
            board.add_p2p_connection(HolePunchPeer(flags=None))
        assert_equal(len(board.getpeerinfo()), 4)
        # The inbound slots are full now: the next ordinary connection is dropped,
        # and the visitors are not evicted to make room.
        board.add_p2p_connection(HolePunchPeer(flags=None), wait_for_verack=False, expect_success=False)
        assert_equal(len(board.getpeerinfo()), 4)
        assert_equal(len([p for p in board.getpeerinfo() if p["holepunch_flags"] == ["VISITOR"]]), 2)
        board.disconnect_p2ps()

    def run_test(self):
        self.test_options()
        self.test_board_connection_port()
        self.test_feature_exchange()
        self.test_visitors_outside_inbound_limit()


if __name__ == '__main__':
    HolePunchTest(__file__).main()
