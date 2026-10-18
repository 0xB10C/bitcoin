#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Two nodes behind NATs connect to each other by TCP hole punching through boards.

Nodes 0 and 1 are visitors with punch ports, nodes 2 and 3 are boards, and node 4
relays blocks between the visitors over ordinary connections, since a visitor
avoids boards it is otherwise connected to. The visitors are not connected to
each other until the punch."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    holepunch_port,
    p2p_port,
)


class HolePunchNodesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 5
        seeds = [f"-holepunchboardseed=127.0.0.1:{p2p_port(n)}" for n in (2, 3)]
        self.extra_args = [
            ["-v2transport=1", "-holepunch=1", f"-holepunchport={holepunch_port(0)}"] + seeds,
            ["-v2transport=1", "-holepunch=1", f"-holepunchport={holepunch_port(1)}"] + seeds,
            ["-v2transport=1", "-holepunchboard=1"],
            ["-v2transport=1", "-holepunchboard=1"],
            ["-v2transport=1"],
        ]
        # Board connections are opened by the automatic connection logic.
        self.disable_autoconnect = False

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 4)
        self.connect_nodes(1, 4)
        self.sync_all(self.nodes[:2] + self.nodes[4:])

    def family(self, node):
        return node.getholepunchinfo()["families"][0]

    def punched(self, node):
        return [p for p in node.getpeerinfo() if p["hole_punched"]]

    def run_test(self):
        visitors = self.nodes[:2]
        boards = self.nodes[2:4]
        chain = visitors + [self.nodes[4]]
        endpoints = [f"127.0.0.1:{holepunch_port(n)}" for n in range(2)]

        self.log.info("The visitors open board connections and learn their external addresses from the boards")
        for n, visitor in enumerate(visitors):
            self.wait_until(lambda: len(self.family(visitor)["boards"]) == 2)
            self.wait_until(lambda: self.family(visitor).get("address") == endpoints[n])

        self.log.info("Each visitor announces to its boards and learns the other's entry from them")
        for visitor in visitors:
            self.wait_until(lambda: "announced" in self.family(visitor))
            self.wait_until(lambda: visitor.getholepunchinfo()["table"]["entries"] == 1)
        for board in boards:
            assert_equal(board.getholepunchinfo()["board_entries"], {"live": 2, "total": 2})

        self.log.info("The block after the announcements holds no pick, the next one pairs the visitors")
        self.generate(visitors[0], 1, sync_fun=lambda: self.sync_blocks(chain))
        for visitor in visitors:
            assert_equal(visitor.getholepunchinfo()["rounds"]["picks"], 0)
        self.generate(visitors[0], 1, sync_fun=lambda: self.sync_blocks(chain))
        for visitor in visitors:
            self.wait_until(lambda: len(self.punched(visitor)) == 1)
            # The handshake takes a moment: the transport reads "detecting" until the
            # initiator's first bytes have been processed.
            self.wait_until(lambda: self.punched(visitor)[0]["transport_protocol_type"] == "v2")
        peer0, peer1 = self.punched(visitors[0])[0], self.punched(visitors[1])[0]
        assert_equal(peer0["addr"], endpoints[1])
        assert_equal(peer0["addrbind"], endpoints[0])
        assert_equal(peer1["addr"], endpoints[0])
        assert_equal(peer1["addrbind"], endpoints[1])
        # One side is the initiator with an outbound, the other the responder with an inbound.
        assert peer0["inbound"] != peer1["inbound"]
        for peer in (peer0, peer1):
            assert_equal(peer["transport_protocol_type"], "v2")
        for visitor in visitors:
            assert_equal(visitor.getholepunchinfo()["rounds"]["picks"], 1)
            assert_equal(visitor.getholepunchinfo()["table"]["entries"], 0)

        self.log.info("A picked entry is gone: further blocks start no session until the peer announces again")
        visitors[0].disconnectnode(nodeid=peer0["id"])
        for visitor in visitors:
            self.wait_until(lambda: self.punched(visitor) == [])
        self.generate(visitors[0], 2, sync_fun=lambda: self.sync_blocks(chain))
        for visitor in visitors:
            assert_equal(visitor.getholepunchinfo()["rounds"]["picks"], 1)
            assert_equal(self.punched(visitor), [])

        self.log.info("A restarted visitor begins with an empty table")
        self.restart_node(1, extra_args=self.extra_args[1])
        assert_equal(visitors[1].getholepunchinfo()["table"]["entries"], 0)


if __name__ == "__main__":
    HolePunchNodesTest(__file__).main()
