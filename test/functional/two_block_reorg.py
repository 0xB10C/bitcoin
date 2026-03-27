#!/usr/bin/env python3
# Copyright (c) 2022-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
""" Shows what nodes consider the tip during a two block fork where miners use preciousblock.

This is meant to explain the network behavior seen in:
https://bnoc.xyz/t/two-block-reorg-at-height-941880/97

- The two Foundry blocks didn't propagate well as they weren't seen first (here F881 and F882)
- Only a few nodes announced the Foundry blocks F881 and F882, but the headers weren't realyed
- The AntPool and ViaBTC blocks did propagate well as they were seen first
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.blocktools import create_block
from test_framework.util import assert_equal

class TwoBlockReorg(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4

    def setup_network(self):
        self.setup_nodes()
        # Construct a network:
        # minerA -> node1 <-> node2 <- minerF
        # node1 is connected to minerA and node2
        # node2 is connected to minerF and node1
        #
        # minerA to node1
        self.connect_nodes(0, 1)
        # node1 to node2 and node2 to node1
        self.connect_nodes(1, 2)
        self.connect_nodes(2, 1)
        # minerF to node2
        self.connect_nodes(3, 2)

    def run_test(self):
        minerA = self.nodes[0]
        node1 = self.nodes[1]
        node2 = self.nodes[2]
        minerF = self.nodes[3]

        self.log.info("Setup network: minerA -> node1 <-> node2 <- minerF")
        self.log.info("Mining one block on node1 and verify all nodes sync")

        # generate verify's that all nodes are in sync under the hood
        self.generate(node1, 880)
        # We start of at height 880. G is the Genesis block.
        #  G - ... -  880

        assert_equal(node1.getblockcount(), 880)
        assert_equal(node1.getblockcount(), node2.getblockcount())
        assert_equal(node1.getblockcount(), minerA.getblockcount())
        assert_equal(minerF.getblockcount(), minerA.getblockcount())

        self.log.info("minerF starts working on a block block F881")
        blockF881 = create_block(
            hashprev=int(node1.getbestblockhash(), 16),
            tmpl={"height": 881}
        )

        self.log.info("however, minerA beats it and publishes a block A881 and everybody sees it")
        self.generate(minerA, 1)

        #   G ... -- 880 -- A881
        #                     ^: minerA, minerF, node1, node2
        assert_equal(node1.getblockcount(), 881)
        assert_equal(node1.getblockcount(), node2.getblockcount())
        assert_equal(node1.getblockcount(), minerA.getblockcount())
        assert_equal(minerF.getblockcount(), minerA.getblockcount())

        self.log.info("minerF finds the block F881, publishes it, and switches to it")
        blockF881.solve()
        minerF.submitblock(blockF881.serialize().hex())
        # minerF is still on the minerA block, as it heard about this one first
        assert_equal(minerF.getbestblockhash(), minerA.getbestblockhash())
        minerF.preciousblock(blockF881.hash_hex)
        assert_equal(minerF.getbestblockhash(), blockF881.hash_hex)

        # We now have a fork.
        #                   v: minerF
        #             /- F881
        #  G .. -- 880
        #             \- A881
        #                   ^: minerA, node1, node2

        self.log.info("Only node2, who is directly connected to minerF, has seen F881. It did not relay the header/block to node1")
        chaintips_node1 = node1.getchaintips()
        chaintips_node2 = node2.getchaintips()
        assert_equal(len(chaintips_node2), 2)
        for tip in chaintips_node2:
            if tip["status"] == "active":
                assert_equal(tip["hash"], minerA.getbestblockhash())
            elif tip["status"] == "headers-only":
                assert_equal(tip["hash"], blockF881.hash_hex)

        assert_equal(len(chaintips_node1), 1)
        assert_equal(chaintips_node1[0]["hash"], minerA.getbestblockhash())


        self.log.info("Our node1 node is still on the A881 block, as it saw this one first")
        assert_equal(node1.getbestblockhash(), minerA.getbestblockhash())

        self.log.info("Again, minerF starts mining on a block F882")
        blockF882 = create_block(
            hashprev=int(minerF.getbestblockhash(), 16),
            tmpl={"height": 882}
        )

        self.log.info("minerA finds block A882. node1 and minerF switch to it")
        self.generate(minerA, 1)
        #
        #             /- F881
        #  G .. -- 880
        #             \- A881 - A882
        #                          ^: minerA, minerF, node1
        assert_equal(node1.getbestblockhash(), minerA.getbestblockhash())
        assert_equal(minerF.getbestblockhash(), minerA.getbestblockhash())

        self.log.info("minerF finds block F882, publishes it, and switches to it")
        blockF882.solve()
        minerF.submitblock(blockF882.serialize().hex())
        # minerF is still on the minerA block, as it heard about this one first
        assert_equal(minerF.getbestblockhash(), minerA.getbestblockhash())
        minerF.preciousblock(blockF882.hash_hex)
        assert_equal(minerF.getbestblockhash(), blockF882.hash_hex)

        # We now have a two block fork.
        #                          v: minerF
        #             /- F881 - F882
        #  G .. -- 880
        #             \- A881 - A882
        #                          ^: minerA, node1

        self.log.info("Only node2, who is directly connected to minerF, has seen F882. It did not relay the header/block to node1")
        chaintips_node1 = node1.getchaintips()
        chaintips_node2 = node2.getchaintips()
        assert_equal(len(chaintips_node2), 2)
        for tip in chaintips_node2:
            if tip["status"] == "active":
                assert_equal(tip["hash"], minerA.getbestblockhash())
            elif tip["status"] == "headers-only":
                assert_equal(tip["hash"], blockF882.hash_hex)

        assert_equal(len(chaintips_node1), 1)
        assert_equal(chaintips_node1[0]["hash"], minerA.getbestblockhash())

        self.log.info("minerF finds block F883, causing a two block reorg")
        self.generate(minerF, 1)

        #                                 v: minerF, minerA, node1
        #             /- F881 - F882 - F883
        #  G .. -- 880
        #             \- A881 - A882
        #
        assert_equal(node1.getbestblockhash(), minerA.getbestblockhash())
        assert_equal(minerF.getbestblockhash(), minerA.getbestblockhash())

        self.log.info("minerF wins the fork race")


if __name__ == '__main__':
    TwoBlockReorg(__file__).main()
