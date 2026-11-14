#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tests for the cached CMPCTBLOCK message (bitcoin#36787).

Run one case at a time:  --case=regress | inconsistent | log | fallback

regress      A peer that fetches the cached block via getdata MSG_CMPCT_BLOCK must
             still receive the NEXT block by headers (low-bandwidth) or by a
             fast-announced cmpctblock (high-bandwidth), never by inv.
             FAILS on PR 36787, passes on master.

inconsistent Two identical low-bandwidth peers each fetch one recent block as a
             compact block; one happens to hit the cache, the other does not.
             Their next announcements must not differ.
             FAILS on PR 36787, passes on master.

log          Serving a getdata MSG_CMPCT_BLOCK to a low-bandwidth peer must not log
             as an announcement ("sending header-and-ids").
             FAILS on PR 36787, passes on master.

fallback     Demonstration for the comment "This is unlikely since it means that we
             have connected another block since vHeaders was assembled": the
             SendMessages fallback is taken for a block that was simply never cached
             (it arrived before its parent), with the tip unchanged throughout.
             Passes on PR 36787 and proves the comment's premise is incomplete
             there; on master the same log line is emitted on both paths, so the
             case is not distinguishing.

Mechanism used by every case: a source peer delivers blocks OUT OF ORDER (child
before parent).  NewPoWValidBlock only caches a block whose parent is the active
tip at AcceptBlock time, so the child is never cached while the parent is.
"""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.messages import (CBlockHeader, CInv, MSG_CMPCT_BLOCK, msg_block,
                                     msg_getdata, msg_getheaders, msg_headers,
                                     msg_sendcmpct, msg_sendheaders)
from test_framework.blocktools import create_block, create_coinbase
from test_framework.util import assert_equal


class Victim(P2PInterface):
    """Passive peer: never announces anything to the node, only records what it is told."""
    def __init__(self, name):
        super().__init__()
        self.name = name
        self.events = []  # ordered (kind, [block hash ints]); appended under p2p_lock

    def on_inv(self, message):  # the base class would auto-getdata; stay passive
        self.events.append(("inv", [x.hash for x in message.inv]))

    def on_headers(self, message):
        self.events.append(("headers", [h.hash_int for h in message.headers]))

    def on_cmpctblock(self, message):
        self.events.append(("cmpctblock", [message.header_and_shortids.header.hash_int]))

    def kinds_for(self, h):  # caller holds p2p_lock (wait_until does)
        return [k for (k, hs) in self.events if h in hs]

    def kinds(self, h):
        with p2p_lock:
            return self.kinds_for(h)

    def fetch_cmpctblock(self, block):
        self.send_and_ping(msg_getdata([CInv(MSG_CMPCT_BLOCK, block.hash_int)]))
        self.wait_until(lambda: "cmpctblock" in self.kinds_for(block.hash_int))


class Source(P2PInterface):
    def __init__(self):
        super().__init__()
        self.getdata_hashes = set()

    def on_getdata(self, message):
        for i in message.inv:
            self.getdata_hashes.add(i.hash)


class CompactBlockCacheTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument("--case", default="all",
                            choices=["all", "regress", "inconsistent", "log", "fallback"])

    def set_test_params(self):
        self.num_nodes = 1

    # ---- helpers -----------------------------------------------------------

    def connect_peers(self, victim_specs):
        """victim_specs: list of (name, high_bandwidth). Returns (source, [victims])."""
        node = self.nodes[0]
        tip_int = int(node.getbestblockhash(), 16)
        src = node.add_p2p_connection(Source())
        victims = []
        for name, hb in victim_specs:
            v = node.add_p2p_connection(Victim(name))
            v.send_and_ping(msg_sendheaders())
            v.send_and_ping(msg_sendcmpct(announce=hb, version=2))
            # getheaders with locator=[tip]: the node replies with empty headers and
            # sets pindexBestHeaderSent = tip, which enables header announcements.
            gh = msg_getheaders()
            gh.locator.vHave = [tip_int]
            gh.hashstop = 0
            v.send_and_ping(gh)
            victims.append(v)
        return src, victims

    def make_chain(self, n):
        node = self.nodes[0]
        prev = int(node.getbestblockhash(), 16)
        height = node.getblockcount()
        t = node.getblockheader(node.getbestblockhash())["time"]
        blocks = []
        for i in range(1, n + 1):
            b = create_block(prev, create_coinbase(height + i), ntime=t + i)
            b.solve()
            blocks.append(b)
            prev = b.hash_int
        return blocks

    def announce(self, src, blocks):
        src.send_and_ping(msg_headers([CBlockHeader(b) for b in blocks]))
        src.wait_until(lambda: {b.hash_int for b in blocks} <= src.getdata_hashes)

    def deliver(self, src, blocks_in_order, expected_tip):
        for b in blocks_in_order[:-1]:
            src.send_without_ping(msg_block(b))
        src.send_and_ping(msg_block(blocks_in_order[-1]))
        assert_equal(self.nodes[0].getbestblockhash(), expected_tip.hash_hex)

    def wait_announced(self, victims, block):
        for v in victims:
            v.wait_until(lambda: v.kinds_for(block.hash_int))

    # ---- cases -------------------------------------------------------------

    def case_regress(self):
        src, (lowbw, hb) = self.connect_peers([("lowbw", False), ("hb", True)])
        b1, b2, b3 = self.make_chain(3)
        self.announce(src, [b1, b2])
        self.deliver(src, [b2, b1], expected_tip=b2)  # b1 cached, b2 is tip
        self.wait_announced([lowbw, hb], b2)
        for v in (lowbw, hb):
            v.fetch_cmpctblock(b1)  # the cached block

        self.announce(src, [b3])
        self.deliver(src, [b3], expected_tip=b3)
        self.wait_announced([lowbw, hb], b3)
        got = {v.name: v.kinds(b3.hash_int) for v in (lowbw, hb)}
        self.log.info(f"next block announced via {got}")
        assert_equal(got["lowbw"], ["headers"])
        assert_equal(got["hb"], ["cmpctblock"])

    def case_inconsistent(self):
        src, (v_cached, v_uncached) = self.connect_peers([("fetches_cached", False), ("fetches_uncached", False)])
        c1, c2, c3, c4 = self.make_chain(4)
        self.announce(src, [c1, c2, c3])
        self.deliver(src, [c1], expected_tip=c1)        # c1 cached
        self.deliver(src, [c3, c2], expected_tip=c3)    # c2 cached (parent was tip), c3 never cached
        self.wait_announced([v_cached, v_uncached], c3)
        v_cached.fetch_cmpctblock(c2)    # served from the cache
        v_uncached.fetch_cmpctblock(c1)  # within MAX_CMPCTBLOCK_DEPTH, served by constructing a fresh cmpctblock

        self.announce(src, [c4])
        self.deliver(src, [c4], expected_tip=c4)
        self.wait_announced([v_cached, v_uncached], c4)
        got = {v.name: v.kinds(c4.hash_int) for v in (v_cached, v_uncached)}
        self.log.info(f"next block announced via {got}")
        assert_equal(got["fetches_uncached"], ["headers"])
        assert_equal(got["fetches_cached"], got["fetches_uncached"])

    def case_log(self):
        node = self.nodes[0]
        src, (lowbw,) = self.connect_peers([("lowbw", False)])
        d1, d2 = self.make_chain(2)
        self.announce(src, [d1, d2])
        self.deliver(src, [d2, d1], expected_tip=d2)
        self.wait_announced([lowbw], d2)
        with node.assert_debug_log(expected_msgs=[], unexpected_msgs=["sending header-and-ids"]):
            lowbw.fetch_cmpctblock(d1)

    def case_fallback(self):
        node = self.nodes[0]
        src, (hb,) = self.connect_peers([("hb", True)])
        e1, e2 = self.make_chain(2)
        self.announce(src, [e1, e2])
        # On PR 36787 "SendMessages sending header-and-ids" is logged ONLY on the fallback path.
        with node.assert_debug_log(expected_msgs=[f"SendMessages sending header-and-ids {e2.hash_hex}"], timeout=10):
            self.deliver(src, [e2, e1], expected_tip=e2)
            self.wait_announced([hb], e2)
        # The tip never moved past e2, so "we have connected another block since
        # vHeaders was assembled" is not why the fallback was taken.
        assert_equal(node.getbestblockhash(), e2.hash_hex)
        assert_equal(hb.kinds(e2.hash_int), ["cmpctblock"])

    def run_test(self):
        self.generate(self.nodes[0], 1)  # leave IBD
        cases = {"regress": self.case_regress, "inconsistent": self.case_inconsistent,
                 "log": self.case_log, "fallback": self.case_fallback}
        for name, fn in cases.items():
            if self.options.case in ("all", name):
                self.log.info(f"=== case: {name} ===")
                fn()
                self.nodes[0].disconnect_p2ps()


if __name__ == "__main__":
    CompactBlockCacheTest(__file__).main()
