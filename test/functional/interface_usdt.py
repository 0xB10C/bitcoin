#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

""" Userspace, Statically Defined Tracing interface tests

The goal of these tests is to test the tracepoint interface. That means, the
we test that the tracepoints are reached and that the expected arguments are
passed. This should ensure a semi-stable API. The API can change between
releases as implementation details and tracepoint argument avaliablility
changes. However, it shouldn't change through, for example, unrelated
refactoring.

"""

import ctypes

from bcc import BPF, USDT
from io import BytesIO
from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.blocktools import get_legacy_sigopcount_tx
from test_framework.messages import msg_version, msg_ping, msg_pong
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

net_tracepoints_program = """
#include <uapi/linux/ptrace.h>

// Tor v3 addresses are 62 chars + 6 chars for the port (':12345').
#define MAX_PEER_ADDR_LENGTH 62 + 6
#define MAX_PEER_CONN_TYPE_LENGTH 20
#define MAX_MSG_TYPE_LENGTH 20
// We don't read any msg larger than 120 byte in this test. For reading
// larger messages see contrib/tracing/log_raw_p2p_msgs.py
#define MAX_MSG_DATA_LENGTH 300

# define MIN(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })

struct p2p_message
{
    u64     peer_id;
    char    peer_addr[MAX_PEER_ADDR_LENGTH];
    char    peer_conn_type[MAX_PEER_CONN_TYPE_LENGTH];
    char    msg_type[MAX_MSG_TYPE_LENGTH];
    u64     msg_size;
    u8      msg[MAX_MSG_DATA_LENGTH];
};

BPF_PERF_OUTPUT(inbound_messages);
int trace_inbound_message(struct pt_regs *ctx) {
    struct p2p_message msg = {};
    bpf_usdt_readarg(1, ctx, &msg.peer_id);
    bpf_usdt_readarg_p(2, ctx, &msg.peer_addr, MAX_PEER_ADDR_LENGTH);
    bpf_usdt_readarg_p(3, ctx, &msg.peer_conn_type, MAX_PEER_CONN_TYPE_LENGTH);
    bpf_usdt_readarg_p(4, ctx, &msg.msg_type, MAX_MSG_TYPE_LENGTH);
    bpf_usdt_readarg(5, ctx, &msg.msg_size);
    bpf_usdt_readarg_p(6, ctx, &msg.msg, MIN(msg.msg_size, MAX_MSG_DATA_LENGTH));
    inbound_messages.perf_submit(ctx, &msg, sizeof(msg));
    return 0;
}

BPF_PERF_OUTPUT(outbound_messages);
int trace_outbound_message(struct pt_regs *ctx) {
    struct p2p_message msg = {};
    bpf_usdt_readarg(1, ctx, &msg.peer_id);
    bpf_usdt_readarg_p(2, ctx, &msg.peer_addr, MAX_PEER_ADDR_LENGTH);
    bpf_usdt_readarg_p(3, ctx, &msg.peer_conn_type, MAX_PEER_CONN_TYPE_LENGTH);
    bpf_usdt_readarg_p(4, ctx, &msg.msg_type, MAX_MSG_TYPE_LENGTH);
    bpf_usdt_readarg(5, ctx, &msg.msg_size);
    bpf_usdt_readarg_p(6, ctx, &msg.msg, MIN(msg.msg_size, MAX_MSG_DATA_LENGTH));
    outbound_messages.perf_submit(ctx, &msg, sizeof(msg));
    return 0;
};

"""


validation_blockconnected_program = """
#include <uapi/linux/ptrace.h>

struct connected_block
{
    char        hash[32];
    int         height;
    long    transactions;
    int         inputs;
    long    sigops;
    u64         duration;
};

BPF_PERF_OUTPUT(block_connected);
int trace_block_connected(struct pt_regs *ctx) {
    struct connected_block block = {};
    bpf_usdt_readarg_p(1, ctx, &block.hash, 32);
    bpf_usdt_readarg(2, ctx, &block.height);
    bpf_usdt_readarg(3, ctx, &block.transactions);
    bpf_usdt_readarg(4, ctx, &block.inputs);
    bpf_usdt_readarg(5, ctx, &block.sigops);
    bpf_usdt_readarg(6, ctx, &block.duration);
    block_connected.perf_submit(ctx, &block, sizeof(block));
    return 0;
}
"""


class TracepointTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        # TODO: check that we are on Linux
        self.skip_if_no_python_bcc()
        self.skip_if_no_bitcoind_tracepoints()
        # TODO: check that we have the right privileges (is that possible? maybe load a bpf map..)

    def run_test(self):
        self.net_message_tracepoint_tests()
        self.validation_blockconnected_tracepoint_tests()

    def net_message_tracepoint_tests(self):
        """ tests the net:inbound_message and net:outbound_message tracepoints
            See https://github.com/bitcoin/bitcoin/blob/master/doc/tracing.md#context-net
        """
        checked_inbound_version_msg = False
        checked_outbound_version_msg = False

        ctx = USDT(path=str(self.options.bitcoind))
        ctx.enable_probe(probe="inbound_message", fn_name="trace_inbound_message")
        ctx.enable_probe(probe="outbound_message", fn_name="trace_outbound_message")
        bpf = BPF(text=net_tracepoints_program, usdt_contexts=[ctx], debug=0)

        def check_p2p_message(event, inbound):
            nonlocal checked_inbound_version_msg, checked_outbound_version_msg
            if event.msg_type.decode("utf-8") == "version":
                peer = self.nodes[0].getpeerinfo()[0]
                msg = msg_version()
                msg.deserialize(BytesIO(bytes(event.msg[:event.msg_size])))
                assert_equal(event.peer_addr.decode("utf-8"), peer["addr"])
                assert_equal(event.peer_id, peer["id"])
                assert_equal(event.peer_conn_type.decode("utf-8"), peer["connection_type"])
                if inbound:
                    checked_inbound_version_msg = True
                else:
                    checked_outbound_version_msg = True
            else:
                pass

        def handle_inbound(_, data, __):
            event = bpf["inbound_messages"].event(data)
            check_p2p_message(event, True)

        def handle_outbound(_, data, __):
            event = bpf["outbound_messages"].event(data)
            check_p2p_message(event, False)

        bpf["inbound_messages"].open_perf_buffer(handle_inbound)
        bpf["outbound_messages"].open_perf_buffer(handle_outbound)

        test_node = P2PInterface()
        self.nodes[0].add_p2p_connection(test_node)
        bpf.perf_buffer_poll(timeout=200)

        assert(checked_inbound_version_msg)
        assert(checked_outbound_version_msg)

        bpf.cleanup()

    def validation_blockconnected_tracepoint_tests(self):
        """ Tests the validation:block_connected tracepoint by generating blocks
            and comparing the values passed in the tracepoint arguments with the
            blocks.

            See https://github.com/bitcoin/bitcoin/blob/master/doc/tracing.md#tracepoint-validationblock_connected
        """

        class Block(ctypes.Structure):
            _fields_ = [
                ("hash", ctypes.c_char * 32),
                ("height", ctypes.c_int),
                ("transactions", ctypes.c_int64),
                ("inputs", ctypes.c_int),
                ("sigops", ctypes.c_int64),
                ("duration", ctypes.c_uint64),
            ]

        blocks = list()
        blocks_checked = 0

        ctx = USDT(path=str(self.options.bitcoind))
        ctx.enable_probe(probe="block_connected", fn_name="trace_block_connected")
        bpf = BPF(text=validation_blockconnected_program, usdt_contexts=[ctx], debug=0)

        def handle_blockconnected(_, data, __):
            nonlocal blocks, blocks_checked
            event = ctypes.cast(data, ctypes.POINTER(Block)).contents
            block = blocks.pop(0)
            assert_equal(block["hash"], event.hash[::-1].hex())
            assert_equal(block["height"], event.height)
            assert_equal(len(block["tx"]), event.transactions)
            assert_equal(len([tx["vin"] for tx in block["tx"]]), event.inputs)
            # TODO: properly count sigops ?
            assert_equal(0, event.sigops)
            # only plausibility checks
            assert(event.duration > 0)
            blocks_checked += 1

        bpf["block_connected"].open_perf_buffer(handle_blockconnected)

        block_hashes = self.generatetoaddress(self.nodes[0], 2, ADDRESS_BCRT1_UNSPENDABLE)
        for block_hash in block_hashes:
            blocks.append(self.nodes[0].getblock(block_hash, 2))

        bpf.perf_buffer_poll(timeout=200)
        bpf.cleanup()
        assert_equal(blocks_checked, 2)

if __name__ == '__main__':
    TracepointTest().main()
