#!/usr/bin/env python3
# Copyright (c) 2019-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tests the tracepoints for Userspace, Statically Defined Tracing
   present in bitcoind.

- P2P In and outbound tracepoints

"""

from test_framework.test_framework import BitcoinTestFramework
from bcc import BPF, USDT

# BCC: The C program to be compiled to an eBPF program (by BCC) and loaded into
# a sandboxed Linux kernel VM.
program = """
#include <uapi/linux/ptrace.h>

#define MIN(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })

// Maximum possible allocation size
// from include/linux/percpu.h in the Linux kernel
#define PCPU_MIN_UNIT_SIZE (32 << 10)

// Tor v3 addresses are 62 chars + 6 chars for the port (':12345').
#define MAX_PEER_ADDR_LENGTH 62 + 6
#define MAX_PEER_CONN_TYPE_LENGTH 20
#define MAX_MSG_TYPE_LENGTH 20
#define MAX_MSG_DATA_LENGTH PCPU_MIN_UNIT_SIZE - 200

struct p2p_message
{
    u64     peer_id;
    char    peer_addr[MAX_PEER_ADDR_LENGTH];
    char    peer_conn_type[MAX_PEER_CONN_TYPE_LENGTH];
    char    msg_type[MAX_MSG_TYPE_LENGTH];
    u64     msg_size;
    u8      msg[MAX_MSG_DATA_LENGTH];
};

// We can't store the p2p_message struct on the eBPF stack as it is limited to
// 512 bytes and P2P message can be bigger than 512 bytes. However, we can use
// an BPF-array with a length of 1 to allocate up to 32768 bytes (this is
// defined by PCPU_MIN_UNIT_SIZE in include/linux/percpu.h in the Linux kernel).
// Also see https://github.com/iovisor/bcc/issues/2306
BPF_ARRAY(msg_arr, struct p2p_message, 1);

// Two BPF perf buffers for pushing data (here P2P messages) to user-space.
BPF_PERF_OUTPUT(inbound_messages);
BPF_PERF_OUTPUT(outbound_messages);

int trace_inbound_message(struct pt_regs *ctx) {
    int idx = 0;
    struct p2p_message *msg = msg_arr.lookup(&idx);

    // lookup() does not return a NULL pointer. However, the BPF verifier
    // requires an explicit check that that the `msg` pointer isn't a NULL
    // pointer. See https://github.com/iovisor/bcc/issues/2595
    if (msg == NULL) return 1;

    bpf_usdt_readarg(1, ctx, &msg->peer_id);
    bpf_usdt_readarg_p(2, ctx, &msg->peer_addr, MAX_PEER_ADDR_LENGTH);
    bpf_usdt_readarg_p(3, ctx, &msg->peer_conn_type, MAX_PEER_CONN_TYPE_LENGTH);
    bpf_usdt_readarg_p(4, ctx, &msg->msg_type, MAX_MSG_TYPE_LENGTH);
    bpf_usdt_readarg(5, ctx, &msg->msg_size);
    bpf_usdt_readarg_p(6, ctx, &msg->msg, MIN(msg->msg_size, MAX_MSG_DATA_LENGTH));

    inbound_messages.perf_submit(ctx, msg, sizeof(*msg));
    return 0;
};

int trace_outbound_message(struct pt_regs *ctx) {
    int idx = 0;
    struct p2p_message *msg = msg_arr.lookup(&idx);

    // lookup() does not return a NULL pointer. However, the BPF verifier
    // requires an explicit check that that the `msg` pointer isn't a NULL
    // pointer. See https://github.com/iovisor/bcc/issues/2595
    if (msg == NULL) return 1;

    bpf_usdt_readarg(1, ctx, &msg->peer_id);
    bpf_usdt_readarg_p(2, ctx, &msg->peer_addr, MAX_PEER_ADDR_LENGTH);
    bpf_usdt_readarg_p(3, ctx, &msg->peer_conn_type, MAX_PEER_CONN_TYPE_LENGTH);
    bpf_usdt_readarg_p(4, ctx, &msg->msg_type, MAX_MSG_TYPE_LENGTH);
    bpf_usdt_readarg(5, ctx, &msg->msg_size);
    bpf_usdt_readarg_p(6, ctx, &msg->msg,  MIN(msg->msg_size, MAX_MSG_DATA_LENGTH));

    outbound_messages.perf_submit(ctx, msg, sizeof(*msg));
    return 0;
};
"""

# - TODO: check if we are on Linux
# - TODO: check if tracepoints are enabled in Bitcoind
# - TODO: check if bcc is avaliable
# - TODO: check if we have CAP_BPF



class TracepointTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = False
        self.num_nodes = 2

    def run_test(self):

        check_inbound = False
        check_outbound = False

        self.log.info("Node crashed - now verifying restart fails")
        ctx = USDT(path=str(self.options.bitcoind))
        ctx.enable_probe(probe="inbound_message", fn_name="trace_inbound_message")
        ctx.enable_probe(probe="outbound_message", fn_name="trace_outbound_message")
        bpf = BPF(text=program, usdt_contexts=[ctx])

        def print_message(event, inbound):
            print(f"%s %s msg '%s' from peer %d (%s, %s) with %d bytes: %s" %
                (
                f"Warning: incomplete message (only %d out of %d bytes)!" % (len(event.msg), event.msg_size) if len(event.msg) < event.msg_size else "",
                "inbound" if inbound else "outbound",
                event.msg_type.decode("utf-8"),
                event.peer_id,
                event.peer_conn_type.decode("utf-8"),
                event.peer_addr.decode("utf-8"),
                event.msg_size,
                bytes(event.msg[:event.msg_size]).hex(),
                )
            )

        def handle_inbound(_, data, size):
            event = bpf["inbound_messages"].event(data)
            print_message(event, True)
            check_inbound = True

        def handle_outbound(_, data, size):
            event = bpf["outbound_messages"].event(data)
            print_message(event, False)
            check_outbound = True

        bpf["inbound_messages"].open_perf_buffer(handle_inbound)
        bpf["outbound_messages"].open_perf_buffer(handle_outbound)

        while not (check_inbound and check_outbound):
            bpf.perf_buffer_poll()

if __name__ == '__main__':
    TracepointTest().main()
