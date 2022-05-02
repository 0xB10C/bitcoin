#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""  Tests the net:* tracepoint API interface.
     See https://github.com/bitcoin/bitcoin/blob/master/doc/tracing.md#context-net
"""

import ctypes
from io import BytesIO
# Test will be skipped if we don't have bcc installed
try:
    from bcc import BPF, USDT  # type: ignore[import]
except ImportError:
    pass
from test_framework.messages import msg_version
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

# Tor v3 addresses are 62 chars + 6 chars for the port (':12345').
MAX_PEER_ADDR_LENGTH = 68
MAX_PEER_CONN_TYPE_LENGTH = 20
MAX_MSG_TYPE_LENGTH = 20
# We won't process messages larger than 150 byte in this test. For reading
# larger messanges see contrib/tracing/log_raw_p2p_msgs.py
MAX_MSG_DATA_LENGTH = 150

# from net_address.h
NETWORK_TYPE_UNROUTABLE = 0

net_tracepoints_program = """
#include <uapi/linux/ptrace.h>

#define MAX_PEER_ADDR_LENGTH {}
#define MAX_PEER_CONN_TYPE_LENGTH {}
#define MAX_MSG_TYPE_LENGTH {}
#define MAX_MSG_DATA_LENGTH {}
""".format(
    MAX_PEER_ADDR_LENGTH,
    MAX_PEER_CONN_TYPE_LENGTH,
    MAX_MSG_TYPE_LENGTH,
    MAX_MSG_DATA_LENGTH
) + """
#define MIN(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })

struct p2p_message
{
    u64     peer_id;
    char    peer_addr[MAX_PEER_ADDR_LENGTH];
    char    peer_conn_type[MAX_PEER_CONN_TYPE_LENGTH];
    char    msg_type[MAX_MSG_TYPE_LENGTH];
    u64     msg_size;
    u8      msg[MAX_MSG_DATA_LENGTH];
};

struct Connection
{
    u64     id;
    char    addr[MAX_PEER_ADDR_LENGTH];
    char    type[MAX_PEER_CONN_TYPE_LENGTH];
    u32     network;
};

struct NewConnection
{
    struct Connection   conn;
    u64                 existing;
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

BPF_PERF_OUTPUT(inbound_connections);
int trace_inbound_connection(struct pt_regs *ctx) {
    struct NewConnection inbound = {};
    bpf_usdt_readarg(1, ctx, &inbound.conn.id);
    bpf_usdt_readarg_p(2, ctx, &inbound.conn.addr, MAX_PEER_ADDR_LENGTH);
    bpf_usdt_readarg_p(3, ctx, &inbound.conn.type, MAX_PEER_CONN_TYPE_LENGTH);
    bpf_usdt_readarg(4, ctx, &inbound.conn.network);
    bpf_usdt_readarg(5, ctx, &inbound.existing);
    inbound_connections.perf_submit(ctx, &inbound, sizeof(inbound));
    return 0;
};

"""


class Connection(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint64),
        ("addr", ctypes.c_char * MAX_PEER_ADDR_LENGTH),
        ("conn_type", ctypes.c_char * MAX_PEER_CONN_TYPE_LENGTH),
        ("network", ctypes.c_uint32),
    ]

    def __repr__(self):
        return f"Connection(peer={self.id}, addr={self.addr.decode('utf-8')}, conn_type={self.conn_type.decode('utf-8')}, network={self.network})"


class NewConnection(ctypes.Structure):
    _fields_ = [
        ("conn", Connection),
        ("existing", ctypes.c_uint64),
    ]

    def __repr__(self):
        return f"NewConnection(conn={self.conn}, existing={self.existing})"

class NetTracepointTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_linux()
        self.skip_if_no_bitcoind_tracepoints()
        self.skip_if_no_python_bcc()
        self.skip_if_no_bpf_permissions()

    def run_test(self):
        self.p2p_message_tracepoint_test()
        self.inbound_conn_tracepoint_test()

    def p2p_message_tracepoint_test(self):
        # Tests the net:inbound_message and net:outbound_message tracepoints
        # See https://github.com/bitcoin/bitcoin/blob/master/doc/tracing.md#context-net

        class P2PMessage(ctypes.Structure):
            _fields_ = [
                ("peer_id", ctypes.c_uint64),
                ("peer_addr", ctypes.c_char * MAX_PEER_ADDR_LENGTH),
                ("peer_conn_type", ctypes.c_char * MAX_PEER_CONN_TYPE_LENGTH),
                ("msg_type", ctypes.c_char * MAX_MSG_TYPE_LENGTH),
                ("msg_size", ctypes.c_uint64),
                ("msg", ctypes.c_ubyte * MAX_MSG_DATA_LENGTH),
            ]

            def __repr__(self):
                return f"P2PMessage(peer={self.peer_id}, addr={self.peer_addr.decode('utf-8')}, conn_type={self.peer_conn_type.decode('utf-8')}, msg_type={self.msg_type.decode('utf-8')}, msg_size={self.msg_size})"

        self.log.info(
            "hook into the net:inbound_message and net:outbound_message tracepoints")
        ctx = USDT(pid=self.nodes[0].process.pid)
        ctx.enable_probe(probe="net:inbound_message",
                         fn_name="trace_inbound_message")
        ctx.enable_probe(probe="net:outbound_message",
                         fn_name="trace_outbound_message")
        bpf = BPF(text=net_tracepoints_program, usdt_contexts=[ctx], debug=0)

        EXPECTED_INOUTBOUND_VERSION_MSG = 1
        checked_inbound_version_msg = 0
        checked_outbound_version_msg = 0
        events = []

        def check_p2p_message(event, is_inbound):
            nonlocal checked_inbound_version_msg, checked_outbound_version_msg
            if event.msg_type.decode("utf-8") == "version":
                self.log.info(
                    f"check_p2p_message(): {'inbound' if is_inbound else 'outbound'} {event}")
                peer = self.nodes[0].getpeerinfo()[0]
                msg = msg_version()
                msg.deserialize(BytesIO(bytes(event.msg[:event.msg_size])))
                assert_equal(peer["id"], event.peer_id, peer["id"])
                assert_equal(peer["addr"], event.peer_addr.decode("utf-8"))
                assert_equal(peer["connection_type"],
                             event.peer_conn_type.decode("utf-8"))
                if is_inbound:
                    checked_inbound_version_msg += 1
                else:
                    checked_outbound_version_msg += 1

        def handle_inbound(_, data, __):
            event = ctypes.cast(data, ctypes.POINTER(P2PMessage)).contents
            events.append((event, True))

        def handle_outbound(_, data, __):
            event = ctypes.cast(data, ctypes.POINTER(P2PMessage)).contents
            events.append((event, False))

        bpf["inbound_messages"].open_perf_buffer(handle_inbound)
        bpf["outbound_messages"].open_perf_buffer(handle_outbound)

        self.log.info("connect a P2P test node to our bitcoind node")
        test_node = P2PInterface()
        self.nodes[0].add_p2p_connection(test_node)
        bpf.perf_buffer_poll(timeout=200)

        self.log.info(
            "check receipt and content of in- and outbound version messages")
        for event, is_inbound in events:
            check_p2p_message(event, is_inbound)
        assert_equal(EXPECTED_INOUTBOUND_VERSION_MSG,
                     checked_inbound_version_msg)
        assert_equal(EXPECTED_INOUTBOUND_VERSION_MSG,
                     checked_outbound_version_msg)


        bpf.cleanup()
        test_node.peer_disconnect()

    def inbound_conn_tracepoint_test(self):
        self.log.info("hook into the net:inbound_connection tracepoint")
        ctx = USDT(pid=self.nodes[0].process.pid)
        ctx.enable_probe(probe="net:inbound_connection",
                         fn_name="trace_inbound_connection")
        bpf = BPF(text=net_tracepoints_program, usdt_contexts=[ctx], debug=0, cflags=["-Wno-error=implicit-function-declaration"])

        inbound_connections = []
        EXPECTED_INBOUND_CONNECTIONS = 2

        def handle_inbound_connection(_, data, __):
            nonlocal inbound_connections
            event = ctypes.cast(data, ctypes.POINTER(NewConnection)).contents
            self.log.info(f"handle_inbound_connection(): {event}")
            inbound_connections.append(event)

        bpf["inbound_connections"].open_perf_buffer(handle_inbound_connection)

        self.log.info("connect two P2P test nodes to our bitcoind node")
        testnodes = list()
        for _ in range(EXPECTED_INBOUND_CONNECTIONS):
            testnode = P2PInterface()
            self.nodes[0].add_p2p_connection(testnode)
            testnodes.append(testnode)
        bpf.perf_buffer_poll(timeout=200)

        assert_equal(EXPECTED_INBOUND_CONNECTIONS, len(inbound_connections))
        for inbound_connection in inbound_connections:
            assert inbound_connection.conn.id > 0
            assert inbound_connection.existing >= 0
            assert_equal(b'inbound', inbound_connection.conn.conn_type)
            assert_equal(NETWORK_TYPE_UNROUTABLE, inbound_connection.conn.network)

        bpf.cleanup()
        for node in testnodes:
            node.peer_disconnect()

if __name__ == '__main__':
    NetTracepointTest().main()
