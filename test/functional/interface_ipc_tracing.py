#!/usr/bin/env python3
# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the IPC tracing interface using the bitcoin-trace client.

bitcoin-trace connects to bitcoin-node over IPC, subscribes to P2P message
events and prints them as JSON lines. This test drives it as a subprocess, so
no python capnp module is needed.
"""

import json
import signal
import subprocess
import threading

from test_framework.messages import msg_ping
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

NONCE = 0x1122334455667788


class TraceProcess:
    """Runs bitcoin-trace and collects its JSON output lines in a thread."""

    def __init__(self, args):
        self.proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.lines = []
        self.lock = threading.Lock()
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._reader, daemon=True)
        self.thread.start()

    def _reader(self):
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            with self.lock:
                self.lines.append(obj)
            if obj.get("event") == "ready":
                self.ready.set()

    def events(self):
        with self.lock:
            return [line for line in self.lines if "dir" in line]

    def summary(self):
        with self.lock:
            return next((line for line in self.lines if line.get("event") == "summary"), None)

    def stop(self, timeout=60):
        self.proc.send_signal(signal.SIGINT)
        self.proc.wait(timeout=timeout)
        self.thread.join(timeout=timeout)
        return self.proc.returncode, self.proc.stderr.read()


class TestBitcoinIpcTracing(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_ipc()

    def setup_nodes(self):
        self.extra_init = [{"ipcbind": True}]
        super().setup_nodes()

    def start_trace(self, extra_args):
        node = self.nodes[0]
        args = [self.binary_paths.bitcointrace, f"-datadir={node.datadir_path}",
                f"-ipcconnect=unix:{node.ipc_socket_path}", "-json"] + extra_args
        trace = TraceProcess(args)
        assert trace.ready.wait(timeout=60), "bitcoin-trace did not subscribe"
        return trace

    def test_ping_pong_events(self):
        self.log.info("Check that inbound ping and outbound pong events are delivered with payload")
        node = self.nodes[0]
        trace = self.start_trace(["-payload=8"])

        peer = node.add_p2p_connection(P2PInterface())
        peer_id = node.getpeerinfo()[0]["id"]
        peer.send_without_ping(msg_ping(nonce=NONCE))
        peer.wait_until(lambda: "pong" in peer.last_message and peer.last_message["pong"].nonce == NONCE)
        payload = NONCE.to_bytes(8, "little").hex()
        # Events are delivered in batches from another thread, so wait for them.
        self.wait_until(lambda: any(e["type"] == "pong" and e["payload"] == payload for e in trace.events()))

        returncode, stderr = trace.stop()
        assert_equal(returncode, 0)
        assert_equal(stderr, "")

        events = trace.events()
        pings = [e for e in events if e["dir"] == "in" and e["type"] == "ping" and e["payload"] == payload]
        pongs = [e for e in events if e["dir"] == "out" and e["type"] == "pong" and e["payload"] == payload]
        assert_equal(len(pings), 1)
        assert_equal(len(pongs), 1)
        for event in pings + pongs:
            assert_equal(event["peer"], peer_id)
            assert_equal(event["conn"], "inbound")
            assert_equal(event["size"], 8)
            assert event["lat_us"] >= 0
        assert pings[0]["t"] <= pongs[0]["t"]
        # The handshake produced events too, all from the same peer.
        assert all(e["peer"] == peer_id for e in events)
        assert any(e["type"] == "version" and e["dir"] == "in" for e in events)
        assert any(e["type"] == "verack" and e["dir"] == "out" for e in events)
        # With -payload=8, larger messages are truncated but report the full size.
        version = next(e for e in events if e["type"] == "version" and e["dir"] == "in")
        assert version["size"] > 8
        assert_equal(len(bytes.fromhex(version["payload"])), 8)

        summary = trace.summary()
        assert_equal(summary["mode"], "ipc")
        assert_equal(summary["dropped"], 0)
        # add_p2p_connection() sends sync pings of its own, so only lower bounds.
        assert summary["ping_in"] >= 1
        assert summary["pong_out"] >= 1
        assert_equal(summary["events"], len(events))
        peer.peer_disconnect()

    def test_direction_filter(self):
        self.log.info("Check that -noinbound only delivers outbound events without payload")
        node = self.nodes[0]
        trace = self.start_trace(["-noinbound"])
        peer = node.add_p2p_connection(P2PInterface())
        peer.send_without_ping(msg_ping(nonce=NONCE))
        peer.wait_until(lambda: "pong" in peer.last_message and peer.last_message["pong"].nonce == NONCE)
        self.wait_until(lambda: any(e["type"] == "pong" for e in trace.events()))
        returncode, _ = trace.stop()
        assert_equal(returncode, 0)
        events = trace.events()
        assert all(e["dir"] == "out" for e in events)
        assert all(e["payload"] == "" for e in events)
        assert_equal(trace.summary()["ping_in"], 0)
        peer.peer_disconnect()

    def test_large_payload(self):
        self.log.info("Check that a large payload is delivered intact (external segment path)")
        node = self.nodes[0]
        trace = self.start_trace(["-payload=1000000"])
        peer = node.add_p2p_connection(P2PInterface())
        # A ping may carry more than the 8 byte nonce; the node ignores the rest.
        payload = NONCE.to_bytes(8, "little") + bytes(range(256)) * 40  # 10248 bytes
        peer.send_raw_message(self.build_ping(peer, payload))
        peer.wait_until(lambda: "pong" in peer.last_message and peer.last_message["pong"].nonce == NONCE)
        self.wait_until(lambda: any(e["type"] == "ping" and e["size"] == len(payload) for e in trace.events()))
        returncode, stderr = trace.stop()
        assert_equal(returncode, 0)
        assert_equal(stderr, "")
        ping = next(e for e in trace.events() if e["type"] == "ping" and e["size"] == len(payload))
        assert_equal(bytes.fromhex(ping["payload"]), payload)
        assert_equal(trace.summary()["dropped"], 0)
        peer.peer_disconnect()

    def test_shared_memory_payload(self):
        self.log.info("Check that a large payload is delivered through the shared memory arena")
        node = self.nodes[0]
        # 8 MiB of shared memory, 1 MB slots, so a handful of slots.
        trace = self.start_trace(["-payload=1000000", "-shm=8388608", "-shmmin=4096"])
        peer = node.add_p2p_connection(P2PInterface())
        payload = NONCE.to_bytes(8, "little") + bytes(range(256)) * 40  # 10248 bytes
        peer.send_raw_message(self.build_ping(peer, payload))
        peer.wait_until(lambda: "pong" in peer.last_message and peer.last_message["pong"].nonce == NONCE)
        self.wait_until(lambda: any(e["type"] == "ping" and e["size"] == len(payload) for e in trace.events()))
        returncode, stderr = trace.stop()
        assert_equal(returncode, 0)
        assert_equal(stderr, "")
        ping = next(e for e in trace.events() if e["type"] == "ping" and e["size"] == len(payload))
        assert_equal(bytes.fromhex(ping["payload"]), payload)
        # The payload came out of an arena slot, not out of the IPC message.
        assert ping["slot"] >= 0
        # Small handshake messages stay inline, below -shmmin.
        version = next(e for e in trace.events() if e["type"] == "version" and e["dir"] == "in")
        assert_equal(version["slot"], -1)
        summary = trace.summary()
        assert_equal(summary["dropped"], 0)
        assert summary["shm_events"] >= 1
        assert_equal(summary["shm_bytes"], 8388608)
        peer.peer_disconnect()

    @staticmethod
    def build_ping(peer, payload):
        """Build a v1 ping message with an arbitrary payload."""
        class RawPing:
            msgtype = b"ping"

            def serialize(self):
                return payload
        return peer.build_message(RawPing())

    def test_node_shutdown_with_subscriber(self):
        self.log.info("Check that bitcoin-trace exits when the node shuts down")
        trace = self.start_trace([])
        self.stop_node(0)
        trace.proc.wait(timeout=60)
        trace.thread.join(timeout=60)
        assert_equal(trace.proc.returncode, 1)
        assert "lost connection to bitcoin-node" in trace.proc.stderr.read()
        assert trace.summary() is not None

    def run_test(self):
        self.test_ping_pong_events()
        self.test_direction_filter()
        self.test_large_payload()
        self.test_shared_memory_payload()
        self.test_node_shutdown_with_subscriber()


if __name__ == '__main__':
    TestBitcoinIpcTracing(__file__).main()
