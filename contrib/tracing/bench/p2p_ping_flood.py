#!/usr/bin/env python3
# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Flood a Bitcoin Core node with P2P ping messages.

Connects to a node with the v1 transport, performs the version handshake and
then sends ping messages at a series of rates ("stages"). A reader thread
drains everything the node sends back: it counts pongs (each pong is proof
that the node processed one of our pings, i.e. that the node's
net:inbound_message and net:outbound_message events fired), and it answers
the node's own pings so the connection stays healthy. Draining is essential:
if the node's send buffer fills up (-maxsendbuffer) it stops processing our
pings entirely.

Example:
  p2p_ping_flood.py --port 18444 --stages 1000:10,10000:10,100000:10,0:30 --total 1000000

A stage "rate:seconds" sends `rate` pings per second for `seconds`; a rate of
0 means "as fast as the node accepts them". The final JSON report goes to
stdout (or --out).
"""

import argparse
import json
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "test", "functional"))

from test_framework.messages import (  # noqa: E402
    MAGIC_BYTES,
    NODE_NETWORK,
    NODE_WITNESS,
    msg_version,
    sha256,
)

HEADER_LEN = 24
TICK_S = 0.01  # sender granularity for rate-limited stages
UNLIMITED_CHUNK = 1024  # pings per write for unlimited stages


def frame(chain, msgtype, payload):
    """Build a v1 P2P message: magic, 12 byte type, length, checksum, payload."""
    return (MAGIC_BYTES[chain] + msgtype + b"\x00" * (12 - len(msgtype))
            + len(payload).to_bytes(4, "little") + sha256(sha256(payload))[:4] + payload)


class Flooder:
    def __init__(self, host, port, chain, total, log):
        self.host = host
        self.port = port
        self.chain = chain
        self.total = total
        self.log = log
        self.sock = None
        self.lock = threading.Lock()
        self.pongs = 0
        self.recv_msgs = 0
        self.recv_bytes = 0
        self.sent = 0
        self.handshake_done = threading.Event()
        self.closed = threading.Event()
        self.ping_frame = frame(chain, b"ping", (0).to_bytes(8, "little"))

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port))
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        self.reader = threading.Thread(target=self._reader, daemon=True)
        self.reader.start()
        version = msg_version()
        version.nVersion = 70016
        version.nServices = NODE_NETWORK | NODE_WITNESS
        version.strSubVer = "/p2p_ping_flood:0.1/"
        version.nStartingHeight = 0
        self.sock.sendall(frame(self.chain, b"version", version.serialize()))
        if not self.handshake_done.wait(timeout=30):
            raise RuntimeError("handshake with node did not complete")

    def _send(self, data):
        with self.lock:
            self.sock.sendall(data)

    def _reader(self):
        buf = b""
        try:
            while not self.closed.is_set():
                chunk = self.sock.recv(1 << 20)
                if not chunk:
                    break
                buf += chunk
                while len(buf) >= HEADER_LEN:
                    length = int.from_bytes(buf[16:20], "little")
                    if len(buf) < HEADER_LEN + length:
                        break
                    msgtype = buf[4:16].rstrip(b"\x00")
                    payload = buf[HEADER_LEN:HEADER_LEN + length]
                    buf = buf[HEADER_LEN + length:]
                    self._handle(msgtype, payload)
        except OSError:
            pass
        finally:
            self.closed.set()

    def _handle(self, msgtype, payload):
        self.recv_msgs += 1
        self.recv_bytes += HEADER_LEN + len(payload)
        if msgtype == b"pong":
            self.pongs += 1
        elif msgtype == b"version":
            self._send(frame(self.chain, b"verack", b""))
        elif msgtype == b"verack":
            self.handshake_done.set()
        elif msgtype == b"ping":
            self._send(frame(self.chain, b"pong", payload))
        # Everything else (sendcmpct, feefilter, getheaders, inv, ...) is ignored.

    def run_stage(self, rate, seconds):
        """Send pings at `rate`/s (0 = unlimited) for `seconds`, then wait until
        the node has answered them all. Returns stage stats measured over the
        whole period, so pong_rate reflects the node's processing rate even when
        the sends themselves only filled socket buffers."""
        start = time.monotonic()
        sent_start, pongs_start = self.sent, self.pongs
        deadline = start + seconds
        if rate > 0:
            per_tick = max(1, int(rate * TICK_S))
            chunk = self.ping_frame * per_tick
            next_tick = start
            while time.monotonic() < deadline and self.sent < self.total and not self.closed.is_set():
                next_tick += TICK_S
                self._send(chunk)
                self.sent += per_tick
                delay = next_tick - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
        else:
            chunk = self.ping_frame * UNLIMITED_CHUNK
            while time.monotonic() < deadline and self.sent < self.total and not self.closed.is_set():
                self._send(chunk)  # blocks when the node stops reading (backpressure)
                self.sent += UNLIMITED_CHUNK
        send_elapsed = time.monotonic() - start
        self.wait_caught_up()
        elapsed = time.monotonic() - start
        stage = {
            "rate": rate,
            "seconds": seconds,
            "elapsed_s": elapsed,
            "send_elapsed_s": send_elapsed,
            "sent": self.sent - sent_start,
            "pongs": self.pongs - pongs_start,
            "send_rate": (self.sent - sent_start) / elapsed if elapsed > 0 else 0,
            "pong_rate": (self.pongs - pongs_start) / elapsed if elapsed > 0 else 0,
        }
        self.log(f"stage rate={rate} done: sent={stage['sent']} pongs={stage['pongs']} "
                 f"send_rate={stage['send_rate']:.0f}/s pong_rate={stage['pong_rate']:.0f}/s")
        return stage

    def wait_caught_up(self, idle_s=2.0, max_s=120.0):
        """Wait until the node has answered every ping sent so far, or until
        no new pongs arrive for idle_s."""
        start = time.monotonic()
        last, last_change = self.pongs, time.monotonic()
        while time.monotonic() - start < max_s and not self.closed.is_set():
            if self.pongs >= self.sent:
                break
            time.sleep(0.01)
            if self.pongs != last:
                last, last_change = self.pongs, time.monotonic()
            elif time.monotonic() - last_change >= idle_s:
                break

    def close(self):
        self.closed.set()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


def parse_stages(text):
    stages = []
    for item in text.split(","):
        rate, seconds = item.split(":")
        stages.append((int(rate), float(seconds)))
    return stages


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True, help="P2P port of the node")
    parser.add_argument("--chain", default="regtest", choices=sorted(MAGIC_BYTES))
    parser.add_argument("--stages", default="1000:10,10000:10,100000:10,0:30",
                        help="comma separated rate:seconds stages, rate 0 = unlimited")
    parser.add_argument("--total", type=int, default=1_000_000, help="stop after this many pings")
    parser.add_argument("--out", help="write the JSON report to this file instead of stdout")
    parser.add_argument("--quiet", action="store_true", help="no progress output on stderr")
    args = parser.parse_args()

    def log(msg):
        if not args.quiet:
            print(msg, file=sys.stderr, flush=True)

    flooder = Flooder(args.host, args.port, args.chain, args.total, log)
    flooder.connect()
    log("handshake complete, starting flood")
    start = time.monotonic()
    stages = []
    for rate, seconds in parse_stages(args.stages):
        if flooder.sent >= args.total or flooder.closed.is_set():
            break
        stages.append(flooder.run_stage(rate, seconds))
    flooder.wait_caught_up()
    duration = time.monotonic() - start
    report = {
        "sent": flooder.sent,
        "pongs": flooder.pongs,
        "recv_msgs": flooder.recv_msgs,
        "recv_bytes": flooder.recv_bytes,
        "duration_s": duration,
        "disconnected": flooder.closed.is_set(),
        "stages": stages,
    }
    flooder.close()
    log(f"done: sent={report['sent']} pongs={report['pongs']} in {duration:.1f}s")
    text = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text)


if __name__ == "__main__":
    main()
