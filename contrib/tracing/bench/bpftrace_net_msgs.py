#!/usr/bin/env python3
# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""bpftrace based receiver for the net:inbound_message and net:outbound_message
tracepoints. Same command line and summary schema as ebpf_net_msgs.py (BCC),
for systems without kernel headers where BCC cannot compile (bpftrace only
needs BTF, /sys/kernel/btf/vmlinux).

bpftrace prints one line per event through its perf ring buffer; this wrapper
parses those lines and counts events, bytes and delivery latency. Events lost
in the ring buffer are reported by bpftrace on stderr as "Lost N events" and
are counted as `dropped`.

Example:
  sudo ./bpftrace_net_msgs.py --pid $(pidof bitcoin-node) --payload 8 --duration 60
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time

LOST_RE = re.compile(r"Lost (\d+) events?")


def build_script(exe, payload):
    fmt = "%d %d %s %d %d"
    args = "arg0, str(arg3), arg4, nsecs"
    if payload > 0:
        fmt += " %r"
        args += f", buf(arg5, {payload})"
    lines = []
    for inbound, name in ((1, "inbound_message"), (0, "outbound_message")):
        lines.append(f'usdt:{exe}:net:{name} {{ printf("{fmt}\\n", {inbound}, {args}); }}')
    return "\n".join(lines) + "\n"


class Counters:
    FIELDS = ("events", "events_in", "events_out", "ping_in", "pong_out", "bytes", "dropped", "lat_sum_us", "lat_max_us")

    def __init__(self):
        for f in self.FIELDS:
            setattr(self, f, 0)

    def add(self, other):
        for f in self.FIELDS:
            if f == "lat_max_us":
                self.lat_max_us = max(self.lat_max_us, other.lat_max_us)
            else:
                setattr(self, f, getattr(self, f) + getattr(other, f))

    def to_json(self, seconds):
        return {
            "events": self.events,
            "events_in": self.events_in,
            "events_out": self.events_out,
            "ping_in": self.ping_in,
            "pong_out": self.pong_out,
            "bytes": self.bytes,
            "dropped": self.dropped,
            "batches": 0,
            "duration_s": seconds,
            "events_per_s": self.events / seconds if seconds > 0 else 0.0,
            "latency_us": {
                "mean": self.lat_sum_us / self.events if self.events else 0.0,
                "max": self.lat_max_us,
            },
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pid", type=int, required=True, help="pid of bitcoind / bitcoin-node")
    parser.add_argument("--payload", type=int, default=0, help="payload bytes to copy per event (0 = none)")
    parser.add_argument("--page-cnt", type=int, default=1024, help="perf ring buffer pages per CPU (BPFTRACE_PERF_RB_PAGES)")
    parser.add_argument("--duration", type=float, default=0, help="exit after this many seconds (0 = until signal/stop file)")
    parser.add_argument("--ready-file", help="write this file (containing our pid) once the probes are attached")
    parser.add_argument("--stop-file", help="exit once this file exists")
    parser.add_argument("--out", help="write the JSON summary to this file instead of stdout")
    parser.add_argument("--json", action="store_true", help="print per-second stats as JSON lines")
    parser.add_argument("--quiet", action="store_true", help="no per-second stats")
    parser.add_argument("--bpftrace", default="bpftrace")
    args = parser.parse_args()

    exe = os.readlink(f"/proc/{args.pid}/exe")
    script = build_script(exe, args.payload)
    env = dict(os.environ, BPFTRACE_PERF_RB_PAGES=str(args.page_cnt), BPFTRACE_MAX_STRLEN="32")
    cmd = [args.bpftrace, "-q", "-p", str(args.pid), "-e", script]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True, bufsize=1)

    lock = threading.Lock()
    total = Counters()
    interval = Counters()
    attached = threading.Event()
    stderr_lines = []

    def read_stderr():
        for line in proc.stderr:
            line = line.rstrip()
            m = LOST_RE.search(line)
            if m:
                with lock:
                    interval.dropped += int(m.group(1))
            else:
                stderr_lines.append(line)
                if not attached.is_set():
                    print(line, file=sys.stderr, flush=True)

    def read_stdout():
        for line in proc.stdout:
            now_ns = time.monotonic_ns()
            parts = line.split(" ", 5)
            if len(parts) < 5:
                continue
            try:
                inbound, msg_type, size, ts_ns = int(parts[0]), parts[2], int(parts[3]), int(parts[4])
            except ValueError:
                continue
            lat_us = max(0, (now_ns - ts_ns) // 1000)
            with lock:
                interval.events += 1
                interval.bytes += size
                interval.lat_sum_us += lat_us
                interval.lat_max_us = max(interval.lat_max_us, lat_us)
                if inbound:
                    interval.events_in += 1
                    if msg_type == "ping":
                        interval.ping_in += 1
                else:
                    interval.events_out += 1
                    if msg_type == "pong":
                        interval.pong_out += 1

    threading.Thread(target=read_stderr, daemon=True).start()
    threading.Thread(target=read_stdout, daemon=True).start()

    # bpftrace has no explicit "attached" signal in -q mode; it exits quickly
    # on errors, so wait a moment and check it is still running.
    time.sleep(2.0)
    if proc.poll() is not None:
        print("bpftrace exited early:\n" + "\n".join(stderr_lines), file=sys.stderr)
        return 1
    attached.set()

    stop = False

    def on_signal(_signum, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    if args.ready_file:
        with open(args.ready_file, "w", encoding="utf-8") as f:
            f.write(f"{proc.pid}\n")  # bpftrace's pid: that is the process doing the work
    print(json.dumps({"event": "ready", "pid": proc.pid}), flush=True)

    start = time.monotonic()
    next_tick = start + 1.0
    while not stop and proc.poll() is None:
        time.sleep(0.05)
        now = time.monotonic()
        if args.duration and now - start >= args.duration:
            break
        if args.stop_file and os.path.exists(args.stop_file):
            break
        if now >= next_tick:
            next_tick += 1.0
            with lock:
                c, interval = interval, Counters()
            total.add(c)
            if not args.quiet:
                if args.json:
                    line = c.to_json(1.0)
                    line["event"] = "stats"
                    line["elapsed_s"] = now - start
                    print(json.dumps(line), flush=True)
                else:
                    mean = c.lat_sum_us / c.events if c.events else 0.0
                    print(f"t={now - start:.0f}s events={c.events} (in={c.events_in} out={c.events_out}) "
                          f"bytes={c.bytes} dropped={c.dropped} lat_mean_us={mean:.1f} lat_max_us={c.lat_max_us}",
                          flush=True)
    # Give bpftrace a moment to flush, then stop it and account the rest.
    time.sleep(0.5)
    if proc.poll() is None:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
    time.sleep(0.2)
    with lock:
        total.add(interval)
    duration = time.monotonic() - start

    summary = total.to_json(duration)
    summary.update({"mode": "ebpf", "engine": "bpftrace", "event": "summary",
                    "payload_bytes": args.payload, "page_cnt": args.page_cnt})
    text = json.dumps(summary)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
