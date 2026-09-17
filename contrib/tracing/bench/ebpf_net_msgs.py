#!/usr/bin/env python3
# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""eBPF/USDT receiver for the net:inbound_message and net:outbound_message
tracepoints, counting events and lost events for the IPC-vs-eBPF benchmark.

Needs root (loads an eBPF program) and a bitcoind/bitcoin-node built with
-DWITH_USDT=ON. Prints one stats line per second and, on exit, a JSON summary
with the same schema as `bitcoin-trace -stats -json`.

Example:
  sudo ./ebpf_net_msgs.py --pid $(pidof bitcoin-node) --payload 8 --duration 60

Delivery latency is measured as time.monotonic_ns() in this process minus
bpf_ktime_get_ns() in the kernel; both are CLOCK_MONOTONIC.
"""

import argparse
import ctypes
import json
import os
import signal
import sys
import time

from bcc import BPF, USDT

MAX_MSG_TYPE_LENGTH = 20

PROGRAM = """
#include <uapi/linux/ptrace.h>

#define MAX_MSG_TYPE_LENGTH {max_msg_type}
#define MAX_PAYLOAD {payload}

struct msg_event {{
    u64 ts_ns;
    u64 peer_id;
    u64 msg_size;
    u64 inbound;
    char msg_type[MAX_MSG_TYPE_LENGTH];
#if MAX_PAYLOAD > 0
    u8 payload[MAX_PAYLOAD];
#endif
}};

// Per-CPU scratch space: the eBPF stack is limited to 512 bytes, which is
// too small once payload bytes are included.
BPF_PERCPU_ARRAY(scratch, struct msg_event, 1);
BPF_PERF_OUTPUT(events);

static __always_inline int trace_message(struct pt_regs *ctx, u64 inbound) {{
    u32 zero = 0;
    struct msg_event *e = scratch.lookup(&zero);
    if (e == NULL) return 1;
    e->ts_ns = bpf_ktime_get_ns();
    e->inbound = inbound;
    bpf_usdt_readarg(1, ctx, &e->peer_id);
    bpf_usdt_readarg_p(4, ctx, &e->msg_type, MAX_MSG_TYPE_LENGTH);
    bpf_usdt_readarg(5, ctx, &e->msg_size);
#if MAX_PAYLOAD > 0
    void *payload = NULL;
    bpf_usdt_readarg(6, ctx, &payload);
    u64 len = e->msg_size;
    if (len > MAX_PAYLOAD) len = MAX_PAYLOAD;
    bpf_probe_read_user(&e->payload, len, payload);
#endif
    events.perf_submit(ctx, e, sizeof(*e));
    return 0;
}}

int trace_inbound_message(struct pt_regs *ctx) {{ return trace_message(ctx, 1); }}
int trace_outbound_message(struct pt_regs *ctx) {{ return trace_message(ctx, 0); }}
"""


def make_event_class(payload):
    fields = [
        ("ts_ns", ctypes.c_uint64),
        ("peer_id", ctypes.c_uint64),
        ("msg_size", ctypes.c_uint64),
        ("inbound", ctypes.c_uint64),
        ("msg_type", ctypes.c_char * MAX_MSG_TYPE_LENGTH),
    ]
    if payload > 0:
        fields.append(("payload", ctypes.c_ubyte * payload))

    class MsgEvent(ctypes.Structure):
        _fields_ = fields

    return MsgEvent


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
    parser.add_argument("--page-cnt", type=int, default=1024, help="perf buffer pages per CPU (power of two)")
    parser.add_argument("--duration", type=float, default=0, help="exit after this many seconds (0 = until signal/stop file)")
    parser.add_argument("--ready-file", help="write this file (containing our pid) once the probes are attached")
    parser.add_argument("--stop-file", help="exit once this file exists")
    parser.add_argument("--out", help="write the JSON summary to this file instead of stdout")
    parser.add_argument("--json", action="store_true", help="print per-second stats as JSON lines")
    parser.add_argument("--quiet", action="store_true", help="no per-second stats")
    args = parser.parse_args()

    usdt = USDT(pid=args.pid)
    usdt.enable_probe(probe="net:inbound_message", fn_name="trace_inbound_message")
    usdt.enable_probe(probe="net:outbound_message", fn_name="trace_outbound_message")
    program = PROGRAM.format(max_msg_type=MAX_MSG_TYPE_LENGTH, payload=args.payload)
    bpf = BPF(text=program, usdt_contexts=[usdt],
              cflags=["-Wno-error=implicit-function-declaration", "-Wno-duplicate-decl-specifier"])
    event_class = make_event_class(args.payload)

    total = Counters()
    interval = Counters()

    def handle_event(_cpu, data, _size):
        now_ns = time.monotonic_ns()
        event = ctypes.cast(data, ctypes.POINTER(event_class)).contents
        lat_us = max(0, (now_ns - event.ts_ns) // 1000)
        interval.events += 1
        interval.bytes += event.msg_size
        interval.lat_sum_us += lat_us
        interval.lat_max_us = max(interval.lat_max_us, lat_us)
        if event.inbound:
            interval.events_in += 1
            if event.msg_type == b"ping":
                interval.ping_in += 1
        else:
            interval.events_out += 1
            if event.msg_type == b"pong":
                interval.pong_out += 1

    def handle_lost(_cpu, count):
        interval.dropped += count

    bpf["events"].open_perf_buffer(handle_event, page_cnt=args.page_cnt, lost_cb=handle_lost)

    stop = False

    def on_signal(_signum, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    if args.ready_file:
        with open(args.ready_file, "w", encoding="utf-8") as f:
            f.write(f"{os.getpid()}\n")
    print(json.dumps({"event": "ready", "pid": os.getpid()}), flush=True)

    start = time.monotonic()
    next_tick = start + 1.0
    while not stop:
        bpf.perf_buffer_poll(timeout=100)
        now = time.monotonic()
        if args.duration and now - start >= args.duration:
            break
        if args.stop_file and os.path.exists(args.stop_file):
            break
        if now >= next_tick:
            next_tick += 1.0
            total.add(interval)
            if not args.quiet:
                if args.json:
                    line = interval.to_json(1.0)
                    line["event"] = "stats"
                    line["elapsed_s"] = now - start
                    print(json.dumps(line), flush=True)
                else:
                    c = interval
                    mean = c.lat_sum_us / c.events if c.events else 0.0
                    print(f"t={now - start:.0f}s events={c.events} (in={c.events_in} out={c.events_out}) "
                          f"bytes={c.bytes} dropped={c.dropped} lat_mean_us={mean:.1f} lat_max_us={c.lat_max_us}",
                          flush=True)
            interval = Counters()
    # Drain whatever is still buffered, then account the last interval.
    bpf.perf_buffer_poll(timeout=200)
    total.add(interval)
    duration = time.monotonic() - start

    summary = total.to_json(duration)
    summary.update({"mode": "ebpf", "event": "summary", "payload_bytes": args.payload, "page_cnt": args.page_cnt})
    text = json.dumps(summary)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text, flush=True)
    bpf.cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(main())
