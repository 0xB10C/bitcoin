#!/usr/bin/env python3
# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Benchmark driver: IPC tracing vs eBPF/USDT tracing under a P2P ping flood.

Starts a regtest bitcoin-node in a temporary datadir, optionally attaches a
trace receiver (bitcoin-trace over IPC, or the BCC script over USDT), floods
the node with pings using p2p_ping_flood.py, samples the node's CPU and
memory, and writes a JSON result file. `compare` prints a markdown table over
result files.

Examples:
  run_bench.py run --mode none
  run_bench.py run --mode ipc --payload 8
  run_bench.py run --mode ebpf --payload 8   # prints a sudo command to run in another terminal
  run_bench.py compare results/*.json

The eBPF receiver needs root, so in --mode ebpf this script prints the exact
command and waits until the receiver reports readiness via a file.

The `ibd` mode is a stub: it documents the intended setup (a synced local
node to download from) but is not implemented yet.
"""

import argparse
import datetime
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
CLK_TCK = os.sysconf("SC_CLK_TCK")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def pick_ports():
    """Pick a P2P and an RPC port that are not adjacent (the node also binds port+1)."""
    while True:
        p2p, rpc = free_port(), free_port()
        if abs(p2p - rpc) > 2:
            return p2p, rpc


class ProcSampler(threading.Thread):
    """Samples utime+stime and RSS of a set of pids once per second."""

    def __init__(self):
        super().__init__(daemon=True)
        self.pids = {}
        self.samples = []
        self.stop_event = threading.Event()
        self.lock = threading.Lock()

    def add(self, name, pid):
        with self.lock:
            self.pids[name] = pid

    @staticmethod
    def read(pid):
        try:
            with open(f"/proc/{pid}/stat", encoding="utf-8") as f:
                fields = f.read().rsplit(")", 1)[1].split()
            cpu_s = (int(fields[11]) + int(fields[12])) / CLK_TCK  # utime + stime
            rss_kb = 0
            with open(f"/proc/{pid}/status", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        rss_kb = int(line.split()[1])
                        break
            return cpu_s, rss_kb
        except (OSError, IndexError, ValueError):
            return None

    def run(self):
        while not self.stop_event.is_set():
            sample = {"t": time.monotonic()}
            with self.lock:
                pids = dict(self.pids)
            for name, pid in pids.items():
                r = self.read(pid)
                if r:
                    sample[name] = {"cpu_s": r[0], "rss_kb": r[1]}
            self.samples.append(sample)
            self.stop_event.wait(1.0)

    def summary(self, name, t0, t1):
        """CPU seconds and average CPU% of `name` between monotonic times t0..t1."""
        pts = [s for s in self.samples if name in s and t0 <= s["t"] <= t1]
        if len(pts) < 2:
            return None
        cpu = pts[-1][name]["cpu_s"] - pts[0][name]["cpu_s"]
        wall = pts[-1]["t"] - pts[0]["t"]
        return {
            "cpu_s": cpu,
            "avg_cpu_pct": 100.0 * cpu / wall if wall > 0 else 0.0,
            "peak_rss_kb": max(p[name]["rss_kb"] for p in pts),
        }


def wait_for_file(path, timeout, what):
    start = time.monotonic()
    while not os.path.exists(path):
        if time.monotonic() - start > timeout:
            raise RuntimeError(f"timeout waiting for {what} ({path})")
        time.sleep(0.2)


def read_json_line(path, key="summary"):
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                obj = json.loads(line)
                if obj.get("event", key) == key:
                    return obj
    raise RuntimeError(f"no {key} in {path}")


class Node:
    def __init__(self, binary, cli, datadir, p2p_port, rpc_port, extra_args):
        self.binary = binary
        self.cli = cli
        self.datadir = datadir
        self.p2p_port = p2p_port
        self.rpc_port = rpc_port
        self.args = [
            binary, "-regtest", f"-datadir={datadir}", "-ipcbind=unix", "-bind=127.0.0.1",
            f"-port={p2p_port}", f"-rpcport={rpc_port}", "-dnsseed=0", "-listenonion=0",
            "-printtoconsole=0", "-debug=0",
        ] + extra_args
        self.proc = None

    def cli_args(self):
        return [self.cli, "-regtest", f"-datadir={self.datadir}", f"-rpcport={self.rpc_port}"]

    def start(self):
        self.proc = subprocess.Popen(self.args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        start = time.monotonic()
        while True:
            if self.proc.poll() is not None:
                raise RuntimeError(f"node exited early with {self.proc.returncode}; see {self.datadir}/regtest/debug.log")
            r = subprocess.run(self.cli_args() + ["getblockcount"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if r.returncode == 0:
                return
            if time.monotonic() - start > 60:
                raise RuntimeError("node did not become ready")
            time.sleep(0.2)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            subprocess.run(self.cli_args() + ["stop"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                self.proc.wait(timeout=120)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    @property
    def socket_path(self):
        return os.path.join(self.datadir, "regtest", "node.sock")


def run(args):
    if args.mode == "ibd":
        raise NotImplementedError(
            "IBD mode is not implemented yet. Intended setup: a synced local node as source, "
            "the benchmark node started with -connect=<source> -stopatheight=<N> (mainnet, no flooder), "
            "the same receiver plumbing as the ping benchmark, and blocks/s sampled via getblockcount.")

    os.makedirs(args.results, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    label = f"{stamp}-{args.mode}" + (f"-{args.label}" if args.label else "")
    workdir = tempfile.mkdtemp(prefix=f"ipc-bench-{args.mode}-")
    datadir = os.path.join(workdir, "datadir")
    os.makedirs(datadir)
    p2p_port, rpc_port = pick_ports()
    node = Node(args.node, args.cli, datadir, p2p_port, rpc_port,
                [f"-maxreceivebuffer={args.maxreceivebuffer}", f"-maxsendbuffer={args.maxsendbuffer}"])
    sampler = ProcSampler()
    receiver = None
    receiver_out = os.path.join(workdir, "receiver.json")
    stop_file = os.path.join(workdir, "stop")
    ready_file = os.path.join(workdir, "ready")
    result = {"mode": args.mode, "label": label, "node_args": node.args[1:], "stages": args.stages,
              "total": args.total, "payload": args.payload, "workdir": workdir}
    print(f"[bench] mode={args.mode} workdir={workdir} p2p_port={p2p_port} rpc_port={rpc_port}", flush=True)
    try:
        node.start()
        sampler.add("node", node.proc.pid)
        sampler.start()
        print(f"[bench] node pid={node.proc.pid} ready", flush=True)

        if args.mode == "ipc":
            cmd = [args.trace, "-regtest", f"-datadir={datadir}", f"-ipcconnect=unix:{node.socket_path}",
                   "-stats", "-json", f"-payload={args.payload}", f"-queue={args.queue}", f"-batch={args.batch}",
                   f"-out={receiver_out}"]
            receiver_log = open(os.path.join(workdir, "receiver.log"), "w", encoding="utf-8")
            receiver = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=receiver_log, text=True)
            line = receiver.stdout.readline()
            if '"ready"' not in line:
                raise RuntimeError(f"bitcoin-trace did not become ready: {line!r}")
            # Keep draining stdout so the receiver never blocks on a full pipe.
            threading.Thread(target=lambda: [receiver_log.write(ln) for ln in receiver.stdout], daemon=True).start()
            sampler.add("receiver", receiver.pid)
            result["receiver_cmd"] = cmd
            print(f"[bench] bitcoin-trace pid={receiver.pid} subscribed", flush=True)
        elif args.mode == "ebpf":
            receiver_script = "bpftrace_net_msgs.py" if args.engine == "bpftrace" else "ebpf_net_msgs.py"
            cmd = ["sudo", sys.executable, os.path.join(HERE, receiver_script), "--pid", str(node.proc.pid),
                   "--payload", str(args.payload), "--page-cnt", str(args.page_cnt), "--ready-file", ready_file,
                   "--stop-file", stop_file, "--out", receiver_out, "--json"]
            if args.engine == "bpftrace":
                # Root shells often lack the user's PATH (e.g. nix shells), so pass the absolute path.
                cmd += ["--bpftrace", shutil.which("bpftrace") or "bpftrace"]
            # Also write the command to a file, for terminals where copy/paste is awkward.
            helper = os.path.join(args.results, "run_ebpf_receiver.sh")
            with open(helper, "w", encoding="utf-8") as f:
                f.write("#!/usr/bin/env bash\n" + " ".join(cmd) + "\n")
            os.chmod(helper, 0o755)
            result["receiver_cmd"] = cmd
            print("\n[bench] Run the eBPF receiver as root in another terminal now:\n\n    "
                  + " ".join(cmd) + f"\n\n[bench] (also saved as {helper})\n[bench] waiting for it to attach ...", flush=True)
            wait_for_file(ready_file, timeout=3600, what="eBPF receiver ready file")
            with open(ready_file, encoding="utf-8") as f:
                sampler.add("receiver", int(f.read().strip()))
            print("[bench] eBPF receiver attached", flush=True)

        time.sleep(2)  # let samplers settle
        flood_out = os.path.join(workdir, "flood.json")
        flood_cmd = [sys.executable, os.path.join(HERE, "p2p_ping_flood.py"), "--port", str(p2p_port),
                     "--stages", args.stages, "--total", str(args.total), "--out", flood_out]
        t0 = time.monotonic()
        subprocess.run(flood_cmd, check=True)
        t1 = time.monotonic()
        with open(flood_out, encoding="utf-8") as f:
            result["flood"] = json.load(f)
        time.sleep(2)  # let the receiver drain
        t_end = time.monotonic()

        if args.mode == "ipc":
            receiver.send_signal(signal.SIGINT)
            receiver.wait(timeout=120)
            result["receiver"] = read_json_line(receiver_out)
        elif args.mode == "ebpf":
            open(stop_file, "w").close()
            wait_for_file(receiver_out, timeout=120, what="eBPF receiver summary")
            time.sleep(0.5)
            result["receiver"] = read_json_line(receiver_out)

        result["cpu"] = {"node": sampler.summary("node", t0, t1)}
        if "receiver" in sampler.pids:
            result["cpu"]["receiver"] = sampler.summary("receiver", t0, t_end)
        pongs = result["flood"]["pongs"]
        result["expected_events"] = 2 * pongs
        if "receiver" in result:
            got = result["receiver"]["ping_in"] + result["receiver"]["pong_out"]
            result["received_ping_pong_events"] = got
            result["drop_pct"] = 100.0 * (1 - got / (2 * pongs)) if pongs else None
    finally:
        sampler.stop_event.set()
        node.stop()
        if receiver and receiver.poll() is None:
            receiver.kill()
        if not args.keep_workdir:
            shutil.rmtree(workdir, ignore_errors=True)
            result.pop("workdir", None)

    out_path = os.path.join(args.results, f"{label}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"[bench] wrote {out_path}", flush=True)
    print(compare_table([result]))


def compare_table(results):
    rows = ["| run | pings processed | ping/s (max stage) | events received | expected | drop % | reported dropped | node CPU % | node RSS MB | recv CPU % | lat mean/max us |",
            "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in sorted(results, key=lambda r: r["label"]):
        flood = r.get("flood", {})
        rec = r.get("receiver")
        cpu = r.get("cpu", {})
        node_cpu = cpu.get("node") or {}
        recv_cpu = cpu.get("receiver") or {}
        max_pong_rate = max((s["pong_rate"] for s in flood.get("stages", [])), default=0)
        rows.append("| {label} | {pongs} | {rate:.0f} | {got} | {exp} | {drop} | {rdrop} | {ncpu} | {rss} | {rcpu} | {lat} |".format(
            label=r["label"],
            pongs=flood.get("pongs", "-"),
            rate=max_pong_rate,
            got=r.get("received_ping_pong_events", "-"),
            exp=r.get("expected_events", "-"),
            drop=f"{r['drop_pct']:.2f}" if r.get("drop_pct") is not None else "-",
            rdrop=rec["dropped"] if rec else "-",
            ncpu=f"{node_cpu['avg_cpu_pct']:.0f}" if node_cpu else "-",
            rss=f"{node_cpu['peak_rss_kb'] / 1024:.0f}" if node_cpu else "-",
            rcpu=f"{recv_cpu['avg_cpu_pct']:.0f}" if recv_cpu else "-",
            lat=f"{rec['latency_us']['mean']:.0f}/{rec['latency_us']['max']}" if rec else "-",
        ))
    return "\n".join(rows)


def compare(args):
    results = []
    for path in args.files:
        with open(path, encoding="utf-8") as f:
            results.append(json.load(f))
    print(compare_table(results))
    print()
    for r in sorted(results, key=lambda r: r["label"]):
        print(f"{r['label']}: stages " + ", ".join(
            f"{s['rate'] or 'max'}/s -> {s['pong_rate']:.0f} pong/s" for s in r.get("flood", {}).get("stages", [])))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("run", help="run one benchmark")
    p.add_argument("--mode", choices=["none", "ipc", "ebpf", "ibd"], required=True)
    p.add_argument("--node", default=os.path.join(REPO, "build", "bin", "bitcoin-node"))
    p.add_argument("--trace", default=os.path.join(REPO, "build", "bin", "bitcoin-trace"))
    p.add_argument("--cli", default=os.path.join(REPO, "build", "bin", "bitcoin-cli"))
    p.add_argument("--stages", default="1000:10,10000:10,100000:10,0:30")
    p.add_argument("--total", type=int, default=1_000_000)
    p.add_argument("--payload", type=int, default=0, help="payload bytes per event for the receiver")
    p.add_argument("--queue", type=int, default=65536, help="ipc: node-side queue size")
    p.add_argument("--batch", type=int, default=1024, help="ipc: max events per IPC call")
    p.add_argument("--page-cnt", type=int, default=1024, help="ebpf: perf buffer pages per CPU")
    p.add_argument("--engine", choices=["bpftrace", "bcc"], default="bpftrace",
                   help="ebpf: receiver implementation (bcc needs kernel headers, bpftrace only BTF)")
    p.add_argument("--maxreceivebuffer", type=int, default=5000)
    p.add_argument("--maxsendbuffer", type=int, default=1000)
    p.add_argument("--results", default=os.path.join(HERE, "results"))
    p.add_argument("--label", default="")
    p.add_argument("--keep-workdir", action="store_true")
    p.set_defaults(func=run)
    c = sub.add_parser("compare", help="print a markdown table for result files")
    c.add_argument("files", nargs="+")
    c.set_defaults(func=compare)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
