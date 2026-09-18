# IPC tracing vs eBPF/USDT tracing benchmark

Tooling for the "ping benchmark" described in
[bitcoin/bitcoin#35142](https://github.com/bitcoin/bitcoin/issues/35142#issuecomment-4303708807):
flood a node with small P2P messages and compare how many `net:inbound_message` /
`net:outbound_message` events each tracing interface delivers, how many it drops,
and what it costs the node.

## Pieces

- `p2p_ping_flood.py`: v1-transport P2P client that sends pings in stages
  (`rate:seconds,...`, rate `0` = as fast as the node accepts) and drains the
  node's replies. Every `pong` it receives is one ping the node processed, so
  `2 * pongs` is the number of ping/pong trace events the node emitted.
- `bpftrace_net_msgs.py`: bpftrace receiver attaching to the two USDT
  tracepoints; one printf line per event, "Lost N events" counted as drops.
  Needs root, BTF (`/sys/kernel/btf/vmlinux`) and a node built with
  `-DWITH_USDT=ON`. Default engine of the driver.
- `ebpf_net_msgs.py`: BCC receiver, same interface, delivering a binary struct
  per event with `open_perf_buffer(..., lost_cb=...)`. Needs kernel headers in
  addition (`--engine bcc`).
- `bitcoin-trace` (in `src/`): IPC receiver. `-stats -json` prints per-second
  counters and a summary with the same schema as the eBPF receiver.
- `run_bench.py`: starts a regtest `bitcoin-node` with `-ipcbind=unix`, attaches
  the receiver, runs the flooder, samples node CPU/RSS, writes
  `results/<timestamp>-<mode>.json`, and `compare` prints a markdown table.

## Running

Build with both interfaces enabled: `cmake -B build -DENABLE_IPC=ON -DWITH_USDT=ON`.

```
contrib/tracing/bench/run_bench.py run --mode none
contrib/tracing/bench/run_bench.py run --mode ipc  --payload 8
contrib/tracing/bench/run_bench.py run --mode ebpf --payload 8
contrib/tracing/bench/run_bench.py compare contrib/tracing/bench/results/*.json
```

`--mode ebpf` prints a `sudo ... --pid ...` receiver command (also written to
`results/run_ebpf_receiver.sh`) and waits until you run it in another terminal;
the driver itself never needs root. With `--run-receiver` (non-interactive sudo, e.g. CI)
the driver starts the receiver itself. The eBPF side cannot run in containers
without BPF program loading permission (the load fails with "Unknown BPF object
load failure"); run it on a host or a VM instead.

## Reading the numbers

- `expected_events = 2 * pongs`, `drop % = 1 - (ping_in + pong_out) / expected`.
  This is independent of the receiver's own drop counter, which is also reported
  (`dropped` = queue-full drops for IPC, perf-buffer lost samples for eBPF).
- Node CPU% is utime+stime over the flood period, sampled from `/proc`.
- Latency is `now - event timestamp` when the receiver sees an event. Both the
  node (`std::chrono::steady_clock`) and eBPF (`bpf_ktime_get_ns`) use
  `CLOCK_MONOTONIC`, so the numbers are comparable. For IPC this includes queueing
  in the node and the batch RPC; for eBPF it includes the perf buffer and BCC's
  polling loop.
- The node's `msghand` thread is single-threaded and replies to every ping, so the
  achievable ping rate is bounded by the node, not by the flooder. Backpressure
  (`-maxreceivebuffer`, `-maxsendbuffer`) is left at defaults unless overridden.

The IBD (large messages) benchmark is only stubbed (`--mode ibd`); it needs a
synced local node to download from.
