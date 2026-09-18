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
- `libbpf-receiver/`: Rust (libbpf-rs) receiver, the default eBPF engine and
  the fair baseline: one fixed-size event per USDT hit into a BPF ring buffer,
  consumed without per-event allocation; drops are counted in the BPF program
  (failed `bpf_ringbuf_reserve`). Build with
  `cargo build --release --manifest-path contrib/tracing/bench/libbpf-receiver/Cargo.toml`
  (needs clang, libelf and zlib headers; `vmlinux.h` comes from the `vmlinux`
  crate, so no bpftool). On NixOS set `BPF_CLANG` to an unwrapped clang and
  `BPF_CFLAGS=-I<linux-headers>/include`. Needs root and BTF at runtime.
- `bpftrace_net_msgs.py`: bpftrace receiver (`--engine bpftrace`); one printf
  line per event, "Lost N events" counted as drops. Only needs BTF. Its single
  user-space formatting thread is the bottleneck at high rates.
- `ebpf_net_msgs.py`: BCC receiver (`--engine bcc`), binary struct per event via
  `open_perf_buffer(..., lost_cb=...)`, Python callback per event. Needs kernel
  headers.
- `bitcoin-trace` (in `src/`): IPC receiver (C++, libmultiprocess). `-stats -json`
  prints per-second counters and a summary with the same schema as the eBPF
  receivers.
- `ipc-receiver-rs/`: Rust IPC receiver (capnp-rpc, modeled on peer-observer's
  ipc-extractor). Compiles the repo's `src/ipc/capnp/*.capnp` with capnpc at
  build time, implements the `ThreadMap`/`Thread` and `NetMessageTrace`
  capabilities the node calls back into, and counts events straight from the
  Cap'n Proto readers. Build with
  `cargo build --release --manifest-path contrib/tracing/bench/ipc-receiver-rs/Cargo.toml`
  (needs the `capnp` compiler). Select with `--ipc-client rust`. About 3x
  cheaper per event than `bitcoin-trace` (0.08 vs 0.23 µs at ~500k events/s),
  because libmultiprocess converts every event into `std::string`-carrying
  structs while the Rust client reads fields in place.
- `run_bench.py`: starts a regtest `bitcoin-node` with `-ipcbind=unix`, attaches
  the receiver, runs the flooder, samples node CPU/RSS, writes
  `results/<timestamp>-<mode>.json`, and `compare` prints a markdown table.
  `--mode ebpf --engine libbpf|bpftrace|bcc` selects the eBPF receiver,
  `--mode ipc --ipc-client cpp|rust` the IPC receiver.

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
- Node CPU% is utime+stime over the flood period, sampled from `/proc`. Compare
  the per-work columns (node CPU µs per ping, receiver CPU µs per event):
  percentages hide throughput differences, e.g. eBPF halves the node's message
  rate while its CPU% stays flat.
- Latency is `now - event timestamp` when the receiver sees an event. Both the
  node (`std::chrono::steady_clock`) and eBPF (`bpf_ktime_get_ns`) use
  `CLOCK_MONOTONIC`, so the numbers are comparable. For IPC this includes queueing
  in the node and the batch RPC; for eBPF it includes the ring/perf buffer and
  the receiver's polling loop.
- IPC batching: the node waits up to `max_batch_wait_us` (default 1 ms,
  `bitcoin-trace -batchwait`) for a batch to fill. Per-call overhead dominates
  otherwise: at ~500k events/s, coalescing cut the node's extra CPU from 0.65 to
  0.21 µs/event and the receiver's from 1.13 to 0.23 µs/event.
- eBPF's cost to the node is the uprobe trap on every tracepoint hit (on the
  `msghand` thread), independent of the receiver; the receiver only determines
  how many events survive. IPC's cost is the enqueue plus the delivery thread.
- The node's `msghand` thread is single-threaded and replies to every ping, so the
  achievable ping rate is bounded by the node, not by the flooder. Backpressure
  (`-maxreceivebuffer`, `-maxsendbuffer`) is left at defaults unless overridden.

## Large messages

`p2p_ping_flood.py --ping-size N` sends pings with an N byte payload (the node
reads the 8 byte nonce and ignores the rest, up to the 4 MB message limit), so
the same driver measures large-message tracing: `run_bench.py run --mode ipc
--ping-size 1000000 --payload 4000000 --total 20000 --stages 0:20`. The node
bounds buffered payload bytes per subscriber (`max_queue_bytes`, default 64 MiB,
`-queuebytes`) and batch payload bytes (`max_batch_bytes`, default 4 MiB,
`-batchbytes`); large payload buffers are recycled through a small per-subscriber
pool so steady-state large messages do not allocate per event. Payloads of 4 KiB
and more are attached to the outgoing Cap'n Proto message as an external segment
(`capnp::Orphanage::referenceExternalData`, see `src/ipc/capnp/tracing-types.h`)
instead of being copied into it on the node's event-loop thread. Locally, full
capture of 1 MB messages then costs the calling thread one memcpy (~70 µs/MB)
and the event-loop thread ~150 µs/MB, mostly the kernel copy into the socket.
The libbpf receiver uses a second ring buffer with 4 MiB records for large payloads
(`--large-ring-mb`), like peer-observer's tiered rings.

The IBD benchmark itself is only stubbed (`--mode ibd`); it needs a synced local
node to download from. The large-ping flood covers the same message sizes.
