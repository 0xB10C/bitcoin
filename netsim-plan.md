# Large-scale in-process Bitcoin network simulator

Target: 10k–100k simulated nodes in one process, no TCP, real Bitcoin Core
networking code, simulated latency and simulated IP addresses. First goals are
topology formation (e.g. 20k listening / 80k non-listening) and address relay.
Block and transaction relay are explicitly out of scope for the MVP.

Investigated against `master` at `228877d783` (v32.99). All line references are
from that tree.

---

## 0. Status

The 100-node MVP is built and running. Code in `src/netsim/`, regression tests
in `src/test/netsim_tests.cpp`, driven by the `netsim_tests` suite.

There is also a standalone driver, `bitcoin-netsim`, built with
`cmake --build build --target bitcoin-netsim`. It takes `--nodes`,
`--listeners`, `--minutes`, `--bootstrap`, `--blocksonly`, `--seed` and
`--csv`, and reports what the run cost.

What works: real `AddrMan`, `CConnman` and `PeerManager` per node, no sockets
and no threads, a microsecond event queue with a region latency model and
ordered per-direction delivery, Core's own ladder choosing what to open,
full-relay plus block-relay-only plus feelers, connection teardown, inbound
eviction, and reproducible runs.

Measured over 100 nodes, 20 listening, 30 simulated minutes:

| | |
|---|---|
| Connections opened | 1165: 875 full-relay, 163 block-relay, 127 feeler |
| Still up at the end | 947 |
| Nodes filling all 8 outbound slots | 88 of 100 |
| Nodes left isolated | 0 |
| Addresses held, total | 1265 against 400 seeded |
| Circulating addresses pointing nowhere | 0 |
| Outbound attempts to a dead address | 0 |

Eviction is exercised separately, because a default node holds 189 inbound and
Core's protections shield around 28 candidates, so a population large enough to
evict is slow to simulate. With the connection budget cut to 51, giving 40
inbound slots, 50 nodes against 8 listeners produced 2537 evictions with no
listener ever over its cap and not one refusal.

Both blockers from §3 are resolved. AddrMan takes a per-instance seed, and the
listen flag is now per `CConnman` rather than the process-wide `fListen`;
without the second, three quarters of all circulating addresses pointed at
non-listening nodes.

`mapLocalHost` is still global, but no longer blocking: a node learns its own
address from the `addr_recv` field of its peer's VERSION, so the peer-reported
substitution path in `GetLocalAddrForPeer` produces the right answer as long
as the address universe uses `GetListenPort()`.

The graph export lands in `<prefix>-nodes.csv` and `<prefix>-edges.csv` via
`--export=PREFIX`, readable directly by networkx or igraph. Closed connections
are kept, marked `live=0`, because a feeler exists only for a moment and when
short-lived connections happened is the interesting part.

Still to do: churn and the extra networks in §12, the 20-minute chain-sync
timeout in §8, and the further production-fidelity steps in §11.

---

## 1. Verdict

This is feasible, and most of the machinery already exists in the test
utilities. Three facts carry the whole design:

1. **`CConnman::Init()` is a public inline that configures a fully usable
   `CConnman` with zero threads and zero sockets** (`src/net.h:1119`).
   `Start()` is what spawns the 4–7 threads per instance; nothing in the unit
   tests or fuzz harnesses ever calls it. `TestingSetup` already uses
   `Init()`-only (`src/test/util/setup_common.cpp:417-421`).

2. **`ProcessMessages()` and `SendMessages()` are directly callable from a
   single driver thread.** `src/test/fuzz/process_messages.cpp` is already a
   complete single-threaded driver: it takes
   `NetEventsInterface::g_msgproc_mutex` once for the whole run, uses
   `ImmediateBackgroundTaskRunner` so no scheduler thread exists, and pumps
   `ProcessMessagesOnce` / `SendMessages` in a loop. It drives one node with
   1–3 peers. The simulator is that harness generalised to N nodes.

3. **The byte-level loopback primitive already exists.**
   `ConnmanTestMsg::FlushSendBuffer` (`src/test/util/net.cpp:99`) drains a
   node's transport with `GetBytesToSend` / `MarkBytesSent`, and
   `NodeReceiveMsgBytes` (`src/test/util/net.cpp:91`) feeds bytes into a node
   with `ReceiveMsgBytes` + `MarkReceivedMsgsForProcessing`. Today
   `ReceiveMsgFrom` wires a node's output back into *itself*. The simulator
   only has to route node A's drained bytes to node B instead.

So the socket layer is not replaced so much as simply never used.
`CConnman::SocketSendData` already bails out cleanly when `m_sock` is null,
with the comment *"or in test cases without real connections"*
(`src/net.cpp:1639-1641`), leaving the bytes in the transport for us to drain.

---

## 2. Architecture

### 2.1 Per simulated node

| Component | Approach |
|---|---|
| `AddrMan` | Real, unmodified, one per node. Needs a per-instance seed (see §3.1). |
| `CConnman` | A `SimConnman` sibling of `ConnmanTestMsg`, constructed with per-node `nSeed0`/`nSeed1`, configured with `Init()` only. |
| `PeerManager` | Real, one per node. |
| `CNode` | Real, two per connection (one per side). |
| `Transport` | `V1Transport` for the MVP; a pass-through transport is an optional optimisation. |
| Self-address state | Currently process-global, must become per-node (see §3.2). |

`CConnman` has **no virtual functions at all**, so none of its methods can be
overridden. Access to the private connection machinery goes through the
existing `friend struct ConnmanTestMsg` pattern (`src/net.h:1912`); the
simulator adds one more friend or extends that struct.

### 2.2 Shared across all nodes

- One `NetGroupManager`, const, built from the embedded asmap. Sharing is safe
  and gives real ASN bucketing for free.
- One `ChainstateManager` (regtest, genesis only, forced out of initial block
  download) and one `CTxMemPool`. This is **required, not an optimisation**:
  the address path dereferences chainstate in two places. See §2.6.
- One logical clock, advanced by the driver.

### 2.3 Message plumbing

```
A: PeerManager::SendMessages
     -> CConnman::PushMessage -> A's transport
driver: GetBytesToSend / MarkBytesSent        (FlushSendBuffer)
     -> event queue, deliver at now + latency(A,B)
B: ReceiveMsgBytes + MarkReceivedMsgsForProcessing   (NodeReceiveMsgBytes)
     -> PeerManager::ProcessMessages
```

Keeping `V1Transport` means real serialisation, real 24-byte headers, real
checksums and realistic message sizes, for a cost we can measure before
deciding to remove it. If it turns out to matter, `MakeTransport`
(`src/net.cpp:4103`) is a file-static function with exactly one call site in
the `CNode` constructor (`src/net.cpp:4123`) — a one-line seam for a
pass-through `Transport`. Use V1, not V2: `V2Transport` embeds a whole
`V1Transport` as its fallback plus a `BIP324Cipher`, and generates a keypair
per connection.

### 2.4 Event loop

Single-threaded, one priority queue keyed on simulated time. Event kinds:

- `DELIVER(dst, conn, bytes)` — hand bytes to the destination node
- `PROCESS(node)` — `ProcessMessages` then `SendMessages` until no more work
- `OPEN_CONN(node)` — one outbound attempt, re-armed every 500 ms
- `TICK(node)` — periodic work the scheduler would normally do

Single-threaded is not a limitation we chose; it is forced. `cs_main`,
`NetEventsInterface::g_msgproc_mutex` and mock time are all process globals, so
any parallel version has to shard all three first.

### 2.5 Connection establishment

Do not go through `CConnman::ConnectNode` — it performs real DNS lookups and
real socket connects, and the two `Connect*` functions it calls are plain
functions with no injection hook.

Instead, reuse the seam already built on branch `2026-06-simulations-34019`:
`CConnman::TryPickOutboundAddress(anchor, conn_type, feeler,
outbound_ipv46_peer_netgroups, preferred_net)`, extracted from
`ThreadOpenConnections` in commit `1dfd725c93`. The simulator calls it, then
creates the `CNode` pair itself and calls `InitializeNode` on both sides.

Honour two pieces of real pacing in simulated time:

- `ThreadOpenConnections` sleeps a hard 500 ms per iteration
  (`src/net.cpp:2667`), so a node fills 10 outbound slots in at least 5
  simulated seconds.
- The outbound semaphore caps in-flight attempts at `m_max_automatic_outbound`.

Inbound: the simulator looks the destination up in a listener map, applies
`m_max_inbound`, and calls the real `AttemptToEvictConnection` when full.
With default options (`DEFAULT_MAX_PEER_CONNECTIONS = 200`,
`src/net.h:82`): 8 full-relay + 2 block-relay + 1 feeler outbound, leaving
`m_max_inbound = 189` and `m_max_inbound_full_relay = 94`.

For the 20k listening / 80k non-listening target, 100k nodes × 10 persistent
outbound = 1M connections, which is ~50 inbound per listener. Comfortably under
the 189 cap, so inbound eviction will rarely fire. Worth knowing before
drawing conclusions about eviction.

### 2.6 Why a chainstate is still needed

The address path is not chainstate-free:

- `MaybeSendAddr` gates self-announcement on
  `!m_chainman.IsInitialBlockDownload()` (`src/net_processing.cpp:5742`). In
  IBD a node never advertises itself, which would silence the entire
  experiment.
- `SendMessages` unconditionally does
  `if (m_chainman.m_best_header == nullptr) m_chainman.m_best_header =
  m_chainman.ActiveChain().Tip();` (`src/net_processing.cpp:6111-6113`) on the
  same pass that calls `MaybeSendAddr`.
- `ConsiderEviction` reads `ActiveChain().Tip()->nChainWork`
  (`src/net_processing.cpp:5516`).

One shared regtest chainstate out of IBD satisfies all three. `CTxMemPool` is
genuinely untouched on the address path; the reference is only stored in
`TxDownloadMan` at construction, so one shared empty instance is fine.

Also call `PeerManager::SetBestBlock()`. If it is never called,
`m_best_block_time` stays at zero, `ApproximateBestBlockDepth()` becomes
astronomically large, and `GetDesirableServiceFlags()` always demands
`NODE_NETWORK | NODE_WITNESS` — so simulated nodes must advertise both or
outbound handshakes get dropped.

---

## 3. Required changes

### 3.1 Per-instance AddrMan seed — blocker

```cpp
AddrManImpl::AddrManImpl(const NetGroupManager& netgroupman, bool deterministic, int32_t ratio)
    : insecure_rand{deterministic}
    , nKey{deterministic ? uint256{1} : insecure_rand.rand256()}
```
`src/addrman.cpp:90-92`

Neither existing mode works. With `deterministic=true` every node gets
`nKey == uint256{1}` and a zero-key ChaCha20, so all 100k nodes bucket
identically and make identical `Select()` choices. With `deterministic=false`
the key comes from the global RNG, which is realistic but not reproducible
except through global call ordering.

Fix: accept an optional `uint256` seed and use the existing
`FastRandomContext(const uint256&)` constructor. Roughly five lines across
`src/addrman.cpp:90`, `src/addrman.h:115`, `src/addrman_impl.h:110`.

### 3.2 Per-node self-address state — blocker for the addr-relay goal

`mapLocalHost` (`src/net.h:189`), `fListen` and `fDiscover`
(`src/net.h:177-178`), and `g_reachable_nets` (`src/netbase.h:172`) are all
process globals. `GetLocalAddrForPeer` (`src/net.cpp:241-268`) reads
`mapLocalHost`, so **every simulated node would announce the same address**,
and `MaybeSendAddr` gates on the single global `fListen`, so the listening /
non-listening split cannot be expressed.

This matters more than it first appears, because of §4: self-announcements are
the only thing that propagates multi-hop. Getting them wrong means there is no
address relay to measure. These need to move into `CConnman` (or a per-node
context) for the simulator.

Two smaller globals in the same family, worth knowing about but probably
harmless here: `proxyInfo[]` and `nameProxy` are file-scope statics in
`src/netbase.cpp:33-35`, so proxy configuration is process-wide; and
`net_processing.cpp:5850` has a function-local
`static const CAmount MAX_FILTER{m_fee_filter_rounder.round(MAX_MONEY)}`, which
is computed once from whichever node reaches it first and then reused for every
node forever. It only affects fee filters, which the MVP does not exercise, but
it is the kind of cross-node contamination to grep for.

### 3.3 Per-node PeerManager RNG seed

`PeerManager::Options::deterministic_rng` (`src/net_processing.h:105`) has the
same zero-key-only flaw as AddrMan. Same shape of fix.

### 3.4 Close the global-RNG leaks

For reproducibility, route these through the owning object's RNG instead of a
fresh `FastRandomContext{}`:

- `src/net_processing.cpp:5720` — ping nonce
- `src/net_processing.cpp:1741`, `1774`, `2169`, `2239`
- `src/net.h:1883` — `NodesSnapshot` shuffle, hit every message-handler pass
- `src/net.cpp:415`, `2582`, `3186`, `3611`, `3867`

Wire in the `g_used_g_prng` / `g_used_system_time` tripwires from
`src/test/fuzz/util/check_globals.cpp:15-56` so any remaining leak aborts
instead of silently de-randomising a run.

### 3.5 Works today, no patch needed

- Per-node `nSeed0`/`nSeed1` on `CConnman`. Required, not optional:
  `RelayAddress`'s destination choice is
  `GetDeterministicRandomizer(RANDOMIZER_ID_ADDRESS_RELAY)`
  (`src/net_processing.cpp:2536`), so nodes sharing seeds pick correlated relay
  destinations and the topology degenerates.
- `Init()` only, never `Start()`.
- One `LOCK(g_msgproc_mutex)` for the whole run.
- `ImmediateBackgroundTaskRunner` instead of `CScheduler`. Never call
  `PeerManager::StartScheduledTasks`; drive `CheckForStaleTipAndEvictPeers`
  from the event loop.
- `CCheckQueue` with zero worker threads, and
  `script_execution_cache_bytes = signature_cache_bytes = 0` on the shared
  chainstate. Left at their defaults, `ValidationCache` eagerly allocates and
  touches 32.25 MiB. The precedent is
  `src/test/util/setup_common.cpp:317-318`.
- Pass `BanMan* = nullptr` to every `PeerManager`. It is the one nullable
  constructor argument and every use is guarded. A per-node `BanMan` would cost
  539 KiB each for its discouragement filter. The cost of saying no is that the
  ban and discourage checks in `ProcessAddrs`
  (`src/net_processing.cpp:6024-6028`) are skipped, which is fine as long as
  nothing in the simulation misbehaves.
- `consistency_check_ratio = 0` on every AddrMan, or each operation walks the
  whole table.
- No `-debug`, and `Logger::DisableLogging()`. `LogDebug` with its category off
  costs one relaxed atomic load, but `LogInfo` is unconditional and does a
  `SystemClock::now()` plus a thread-name string allocation *before* any
  enablement check (`src/util/log.h:61-70`). Audit the `LogInfo` calls on net
  startup paths; several fire once per node.
- Build without `DEBUG_LOCKORDER`.

---

## 4. The finding that shapes the addr-relay experiment

`ProcessAddrs` only gossips an address onward if **all three** of these hold
(`src/net_processing.cpp:6030-6033`):

```cpp
if (addr.nTime > current_time - 10min && vAddr.size() <= 10 && addr.IsRoutable())
    RelayAddress(pfrom.GetId(), addr, reachable);
```

The `vAddr.size() <= 10` clause means **a 1000-entry GETADDR response is
stored but never forwarded**. Multi-hop propagation is carried almost entirely
by self-announcements, which:

- fire once per connection immediately after verack, in their own message
- then repeat every `AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL = 24h`
  (`src/net_processing.cpp:165`), resetting `m_addr_known` first so the
  re-announcement can escape
- fan out to 2 peers per hop, chosen deterministically by SipHash over
  (address, 24h time bucket, peer id), stable for ~24h and rotating at
  `ROTATE_ADDR_RELAY_DEST_INTERVAL = 24h`

Meanwhile the receiving side admits only `MAX_ADDR_RATE_PER_SECOND = 0.1`
addresses per second steady-state, with a 1000-token bucket that starts at 1.0
and gets a one-off +1000 after we send a GETADDR
(`src/net_processing.cpp:199-205`, `4032`).

So the simulation's address dynamics are: a large one-shot GETADDR dump per new
connection that seeds the table but does not spread, plus a slow 24-hour
self-announcement gossip that does. Any result about propagation time depends
on getting §3.2 right.

---

## 5. Memory

Sizes measured directly from this tree (compile-time `static_assert` probe):

| Type | Bytes |
|---|---|
| `AddrManImpl` | 655,872 |
| `AddrInfo` | 128 |
| `CNode` | 1,024 |
| `V1Transport` | 440 |
| `V2Transport` | 1,448 |
| `CAddress` | 56 |
| `CNetAddr` | 32 |
| `Peer` | 648 (664 as a `shared_ptr` block) |
| `PeerManagerImpl` | 1,576 |
| `CConnman` | 1,152 |
| `ChainstateManager` | 2,320 + 32.25 MiB of validation caches |

`AddrManImpl` is 640.5 KiB **per node regardless of content**, because
`vvNew[1024][64]` and `vvTried[256][64]` are fixed C arrays of `int64_t`
(`src/addrman_impl.h:206-212`, `nid_type = int64_t` at `:40`), and the
constructor memsets all 81,920 slots to -1.

Per distinct address held, roughly 250 bytes: a `mapInfo` node (128-byte
`AddrInfo` plus key and link), a `mapAddr` node, a `vRandom` slot, and the two
hash tables' bucket arrays.

Per connection, counting both ends and ignoring bloom filters, about 10 KiB:

| Term (both ends) | Bytes |
|---|---|
| 2 × `CNode` inline | 2,048 |
| 2 × `mapRecvBytesPerMsgType`, 37 tree nodes each | 5,328 |
| 2 × `Peer` as a `shared_ptr` block | 1,328 |
| 2 × `V1Transport` | 880 |
| 2 × `CNodeState` plus its map node | 400 |
| 2 × `m_peer_map` node, `m_addr_name` string | ~190 |

The largest single term is a surprise: `mapRecvBytesPerMsgType` is
unconditionally pre-filled with 37 red-black-tree nodes in the `CNode`
constructor (`src/net.cpp:4143-4147`), about 2.7 KiB per `CNode` whether or not
any message ever arrives.

One more per-peer term to keep an eye on: `Peer::m_addrs_to_send` is a
`std::vector<CAddress>` capped at 1000 entries
(`src/net_processing.cpp:343`), so 56 KB per peer in the worst case. It is
nearly empty in steady state but fills right after a GETADDR response is
queued, which is exactly the start of every connection. At 1M connections that
transient is worth measuring rather than assuming.

So, with `A` = distinct addresses each node ends up holding:

```
M(N, A) = N * (640.5 KiB  +  100 KiB  +  250 B * A)
                addrman      10 conns    addrman content
```

| Nodes | A = 2,000 | A = 5,000 | A = 20,000 |
|---|---|---|---|
| 10,000 | 12 GiB | 19 GiB | 55 GiB |
| 100,000 | 120 GiB | 191 GiB | 549 GiB |

Add 15–20% for allocator overhead and fragmentation.

**`A` is the whole story.** It is not a free parameter: with 20k listening
nodes, each node converges toward holding most of them. A new connection yields
up to 1000 addresses immediately from its GETADDR response, times 8 full-relay
outbound, so `A` reaches several thousand within simulated minutes and then
creeps upward. The underlying cost is quadratic — `N` nodes each storing
`O(listeners)` addresses.

Practical sizing: **10k nodes fits in 64–96 GB. 100k nodes wants 512 GB–1 TB**,
and the run will grow into it as the tables fill, so instrument `A` and
watch it rather than trusting a single up-front number.

### 5.1 Measured, and one correction

The estimate above is wrong in one important way, and it is wrong because of an
instruction to ignore bloom filters: the dominant term *is* a bloom filter.

`bitcoin-netsim` reports its own resident set, one fresh process per point, 30
simulated minutes, listeners at a fifth of the population but never below 12:

| Nodes | Default | Blocks-only | Ratio |
|---|---|---|---|
| 25 | 8.39 MB/node | 1.17 MB/node | 7.2x |
| 50 | 8.32 MB/node | 1.17 MB/node | 7.1x |
| 100 | 9.74 MB/node | 1.26 MB/node | 7.7x |
| 200 | 9.95 MB/node | 1.29 MB/node | 7.7x |
| 400 | 9.95 MB/node | 1.30 MB/node | 7.7x |
| 800 | 9.96 MB/node | 1.31 MB/node | 7.6x |

In absolute terms, 800 nodes costs 7.78 GB by default and 1.02 GB
blocks-only. The figure is flat from 200 nodes upward; the lower numbers at 25
and 50 are simply a lower average degree, since 12 listeners cannot absorb
8 outbound connections from every node.

The gap is `Peer::TxRelay::m_tx_inventory_known_filter`, a 527 KiB rolling
bloom allocated eagerly for every peer that offers transaction relay. No
transaction is ever relayed in these runs. Advertising `fRelay=false`, which is
what `--blocksonly` does, stops the peer allocating it and costs nothing in
fidelity for a study of topology or address relay.

What actually predicts the measurement is peer count, not node count:

```
per node  ~=  700 KB                       fixed: AddrMan tables, connman, peerman
            + peers * 27 KB                Peer::m_addr_known, per addr-relay peer
            + peers * 513 KB               Peer::TxRelay, unless fRelay=false
            + 250 B * A                    addresses held
```

At 16 peers that gives 1.13 MB blocks-only against 1.17 measured, and 9.3 MB
default against 8.3 to 9.9 measured. So the figure moves with the average
degree, which moves with the listener ratio, and quoting one number per node
without saying how many peers it has is meaningless.

The `250 B * A` term is the one that is not flat. Addresses held per node runs
at roughly half the listener count after 30 simulated minutes (71 per node at
160 listeners, 39 at 80, 22 at 40), and it keeps climbing with run length
toward the listener count itself. So extrapolation needs two figures:

| 100k nodes, 20k listening | Default | Blocks-only |
|---|---|---|
| Flat part, from the table | 1.0 TB | 131 GB |
| Plus `A` at half the listeners | 1.2 TB | 360 GB |
| Plus `A` fully converged | 1.5 TB | 630 GB |

Which is to say: **a 100k-node run is a 256 GB to 1 TB machine depending on
whether transaction relay is advertised, and the address tables are what grows
during the run.** Instrument `A` and watch it rather than trusting a figure
taken at the start.

### 5.2 A CPU trap worth more than the memory numbers

A node that cannot fill its outbound slots costs about a hundred times more to
simulate than one that can. Each attempt runs up to 100 `AddrMan::Select()`
calls, and `Select` on a sparse table is some 590 times dearer than on a full
one: the bench pair `AddrManSelectFromAlmostEmpty` and `AddrManSelect` read
38 µs against 65 ns, because selection probes random slots until it finds an
occupied one.

The practical consequence: a run with fewer than 8 listeners never finishes,
because no node can ever fill 8 outbound slots and every node therefore probes
forever. One listener with 100 nodes does not complete a single simulated
minute in two hours of wall clock. Twenty listeners with 100 nodes completes 30
simulated minutes in seconds. Keep the address universe rich enough that nodes
saturate, and treat an unexpectedly slow run as a sign that they cannot.

Two cheap reductions if they are ever wanted, neither needed up front:
`nid_type` to `int32_t` halves the fixed tables and saves ~31 GiB at 100k
nodes; making `mapRecvBytesPerMsgType` lazy saves ~5 GiB.

Also cap the per-node queues. Defaults are 5 MB receive flood and 1 MB send
buffer (`src/net.h:101-102`), i.e. ~6 MB worst case per node, which at scale
dwarfs everything else if back-pressure is ever not driven.

---

## 6. CPU

Measured with `bench_bitcoin` on this laptop (24 cores, powersave governor and
turbo on, so treat as ±20%):

| Operation | Cost |
|---|---|
| `AddrMan::Add`, per address | 676 ns |
| `AddrMan::Select` | 65 ns |
| `AddrMan::GetAddr` (23%, capped at 1000, 16k-entry table) | 59.6 µs |
| `CRollingBloomFilter` insert + query | 226 ns |

`AddrManAdd` reports 11.07 ms per op but inserts 64 × 256 = 16,384 addresses,
hence the per-address figure.

Worked estimate for 100k nodes:

- **Topology formation**: 1M connections, each preceded by a handful of
  `Select()` calls and filter checks. Well under a minute of CPU. The limit is
  simulated time, not CPU — the 500 ms cadence means a node needs ≥5 simulated
  seconds to fill its outbound slots.
- **Initial GETADDR burst**: 1M responses at 59.6 µs is ~60 s, plus up to
  1M × 1000 addresses inserted at the receivers, ~11 CPU-minutes.
- **Steady-state gossip**: bounded above by the inbound rate limit at
  2M links × 0.1/s × 86,400 s = 17.3 billion address records per simulated day.
  Realistic traffic is far below that, and most records are duplicates that
  early-out in `AddSingle`. Expect order 10^10 address-processing events for
  the first simulated day of convergence, at a few hundred ns each.

**Order 1–5 CPU-hours per simulated day at 100k nodes, single-threaded.** CPU
is not the constraint; memory is. One hot spot to watch: `RelayAddress` walks
every peer under `m_peer_mutex` for each accepted address
(`src/net_processing.cpp:2546-2559`).

---

## 7. Implementation sketch

### 7.1 Where it lives: a standalone binary from day one

Do **not** start inside a Boost test. It is not needed, and it would have to be
undone.

The thing that made a unit test tempting was scaffolding: a
`ChainstateManager` needs block storage, a validation cache, a coins view and
`ValidationSignals` wired together, and `TestingSetup` already does all of it.
But `test_util` is a plain `STATIC` library
(`src/test/util/CMakeLists.txt:5-21`) with **zero references to
`boost/test`** anywhere in `src/test/util/`. The Boost.Test dependency lives
only in `test_bitcoin`, never in the scaffolding itself.

The fuzz binary already proves the pattern: it has its own `main()`, links the
test scaffolding, and instantiates `MakeNoLogFileContext<TestingSetup>()`
directly (`src/test/fuzz/process_message.cpp:48`). The simulator does the same.

So: a new `bitcoin-netsim` target, `EXCLUDE_FROM_ALL`, linking `test_util`
alongside `bitcoin_node`. Own `main()`, own CLI arguments, own event loop, own
output. Full chainstate for free, and no later refactor.

What a Boost test would have cost, concretely: Boost owns `main()`, so CLI
knobs arrive through `--` passthrough or environment variables; its logging and
timeouts fight a long-running process; progress reporting and checkpointing
have nowhere to go; and `ctest` would cheerfully start running a 100k-node
simulation in CI. None of that touches the simulator *logic*, which is why the
refactor would have been annoying rather than fatal. There is simply no reason
to pay it.

Keep one small Boost test as well, `src/test/netsim_tests.cpp`, exercising the
two-node handshake and the address-relay assertion against the same library.
That is a cheap regression guard that keeps the core honest, and it costs
nothing because the library is shared.

Construct the environment with `TestOpts` set for a simulation rather than a
test:

```cpp
TestOpts opts;
opts.setup_net = false;              // we build our own connmans
opts.min_validation_cache = true;    // kills the 32.25 MiB validation cache
opts.extra_args = {"-checkaddrman=0", "-nodebuglogfile"};
auto env = MakeNoLogFileContext<TestingSetup>(ChainType::REGTEST, opts);
static_cast<TestChainstateManager&>(*env->m_node.chainman).JumpOutOfIbd();
```

One known wart to patch locally: `src/test/util/setup_common.cpp:308` hardcodes
`.check_block_index = 1` and ignores any `-checkblockindex` argument.
`CheckBlockIndex` is a whole-structure walk, so it is free with only a genesis
block but would become a serious tax the moment block relay is added.

Layout:

```
src/netsim/
  env.{h,cpp}        shared chainman / mempool / warnings / netgroupman / clock
  node.{h,cpp}       SimNode: addrman + connman + peerman + its CNode list
  link.{h,cpp}       the two CNode ends of a connection, plus latency
  pump.{h,cpp}       drain, deliver, process
  loop.{h,cpp}       event queue and the simulated clock
  topology.{h,cpp}   outbound selection, inbound accept, eviction, teardown
  addresses.{h,cpp}  synthetic address universe
  metrics.{h,cpp}    CSV output and resident-memory sampling
  main.cpp
```

### 7.2 Node construction

This is the wiring copied from `src/test/util/setup_common.cpp:404-421`, with
per-node seeds substituted. The construction order matters: connman first,
then peerman with a reference to it, then `Init()` with the peerman as
`m_msgproc`.

```cpp
struct SimNode {
    uint32_t sim_id;
    CService self;                      // its own address, port 8333
    bool listening;
    std::unique_ptr<AddrMan> addrman;
    std::unique_ptr<ConnmanTestMsg> connman;
    std::unique_ptr<PeerManager> peerman;
    std::vector<CNode*> conns;          // owned, raw (AddTestNode takes no ref)
};

std::unique_ptr<SimNode> MakeNode(SimEnv& env, uint32_t id)
{
    auto n = std::make_unique<SimNode>();
    n->sim_id = id;
    n->addrman = std::make_unique<AddrMan>(env.netgroupman,
                                           /*seed=*/NodeSeed(id),   // needs §3.1
                                           /*consistency_check_ratio=*/0);
    n->connman = std::make_unique<ConnmanTestMsg>(Seed0(id), Seed1(id),
                                                  *n->addrman, env.netgroupman,
                                                  Params());
    PeerManager::Options po;
    po.max_extra_txs = 0;
    n->peerman = PeerManager::make(*n->connman, *n->addrman, /*banman=*/nullptr,
                                   env.chainman, env.mempool, env.warnings, po);
    CConnman::Options co;
    co.m_msgproc = n->peerman.get();
    co.m_local_services = ServiceFlags(NODE_NETWORK | NODE_WITNESS);
    co.nSendBufferMaxSize = 1 << 20;
    co.nReceiveFloodSize  = 1 << 20;
    n->connman->Init(co);               // never Start()
    return n;
}
```

Environment setup, once: `NetGroupManager::NoAsmap()` (or an embedded asmap
later), `chainman.JumpOutOfIbd()` from `src/test/util/validation.h:48` so
self-announcement is not gated off, `peerman->SetBestBlock()` on every node so
service-flag expectations behave, and one
`LOCK(NetEventsInterface::g_msgproc_mutex)` held for the entire run.

### 7.3 The message pump

This is the heart of the whole thing, and it is short. `CNode::m_transport`
and `CNode::vSendMsg` are both public, so the drain is just
`CConnman::SocketSendData` with the socket removed:

```cpp
// Drain one node's pending output into a byte buffer.
std::vector<uint8_t> Drain(CNode& node)
{
    std::vector<uint8_t> out;
    LOCK(node.cs_vSend);
    while (true) {
        if (!node.vSendMsg.empty()) {
            if (node.m_transport->SetMessageToSend(node.vSendMsg.front())) {
                node.vSendMsg.pop_front();
            }
        }
        const auto& [to_send, more, msg_type] =
            node.m_transport->GetBytesToSend(!node.vSendMsg.empty());
        if (to_send.empty()) break;
        out.insert(out.end(), to_send.begin(), to_send.end());   // copy first
        node.m_transport->MarkBytesSent(to_send.size());
    }
    node.m_send_memusage = 0;
    node.fPauseSend = false;
    return out;
}
```

Delivery is one existing call,
`ConnmanTestMsg::NodeReceiveMsgBytes(dst, bytes, complete)`, which does
`ReceiveMsgBytes` plus `MarkReceivedMsgsForProcessing`. Processing is
`ProcessMessagesOnce(node)` in a loop until it returns false, then
`SendMessages(node)`.

Do not reuse `ConnmanTestMsg::FlushSendBuffer` for this. It clears `vSendMsg`
before draining, so it throws the queued messages away. It exists to discard
fuzzer output, not to move it.

### 7.4 Links and the event loop

```cpp
struct Link {
    SimNode* out_side;  CNode* out_node;   // the initiator
    SimNode* in_side;   CNode* in_node;    // the acceptor
    std::chrono::milliseconds latency;
};
```

A single priority queue keyed on simulated time, with four event kinds:

- `DELIVER(link, direction, bytes)` scheduled at `now + latency`
- `PROCESS(node)` after any delivery into that node
- `OPEN_CONN(node)` re-armed every 500 ms, mirroring
  `ThreadOpenConnections`' hard sleep at `src/net.cpp:2667`
- `TICK(node)` for the periodic work the scheduler normally does, chiefly
  `CheckForStaleTipAndEvictPeers` every 45 s

### 7.4.1 Mock time is second-resolution. Plan around it.

This is the one thing that genuinely complicates a latency simulation.
`SetMockTime` takes `std::chrono::seconds` and stores it in a
`std::atomic<std::chrono::seconds>` (`src/util/time.cpp:32`, `:53-57`).
`NodeClock::now()` reads that directly (`src/util/time.cpp:38-50`). So even
though net_processing asks for microseconds via
`GetTime<std::chrono::microseconds>()`, **the value it gets is quantised to
whole seconds**. A 40 ms link delay is invisible to the node's own clock.

The resolution is to decouple the two notions of time:

- **The event queue runs at microsecond resolution.** It decides ordering and
  causality, so latency is modelled exactly and a 40 ms link really does
  deliver 40 ms later than a 0 ms one, in the right order relative to every
  other event.
- **Mock time advances in whole seconds.** It decides only what the nodes
  *believe* the time is, which drives their timers.

That split is sound because every timer in the address path operates on scales
far above one second: 30 s average address broadcast, 24 h self-announcement,
2 min ping, 2 min feeler, and a rate limiter that refills at 0.1 addresses per
second. Second-granularity belief is plenty. Two consequences to keep in mind:
timers armed for a fractional offset fire at the next second boundary, and
several messages landing in the same simulated second see a zero time delta in
the address rate limiter, so no tokens refill. Both are acceptable, and
arguably realistic.

If sub-second timer fidelity ever matters, widening `g_mock_time` to
microseconds is a small change in `src/util/time.cpp`, but it touches a global
used across the whole codebase. Do not do it for the MVP.

### 7.4.2 Delivery must stay ordered per direction

The links carry TCP semantics, so bytes must arrive in the order they were
sent. A naive `now + latency + jitter` can reorder two sends on the same link
when the jitter on the second is smaller than on the first. Clamp it:

```cpp
arrival = std::max(now + model.Sample(a, b, rng), last_arrival[link][dir] + 1us);
last_arrival[link][dir] = arrival;
```

Each direction of each link therefore needs its own in-flight queue and its own
last-arrival watermark, not a single shared bag of events.

### 7.4.3 Latency model

Keep it behind an interface from the start so real measurements can replace it:

```cpp
struct LatencyModel {
    virtual std::chrono::microseconds Sample(uint32_t from, uint32_t to,
                                             FastRandomContext& rng) const = 0;
    virtual ~LatencyModel() = default;
};
```

MVP implementation: give each node a region, take one-way delay from a small
region-by-region base matrix, add bounded jitter. Bandwidth and queueing can
arrive later as a serialisation delay of `bytes / bandwidth` added to the same
`Sample` result, which is why the byte count should be passed through even if
the MVP ignores it.

### 7.5 Connections

Do not call `ConnectNode`; it does real DNS and real socket work, and the two
functions it delegates to have no injection hook. Instead:

1. `TryPickOutboundAddress(...)` from the existing extraction on branch
   `2026-06-simulations-34019` picks the address, using the real netgroup and
   service-flag filters.
2. The simulator looks the address up in a listener map. A miss, or a listener
   at `m_max_inbound`, is a failed connection, and the simulator calls
   `AttemptToEvictConnection` on the listener when it is full.
3. On success, construct the `CNode` pair with `new CNode(...)`, one
   `OUTBOUND_FULL_RELAY` and one `INBOUND`, pass a null `std::shared_ptr<Sock>`
   (the constructor never dereferences it), then `InitializeNode` on both sides
   and `AddTestNode` into each connman.

### 7.6 Address universe

Generate routable IPv4 addresses placed in distinct /16s so netgroup logic has
something to work with, from a seeded RNG so runs reproduce. Reserve the first
`L` for listeners at port 8333 and give the rest to non-listening nodes.
Addresses must pass `IsRoutable()`, so avoid the private, loopback, link-local
and shared-address ranges. Real prefix and ASN data can be swapped in later
behind the same interface.

---

## 8. Challenges

Roughly in order of how likely they are to cost a day.

**Runs stop being valid at 20 simulated minutes, and the graph export is what
revealed it.** Outbound full-relay peers start getting disconnected in a wave
at about minute 22. The cause is `ConsiderEviction`
(`src/net_processing.cpp:5514`): an outbound peer that has not announced a
block with as much work as our tip within `CHAIN_SYNC_TIMEOUT`, which is 20
minutes, gets one `getheaders` and then a disconnect. Every node here sits on a
genesis-only chain and never announces anything, so every unprotected outbound
peer times out together.

This is Core behaving correctly given a static chain, not a simulator bug, but
it is an artefact of block relay being out of scope and it corrupts any
long-horizon measurement: at 30 simulated minutes, 91 of 875 full-relay
connections had been shed and reopened for this reason alone.

Until it is addressed, keep runs under 20 simulated minutes, or read anything
past that point knowing a disconnection wave is mixed into it. The fix belongs
with block relay: either give the shared chainstate a tip the nodes actually
announce to each other, or keep headers sync from starting so `fSyncStarted`
stays false and `ConsiderEviction` returns immediately. The first is more
faithful; the second is a one-line gate and enough for topology and address
work.

**Per-node self-address state.** Covered in §3.2. It is the one blocker that
cannot be worked around, because self-announcement is the only thing that
propagates multi-hop (§4). Until `mapLocalHost` and `fListen` are per-node,
every node announces the same address and there is no relay to measure.

**Per-node AddrMan seed.** Covered in §3.1. Small patch, but without it the
whole population is one node cloned 100,000 times.

**Handshake ordering.** `InitializeNode` does not send VERSION. The outbound
VERSION is pushed lazily from `SendMessages`
(`src/net_processing.cpp:6067-6070`), and `ProcessMessages` refuses to do
anything for an outbound peer until that has happened
(`src/net_processing.cpp:5430`). So the pump must call `SendMessages` before
`ProcessMessages` on every new outbound link, or the simulation deadlocks
silently with zero messages in flight. This is the first thing that will go
wrong and it looks like nothing happening.

**Back-pressure flags.** `fPauseSend` and `fPauseRecv` are set from the real
buffer thresholds. Nothing clears them if no socket thread runs, so the pump
has to drive them. Left alone, nodes quietly stop sending partway through a
run. The default limits are 5 MB receive and 1 MB send per node, which also
need lowering at scale.

**Node lifecycle.** `AddTestNode` deliberately skips `AddRef` and
`InitializeNode`, and `ClearTestNodes` skips `FinalizeNode`. The simulator must
own the whole lifecycle, because `FinalizeNode` asserts that its per-peer
counters return to zero when the peer map empties
(`src/net_processing.cpp:1818-1826`). Honouring `fDisconnect` matters too:
feelers kill themselves in the VERSION handler before verack, and addr-fetch
connections disconnect on their first useful response or after 5 minutes. Ignore
`fDisconnect` and those accumulate forever.

**Private helpers on CConnman.** `CConnman` has no virtual functions at all, so
nothing can be overridden. `GetNewNodeId` and the keyed-netgroup calculation
are private. Friendship is not inherited, so deriving from `ConnmanTestMsg`
does not grant access. Either extend `ConnmanTestMsg` with the few accessors
needed, or compute node ids and netgroup keys in the simulator. The keyed
netgroup only feeds eviction grouping, so a deterministic hash of the real
netgroup is good enough until eviction is being studied.

**Mock time is second-resolution.** The sharpest edge for a latency-focused
simulation, covered in §7.4.1. `SetMockTime` stores whole seconds, so the
nodes' own clock cannot see a 40 ms link delay. The fix is to run the event
queue at microsecond resolution and let mock time advance in whole seconds,
which works because every timer that matters here operates well above one
second. Decide this on day one, because retrofitting a second notion of time
into a loop that conflated them is unpleasant.

**Ordered delivery.** Jitter can reorder two sends on one link, which TCP never
would. Each direction needs its own last-arrival watermark, per §7.4.2.

**One global clock.** Nodes cannot disagree about now, since mock time is a
single process-wide atomic. Probably fine, and per-node clocks would need a
patch to `NodeClock::now()`. Note also that mock time cannot be zero, since
zero is the sentinel meaning "not mocked".

**Determinism leaks.** Several net and net_processing paths draw from the
global RNG rather than an injectable context, including the ping nonce and the
per-pass node shuffle. Wire in the `g_used_g_prng` and `g_used_system_time`
tripwires from `src/test/fuzz/util/check_globals.cpp` so a leak aborts instead
of silently de-randomising a run.

**Allocation count, not just bytes.** At 100k nodes the process holds on the
order of 10^8 live allocations, most of them small. glibc malloc will not love
this. Expect fragmentation to add noticeably to the §5 table, and consider an
arena or a different allocator before blaming the design.

**Logging.** `LogDebug` with its category off is nearly free, but `LogInfo` is
unconditional and does a `SystemClock::now()` plus a thread-name string
allocation before any enablement check. Several `LogInfo` calls fire once per
node on net startup paths, which at 100k nodes is 100k lines through one
global mutex.

**V1 transport needs chain params.** `V1Transport`'s constructor reads
`Params().MessageStart()`, so `SelectParams` must have run before any `CNode`
is built. Inside `TestingSetup` this is already true.

---

## 9. Phasing

Phases 0 and 1 are done, and Phase 1b has been walked as far as 800 nodes for
the memory measurements in §5.1. This section is kept as written because the
reasoning behind the order still applies to the rungs above; §0 is the record
of where things actually stand.

**Phase 0 — prove the mechanism.** *(done)* `src/test/netsim_tests.cpp` on top of
`TestingSetup`, per §7.1. Two nodes, one link, the pump from §7.3, and a real
VERSION/VERACK handshake with no sockets. Then prepopulate one node's addrman
with synthetic addresses, connect the other to it, and assert the addresses
arrive via GETADDR. That single test exercises the handshake, the transport,
`ProcessAddrs` and `AddrMan::Add` end to end, and it is the cheapest possible
answer to "does this work at all".

**Phase 1 — the 100-node MVP.** *(done)* The full mechanism at a size that runs on a
laptop in seconds: event queue, latency model, synthetic addresses, listener
map, `TryPickOutboundAddress` plus simulator-side connect, inbound caps,
eviction, teardown, and the two patches from §3.

Use 20 listening and 80 non-listening, matching the target ratio. One sizing
constraint to respect: a non-feeler outbound connection requires a netgroup
distinct from every existing outbound peer, so with 10 outbound slots the
listeners must span at least 10 netgroups, and realistically 25 or more, or
selection becomes degenerate and nodes silently fail to fill their slots.
Generating listeners in distinct /16s handles this.

At this size the whole population is about 1000 connections and under 100 MB,
so iteration is fast and a full run is cheap enough to diff between changes.
Exit criteria: every handshake completes, outbound slots fill, addresses
propagate beyond one hop, and two runs with the same seed are byte-identical.

**Phase 1b — scale ladder.** 1k, then 10k, then 100k, with a measurement gate
at each rung rather than one leap:

| Nodes | What this rung is for |
|---|---|
| 1,000 | Validate behaviour against the functional-test expectations. Record resident memory per node, `A`, and wall-clock per simulated hour. |
| 10,000 | First real scaling pressure. Expect the event queue and the allocation count to show up in a profile. This is where optimisation starts. |
| 100,000 | Needs the big machine. Mostly a memory and patience exercise once 10k is clean. |

Optimise in roughly this order, and only when a profile says so:

1. Confirm logging, `checkaddrman` and the validation cache are actually off.
2. Lower the per-node receive and send buffer caps well below the 5 MB and
   1 MB defaults.
3. Swap `V1Transport` for a pass-through transport if serialisation shows up.
4. Make `mapRecvBytesPerMsgType` lazy, worth about 2.7 KiB per `CNode`.
5. Narrow `nid_type` to `int32_t`, halving the fixed AddrMan tables.
6. Try a different allocator for the allocation count, not the byte count.
7. Only then consider sharding the event loop, which is blocked on the three
   process globals in §2.4.

**Phase 2 — address relay.** Per-node self-address state (§3.2), real
`PeerManager` on every node, the shared chainstate. Measure propagation time,
table occupancy over time, duplicate volume, and how often the rate limiter
actually binds.

**Phase 3 — outputs.** CSV per run, plus the topology metrics worth having:
degree distribution, netgroup diversity per node, time to a connected graph,
listening nodes nobody dials, and eclipse exposure.

Validate at small N against the functional tests that already encode the
expected behaviour: `p2p_addr_relay.py`, `p2p_addr_selfannouncement.py`,
`p2p_getaddr_caching.py`, `p2p_addrfetch.py`.

---

## 10. Open questions

1. **Latency model.** Latency only, or also bandwidth and queueing? Should
   latency be geographic, derived from each node's IP, or drawn from a
   distribution? Latency-only with a pluggable per-pair function is the cheap
   MVP.
2. ~~**Address universe.**~~ Settled: synthesise addresses programmatically. No
   `peers.dat` snapshots, no real network data. Real data can be fed in later
   once the mechanism works. Addresses are generated as routable IPv4 in
   distinct /16s so netgroup logic behaves, with an optional asmap later.
3. **Bootstrap.** Hardcoded seeds, simulated DNS seeds, or a prepopulated
   addrman per node? This strongly shapes early topology and is worth deciding
   before Phase 1.
4. **Churn.** Static population for the MVP, or nodes joining and leaving with
   `peers.dat` persistence and anchor reconnects?
5. **Clock skew.** One global clock for all nodes is free; per-node clocks need
   a patch to `NodeClock::now()`. I assume one global clock is fine.
6. **Transport.** Keep real V1 serialisation for the MVP, or go straight to a
   pass-through transport? I would keep V1 and measure first.
7. **Non-listening nodes.** Model them purely as absent from the listener map,
   or also give some of them onion addresses so the privacy-network paths get
   exercised?

---

## 11. Staying close to production

The point of using Core's own code is that a change to Core shows up in the
simulator without anyone remembering to mirror it. That property is not
automatic, so it is worth being precise about where it holds today.

**What is shared, not copied.** The simulator calls
`CConnman::CountOutboundSlots()`, `CConnman::DecideNextOutbound()` and
`CConnman::TryPickOutboundAddress()`. `ThreadOpenConnections` calls the same
three functions. The logic was moved rather than duplicated, so a change to the
connection-type ladder, the netgroup accounting or the selection filters
reaches the simulator with no further work, and a change to their signatures
breaks the simulator's build rather than silently diverging. The same holds for
`AttemptToEvictConnection`, `DisconnectNodes`, `ProcessMessages`,
`SendMessages`, all of `AddrMan`, and the whole V1 transport.

**What is still duplicated.** The loop *around* those calls. The 500 ms
cadence, the outbound semaphore, the ordering of `ProcessAddrFetch` and
`PerformReconnections`, the fixed-seed and seed-node handling, and the
post-selection steps inside `OpenNetworkConnection`: the `IsLocal` and
ban checks, the feeler sleep jitter, `count_failures`, and the v2 transport
decision. Reorder those in `ThreadOpenConnections` and the simulator will not
notice.

**The next step, and it is not threads.** Extract one
`CConnman::OpenOutboundConnectionsOnce()` holding the whole loop body, so
`ThreadOpenConnections` becomes a sleep plus a call, and the simulator calls
the same function on its own 500 ms tick. That removes nearly all the
duplication above. The obstacle is the tail of the body: it ends in
`ConnectNode()`, which does real name resolution and a real socket connect.

**Going further means faking the socket, not the loop.** `CreateSock` is a
`std::function` hook (`src/netbase.h:297`) that `ConnectDirectly` goes through,
and `DynSock` already implements a byte-pipe `Sock` with an accept queue
(`src/test/util/net.h:239`). Supply a `Sock` that connects into the simulated
network and the entire real path runs, `ConnectNode` and even `SocketHandler`
included. Cost: `CreateSock` is one process-global, so it has to be told which
node is connecting, and the poll emulation and byte buffering are not free.

**A thread per node is the one option that cannot work.** Not because of the
threads themselves, though 100k nodes times four threads would end it, but
because `NetEventsInterface::g_msgproc_mutex` is a single process-global mutex
held across the whole of `ProcessMessages` and `SendMessages`. Every node's
message handling already serialises through it. Threads would buy contention
and nondeterminism and no parallelism. The same is true of `cs_main` and of
mock time. Parallelism needs those three sharded first, which is a much larger
change than the simulator.

---

## 12. Requested follow-ups

**Export the network graph when a run finishes.** *(done)* `--export=PREFIX`
writes `PREFIX-nodes.csv` and `PREFIX-edges.csv`. Node rows carry the address,
whether it listens, its region, its netgroup, the size of its AddrMan and its
tried table, and its live degree split by connection kind. Edge rows carry the
initiator, the acceptor, the connection type, whether it is still up, when it
opened and closed, and the bytes moved in each direction.

**Support Tor, I2P and IPv6.** The address universe is IPv4-only today, and
`NetGroupManager::NoAsmap()` groups IPv4 by /16. Three separate pieces of work:

- *IPv6* is the easy one. `AddressUniverse` needs to emit `CNetAddr` from
  `in6_addr`, and the netgroup for IPv6 is a /32 rather than a /16, so the
  "one netgroup per node" property needs rechecking.
- *Tor and I2P* change the selection arithmetic, not just the addresses.
  `CountOutboundSlots()` already separates them: addresses on those networks
  increment `privacy_network_peers` instead of joining the netgroup set,
  because their addrman groups are random and diversity is meaningless there.
  That plumbing is in place and unexercised. What is missing is reachability,
  since `g_reachable_nets` is a process global, so a per-node `-onlynet` is not
  expressible yet; and the fact that onion and I2P addresses have no port in
  the sense the listener map assumes.
- *The extra-network peer branch* of the ladder calls
  `MaybePickPreferredNetwork`, which exists to get one outbound peer on every
  reachable network. It can never fire in an IPv4-only universe, so that path
  is currently dead in the simulator and will come alive the moment a second
  network appears.

Worth doing alongside an asmap, since real ASN grouping and multiple networks
answer the same class of question.
