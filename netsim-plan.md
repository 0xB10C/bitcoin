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
`--listeners`, `--minutes`, `--bootstrap`, `--blocksonly`, `--seed`,
`--service-ms`, `--export`, `--tracked`, `--sample-sec`, `--addr-csv`,
`--mainnet-mix`, `--mainnet-groups`, `--chain`, `--mine`, `--block-sec` and
`--csv`, and reports what the run cost.

What works: real `AddrMan`, `CConnman` and `PeerManager` per node, no sockets
and no threads, a microsecond event queue with a region latency model and
ordered per-direction delivery, Core's own ladder choosing what to open,
full-relay plus block-relay-only plus feelers, connection teardown, inbound
eviction, reproducible runs, a graph export, an address-propagation
measurement (§4.1), a chain that advances (§13), and populations spread over
IPv4, IPv6, Tor and I2P in measured mainnet proportions (§14).

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
`--export=PREFIX`, readable directly by networkx or igraph. It is a snapshot of
what is still up when the clock stops. Closed connections are not in it, and
are not kept in memory either: feelers dominate the count over a long run
(41,260 connections opened in an hour at 1000 nodes against 10,012 ever up at
once), so a file of all of them is a log rather than a topology, and holding
them was the largest remaining avoidable allocation.

### The 1000-node rung

1000 nodes, 200 listening, 15 simulated minutes, from before the chain-sync
timeout was addressed. Blocks-only cost 1.26 GB and 168 seconds of wall clock;
the default configuration cost 9.71 GB and 181 seconds, which says the
transaction inventory filter is a memory cost and not a CPU one.

With the timeout off the same population holds a stable topology for a full
simulated hour: 87 seconds of wall clock, 1.23 GB, 41,260 connections opened
and 10,012 standing at the end.

Checked against the exported graph of that hour:

| | |
|---|---|
| Connections standing at the end | 10,012 |
| Outbound full-relay | 8,000, which is 8 for every node |
| Block-relay-only | 2,000, which is 2 for every node |
| Feelers caught mid-probe | 12, out of 31,248 opened and closed |
| Nodes with all 10 persistent slots filled | 1000 of 1000 |
| Nodes left isolated | 0 |
| Outbound pairs sharing a netgroup | 0 of 10,000 |
| Listener inbound degree | min 19, mean 50, max 96 |
| Addresses held | 108,564, or 109 per node |
| Circulating addresses pointing nowhere | 0 |

The zero duplicate-netgroup pairs across ten thousand persistent connections is
the strongest single check available that the simulator is exercising Core's
selection rather than approximating it.

The inbound spread is the first genuine result rather than a self-check. Load
across listeners varies by a factor of five around a mean of 50, so AddrMan
selection is visibly not uniform across equally reachable listeners. That is
the sort of question the simulator exists to answer.

The graph is rendered at https://claude.ai/artifact/MXqhkGfeoDNX7nG5e1t7q9,
drawn from those two CSV files unchanged.

Still to do: §15.

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

### 4.1 Measured, and the shape it takes

`--tracked=N` withholds the first N listener addresses from the bootstrap
seeding. Nothing starts out knowing them, so coverage over time is a direct
measurement of the path above and of nothing else. `--sample-sec` controls how
often the population is counted and `--addr-csv` writes the curve, with the
holders split by whether the address reached the `tried` table — which
separates nodes that merely heard about it from nodes that connected to it.

The curve is not the 24-hour one the constants suggest, because the first
self-announcement goes out immediately after verack rather than on the 24-hour
timer. Every new outbound connection a node makes is another seeding event, and
`ThreadOpenConnections` makes those constantly. So a fresh listener spreads at
the rate its peers open connections, not at the rate of the broadcast interval:
at 40 nodes a withheld address reached 28 of the other 39 within 8 simulated
minutes, 18 of which had tried it.

The 24-hour interval still matters for a node whose address has gone stale
everywhere, which is a longer experiment than anything run so far.

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

### 5.2 CPU, and the one optimisation that mattered

The optimisation list in §9 had the wrong target at the top. Measured, the cost
was almost entirely `AddrMan::Select()` probing a nearly-empty table, and the
fix was a configuration default rather than a code change.

`Select()` picks a random slot out of 81,920 and retries until it finds an
occupied one, so its cost scales inversely with table occupancy, and
`TryPickOutboundAddress` makes up to a hundred selections per attempt. Seeding
each node with 4 bootstrap addresses instead of 16 therefore dominated
everything else. At 1000 nodes forming their topology:

| Bootstrap addresses | Wall clock | Connections | Saturated |
|---|---|---|---|
| 4 | 147 s | 10,769 | 1000 of 1000 |
| 16 | 5 s | 10,969 | 1000 of 1000 |
| 64 | 6 s | 10,974 | 1000 of 1000 |

Same topology, 29 times faster. Sparse-table selection was 97% of the run. The
default is now 16.

Two wrong guesses are worth recording, because both were plausible and both
were cheap to test. Quadrupling the per-node service interval from 1 s to 4 s
changed the wall clock by 3%, so the periodic flush was not the cost. And
holding the population fixed while varying simulated time showed 2 minutes
costing 148 s against 15 minutes costing 166 s, which is what pointed at
topology formation rather than steady-state traffic.

With the fix in place, scaling is close to linear in connections:

| Nodes | Listeners | Wall clock | Connections | Memory | Saturated |
|---|---|---|---|---|---|
| 1,000 | 200 | 25 s | 17,431 | 1.20 GB | 1000 of 1000 |
| 2,000 | 400 | 59 s | 34,798 | 2.45 GB | 2000 of 2000 |
| 5,000 | 1,000 | 180 s | 87,315 | 6.38 GB | 5000 of 5000 |
| 10,000 | 2,000 | 389 s | 174,867 | 13.34 GB | 10,000 of 10,000 |

Fifteen simulated minutes, blocks-only, nothing isolated at any size. Cost per
connection drifts from 1.43 ms to 2.22 ms across that range, mildly
superlinear, most likely the growing address tables and cache pressure.

Extrapolating to 100k nodes: topology formation alone is around an hour of wall
clock, and steady-state running costs roughly two and a half days of wall clock
per simulated day, single-threaded. Formation is a one-off; the simulated-day
figure is what limits long-horizon address-relay work.

Further profiling needs a real profiler. `perf` is not in the bix flake and
`gdb` cannot attach here, so the measurements above come from varying one knob
at a time, which located the dominant cost but will not resolve what is left.

### 5.3 Memory levers, measured

Every figure below is a measured 1000-node blocks-only run, 15 simulated
minutes, against a 1,261,084 KiB baseline.

| Lever | Effect | Status |
|---|---|---|
| Advertise `fRelay=false` | 9.96 → 1.31 MB/node, 7.6x | **In use.** The single largest lever by far. |
| One shared `ChainstateManager`, validation caches at zero | avoids 32.25 MiB per node | In use |
| No per-node `BanMan` | avoids 539 KiB per node | In use |
| V1 transport rather than V2 | avoids ~1 KiB plus buffers per node | In use |
| jemalloc via `LD_PRELOAD` | **6% worse**: 1,336,000 KiB | **Tested and rejected** |
| `nid_type` 64-bit → 32-bit | **25% better**: 940,396 KiB | **Reverted, see below** |
| Drop the per-`CNode` message-type map prefill | ~4% | Not a one-liner, see below |

**The 25% one is real but must not be taken.** Halving `nid_type` halves
AddrMan's two fixed bucket tables from 640.5 KiB to 320 KiB per instance, which
is 320 KB per node and would take 100k nodes from about 131 GB to 98 GB. It
also reverts a security fix: the 64-bit width exists because the former `int`
let an attacker overflow the counter by making a node add more than 2^31
addresses, disclosed on 2024-07-31. A simulation bounded by its own address
universe cannot reach that; a real node can. Since this branch also carries
commits intended for upstream, the change is not left in the tree. Anyone who
wants it should apply it locally and never ship it.

**The 4% one is not free either.** `CNode`'s constructor pre-fills
`mapRecvBytesPerMsgType` with 37 entries, about 2.7 KiB per `CNode`, whether or
not a message ever arrives. Removing the prefill trips an assertion in
`CNode::ReceiveMsgBytes`, which requires the key to be present, so it needs the
accounting path changed to insert on demand rather than a deletion.

**Where the 1.31 MB actually goes.** A run with `--bootstrap=0` forms no
connections and holds no addresses, so it measures the fixed per-node floor
directly: **671,739 bytes**. That is within 6 KB of `sizeof(AddrManImpl)`,
which is 655,872. So the floor is AddrMan's two bucket tables and essentially
nothing else: `CConnman` at 1,152 bytes, `PeerManagerImpl` at 1,576, the
transaction-download object and the orphanage together account for the
remainder. The three large lazy reject filters, worth 3.1 MB per node, are
confirmed never allocated, because the floor would otherwise be far higher.

So the blocks-only figure decomposes as roughly half AddrMan's fixed tables,
and of the other half about 500 KB is `Peer::m_addr_known` at nineteen peers.
Everything else is about a tenth. **There is no unnecessary allocation left to
remove**; what remains are two load-bearing structures, and reducing either is
a trade rather than a saving.

Two further levers are untested and both carry a trade:

- **An occupancy bitmap in front of the bucket tables.** This is the one large
  reduction left that costs nothing in fidelity, and it may well be faster
  rather than slower. At these occupancies the 81,920 slots hold a few hundred
  entries, so the tables are over 99% empty. A plain sparse map would save the
  memory but make each of `Select()`'s probes a hash lookup, which is the wrong
  trade against the hot spot in §5.2. A bitmap plus a map avoids that: 81,920
  bits is 10 KB that sits in L2, so the 99% of probes that miss become a bit
  test, and only a hit needs the map. Against today's 8-byte reads scattered
  over 656 KB, which is cache-hostile precisely because the array is enormous
  and nearly empty, that should *win* on both axes. Estimated 16 KB in place of
  656 KB, taking per-node cost from 1.31 MB to around 0.66 MB, or 131 GB to
  66 GB at 100k nodes. It is an invasive AddrMan change, and one that would
  benefit a real node with a sparse table too.
- **Not retaining closed links.** The simulator keeps every link ever opened so
  the graph export can include short-lived feelers. Over a simulated day at
  100k nodes that is roughly 72 million closed links at about 80 bytes, so
  5.8 GB. Worth an option for long runs, though small beside the per-node cost.
- **A smaller `Peer::m_addr_known`.** At 26.3 KiB per addr-relay peer this is
  roughly 500 KB per node, the dominant per-peer cost once transaction relay is
  off. It is safe to shrink for a pure topology run and not safe for an
  address-relay run, because the filter's size is exactly what governs the
  re-relay behaviour being measured.

### 5.4 A CPU trap worth more than the memory numbers

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

Two apparently cheap reductions, both since investigated: `nid_type` to
`int32_t` halves the fixed tables and saves ~31 GiB at 100k nodes but **must
not be taken**, for the reason in §5.3; making `mapRecvBytesPerMsgType` lazy
looks like ~5 GiB but trips an assert in `CNode::ReceiveMsgBytes`, which
indexes the map without checking. The remaining safe win is the occupancy
bitmap in §5.3.

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

**Runs stopped being valid at 20 simulated minutes, and the graph export is
what revealed it. Resolved twice.** Outbound full-relay peers started getting
disconnected in a wave at about minute 22. The cause is `ConsiderEviction`
(`src/net_processing.cpp:5514`): an outbound peer that has not announced a
block with as much work as our tip within `CHAIN_SYNC_TIMEOUT`, which is 20
minutes, gets one `getheaders` and then a disconnect. Every node sat on a
genesis-only chain and never announced anything, so every unprotected outbound
peer timed out together.

That was Core behaving correctly given a static chain, not a simulator bug, but
it is an artefact of the absent chain and it corrupted any long-horizon
measurement: at 30 simulated minutes, 91 of 875 full-relay connections had been
shed and reopened for this reason alone.

First fix, `PeerManager::Options::disable_chain_sync_timeout`: a test-only gate
that returns from `ConsiderEviction` before it looks at the chain. With it on,
1000 nodes over 60 simulated minutes hold all 10,000 persistent connections and
isolate nobody, where before the hour contained three disconnection waves.

Second fix, and the honest one: §13. `--chain=N --mine` gives the population a
chain that advances, every node's PeerManager subscribes to tip notifications,
and the announcements that follow satisfy the timer with the check left on.
The gate now follows whether tip notifications are published at all, so a
chainless run still works and a run with a chain needs no gate.

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
   *(done, and the bootstrap-count finding in §5.2 mattered far more)*
2. Lower the per-node receive and send buffer caps well below the 5 MB and
   1 MB defaults.
3. Swap `V1Transport` for a pass-through transport if serialisation shows up.
4. Put an occupancy bitmap in front of the AddrMan bucket tables (§5.3). The
   one remaining large, safe win, and it should be faster as well as smaller.
5. Try a different allocator for the allocation count, not the byte count.
6. Only then consider sharding the event loop, which is blocked on the three
   process globals in §2.4.

Two levers that look attractive and are not: narrowing `nid_type` (§5.3, it
reverts a disclosed overflow fix) and making `mapRecvBytesPerMsgType` lazy
(it trips an assert in `CNode::ReceiveMsgBytes`).

**Phase 2 — address relay.** *(propagation done, §4.1)* Per-node self-address
state (§3.2), real `PeerManager` on every node, the shared chainstate. Still to
measure: duplicate volume and how often the rate limiter actually binds, both
of which need counters inside `ProcessAddrs` rather than anything the simulator
can observe from outside. Table occupancy over time is already in the node
export, sampled once at the end; a periodic version is a small addition to the
sampling tick.

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
initiator, the acceptor, the connection type, when it opened, and the bytes
moved in each direction.

It is a snapshot of the connections still up when the clock stops, not a log of
every connection the run made. Feelers are the reason: a run holds about 30 per
node per simulated hour, each alive for a moment, so they outnumber the real
topology three to one in an hour and keep growing after that. Dropping them
from the export also let the link storage itself be bounded by the peak
concurrent count rather than by history — a closed link's slot goes on a free
list and is reused, guarded by a per-link generation counter so a delivery
queued before the recycle cannot land on the connection that took the slot.

**Support Tor, I2P and IPv6.** *(done)* `--mainnet-mix` spreads the population
over all four networks; see §14 for the shares and for what came alive as a
result. One piece is still missing and is listed in §15: per-node
reachability. `g_reachable_nets` is a process global, so a per-node `-onlynet`
is not expressible, and every node here can reach every network. That is the
right default for studying how a mixed network forms; it is wrong for asking
what happens to a Tor-only node.

**Mine on a real chain.** *(done)* §13.

**Use real mainnet data.** *(done)* §14.

---

## 13. The shared chain

`--chain=N` builds N blocks before the population exists; `--mine` extends the
chain as a Poisson process with a mean interval of `--block-sec`, ten minutes
by default. Both go through `BlockTemplateManager` and `ProcessNewBlock`, so
the coinbase, the witness commitment, the difficulty and the timestamp rules
are Core's rather than something reimplemented here.

Three details that are load-bearing:

- **Intervals are exponential, not even.** Block arrivals are a Poisson
  process, so the gap between two blocks is exponentially distributed and the
  count in any window is Poisson, not fixed: 120 simulated minutes at a
  ten-minute mean produced 11, 12 and 8 blocks for three seeds. Even spacing is
  the one thing mining is definitely not, and it would hide exactly the
  clustering that makes a twenty-minute timeout interesting. `Chain` draws from
  `FastRandomContext::rand_exp_duration`, the same primitive `MaybeSendAddr`
  uses for its own Poisson timers, on a stream derived from the run's seed so
  the schedule is reproducible. `Options::poisson` turns it off, which is how a
  test pins a block count.
- **Timestamps run up to the start of the run, not from it.**
  `IsInitialBlockDownload` calls a tip older than `max_tip_age`, a day by
  default, still-syncing, and a node in initial block download never announces
  its own address. Building the chain forwards from the start instant would
  leave every node silent. Built backwards, the nodes leave initial block
  download on their own and `JumpOutOfIbd()` is no longer needed.
- **Every node's PeerManager subscribes to tip notifications**, as `init.cpp`
  does with the single production one. Without that a new block reaches only
  the miner and nothing is announced. `Chain::MineOne` drains the validation
  queue synchronously afterwards, because those callbacks arriving on the
  scheduler thread at an arbitrary point in the event loop would make the run
  unreproducible.

### 13.1 What this does and does not simulate

There is one `ChainstateManager` for the whole population, so every node sees
the same tip at the same instant. Block **announcement** is real: each node
gets `UpdatedBlockTip` and pushes headers to its own peers, which is what
advances `pindexBestKnownBlock` on the receiving side. Block **transfer** is
not: a peer offered a header it already has never asks for the block, so no
`getdata`/`block` exchange happens and initial block download cannot be
simulated.

Making that real needs one `Chainstate` per node. Separable in principle —
assumeutxo already runs two over one `BlockManager` — but each wants its own
`CCoinsViewDB`, and ten thousand LevelDB instances is out of reach at the sizes
this exists for. For topology and address relay it costs nothing, because both
only need the tip to move.

### 13.2 The memory it costs, and the 23 GB that it should not have

Mining costs **518 KiB per node**: the recent-confirmed-transactions rolling
bloom filter inside `TxDownloadManager`, which the coinbase lands in. That one
is real.

It was 2.96 MiB per node before the fix in
`src/node/txdownloadman_impl.cpp`. `TxDownloadManagerImpl::ActiveTipChange`
reset the recent-rejects and recent-rejects-reconsiderable filters *through
their accessors*, and those accessors allocate on first use — so the first tip
change committed 1.2 MiB apiece before the node had been asked about a single
transaction, and permanently on a `-blocksonly` node, which never is. Resetting
a filter that was never allocated is indistinguishable from not having one.
Going through the lazy pointers instead saves 2.47 MiB per node here, and 23 GB
of the 24 GB the first block cost at ten thousand nodes.

---

## 14. Real mainnet data

From a btcnodes.io snapshot taken 2026-10-21 covering 25,636 reachable nodes.
Two things were taken from it, both as *shape* rather than as a node list, so
that any population size can use them.

**The network mix**, behind `--mainnet-mix`:

| Network | Nodes | Share |
|---|---|---|
| Tor | 12,612 | 49.2% |
| IPv4 | 7,514 | 29.3% |
| I2P | 4,288 | 16.7% |
| IPv6 | 1,222 | 4.8% |
| CJDNS | 2 | — |

Tor is half the reachable network and IPv4 under a third, so an IPv4-only
simulation has the composition upside down. Onion and I2P addresses are built
through `CNetAddr::SetSpecial`, checksum included, so what the simulator holds
is whatever Core's own parser produced. IPv6 addresses live in 2a00::/8 because
the obvious alternatives are all special-cased: 2001:db8::/32 is documentation
space Core calls unroutable, 2001:470::/32 is he.net and gets /36 groups
instead of /32, and 2002::/16 and 2001::/32 are 6to4 and Teredo, which
`GetGroup` unwraps to the encapsulated IPv4 address.

**The netgroup occupancy**, behind `--mainnet-groups`: 7,514 IPv4 nodes in
4,236 distinct /16s, and 1,222 IPv6 nodes in only 384 /32s. Both are a long
tail of singletons under a short, heavy head — IPv4 is 72% singletons with a
top group of 107, IPv6 is 70% singletons with a top /32 holding 156 of 1,222.
Group sizes are drawn from the empirical distribution rather than replayed in
order, which is what makes it work at any scale: a 200-node population is then
a plausible random subsample of mainnet's groups, and 4,000 nodes land on
1.7786 per netgroup against mainnet's 1.7740.

### 14.1 What came alive, and the first result

Two parts of Core could never fire in a single-network population:

- `MaybePickPreferredNetwork`, the extra-network branch of the ladder, which
  exists to put one outbound peer on every reachable network.
- The `privacy_network_peers` branch of `CountOutboundSlots`, which files Tor
  and I2P peers separately from the netgroup diversity set, because
  `GetGroup` gives those addresses only four bits — sixteen possible groups per
  network, so diversity there would be meaningless.

The exemption is visible immediately: **120 nodes on the mainnet mix fill every
outbound slot across just 55 distinct netgroups.** On an IPv4-only population
each node needs ten netgroups it is not already connected to; with half the
population on Tor, most of its outbound peers do not count against that rule at
all. Any conclusion about eclipse exposure drawn from an IPv4-only simulation
is therefore drawn from the wrong network.

---

## 15. Still open

- **Per-node reachability.** `g_reachable_nets` is a process global, so
  `-onlynet` cannot differ between nodes. Needed to ask what a Tor-only node
  experiences, as opposed to how a mixed network forms.
- **An asmap.** `NetGroupManager` takes one and the simulator passes
  `NoAsmap()`. Real ASN grouping is the same class of question as the netgroup
  occupancy above and would supersede the /16 approximation.
- **Initial block download**, which needs §13.1's per-node chainstates.
- **Duplicate address volume and rate-limiter binding**, which need counters
  inside `ProcessAddrs` rather than anything observable from outside.
- **Churn**: nodes joining and leaving mid-run.
- **The AddrMan occupancy bitmap** from §5.3, the one remaining large memory
  win.
- `OpenOutboundConnectionsOnce`, so the simulator calls one extracted function
  per attempt rather than reassembling the ladder; see §11.

---

## 16. Cost accounting, and how to take the numbers again

Everything below was measured, not estimated. Where a figure is a projection
it says so. Machine: this laptop, 24 cores, 125 GB RAM, `TMPDIR` on a real
disk; `RelWithDebInfo`, clang 20.1.5.

### 16.1 How to re-measure

**Per-component costs** live in disabled probes at the end of
`src/test/netsim_tests.cpp`. They are disabled because they measure rather
than assert, so ctest skips them. Name one explicitly to take a reading:

```
export TMPDIR=/some/large/tmp
build/bin/test_bitcoin --run_test=netsim_tests/probe_type_sizes        -l test_suite
build/bin/test_bitcoin --run_test=netsim_tests/probe_rolling_bloom_cost -l test_suite
build/bin/test_bitcoin --run_test=netsim_tests/probe_node_cost_blocksonly -l test_suite
build/bin/test_bitcoin --run_test=netsim_tests/probe_node_cost_txrelay    -l test_suite
build/bin/test_bitcoin --run_test=netsim_tests/probe_node_cost_own_chain  -l test_suite
```

**One probe per process, always.** glibc does not return a freed arena to the
kernel, so a second measurement in the same process sees a resident set that
never shrank and reports nearly zero. That is why the three node-cost probes
are three test cases rather than one loop — an earlier version of this note
had two bogus numbers in it for exactly that reason.

**Whole-run costs** come from the driver's own reporting:

```
bitcoin-netsim --nodes=1000 --listeners=200 --minutes=60 --blocksonly --csv
```

`rss_before_kb` is read after the host process and its shared chainstate
exist but before the population does, so `sim_kb` and `bytes_per_node` are the
population's own cost. Build the chain with `--chain=N` *before* that baseline
is taken — the driver does, which keeps a thousand blocks of block index and
LevelDB cache out of the per-node figure.

For a sweep, `--csv-header` then one `--csv` line per rung; the committed
`netsim-memory-sweep.csv` was produced that way.

### 16.2 What each part costs

| Component | Bytes | Source |
|---|---|---|
| `sizeof(AddrManImpl)` | 655,872 | compile-time |
| `sizeof(CNode)` | 1,024 | compile-time |
| `sizeof(CBlockIndex)` | 152 | compile-time |
| `sizeof(netsim::Link)` | 88 | compile-time |
| Idle node, shared chain | 673,280 | `probe_node_cost_blocksonly` |
| Idle node, own chain | 799,872 | `probe_node_cost_own_chain` |
| → the per-node `ChainstateManager` | 126,592 | difference of the two above |
| → same, measured directly | 122,816 | 128 instances, RSS delta |
| Empty `Chainstate`, shared `BlockManager` | 69,816 | 1024 instances, RSS delta |
| `recent_rejects` filter (120k, 1e-6) | 1,295,339 | `probe_rolling_bloom_cost` |
| `recent_rejects_reconsiderable` | 1,295,339 | same |
| `recent_confirmed_transactions` (48k) | 517,611 | same |
| Per-peer tx inventory filter | ~527 KiB | `Peer::TxRelay`, from source |
| BanMan discouragement filter | ~539 KiB | avoided: `banman=nullptr` |

Two readings worth keeping together: an idle node is **673 KB**, and
`sizeof(AddrManImpl)` is **656 KB** of it. The AddrMan tables are the per-node
floor, and they are 99% empty at any population this simulator reaches. That
is what makes the occupancy bitmap in §5.3 the one remaining large win.

An *idle* node shows no difference between blocks-only and tx-relay, because
`Peer::TxRelay` is allocated per peer and an idle node has none. The
difference only appears in a run with connections, and there it is large: see
the 1k rung below.

### 16.3 What a run costs

| Nodes | Configuration | Minutes | Bytes/node | Total | Wall |
|---|---|---|---|---|---|
| 1,000 | blocks-only | 15 | 1,260,000 | 1.26 GB | 168 s |
| 1,000 | tx-relay | 15 | 9,710,000 | 9.71 GB | 181 s |
| 1,000 | blocks-only | 60 | 1,317,068 | 1.23 GB | 87 s |
| 1,000 | mainnet mix, chain, mining | 60 | 1,884,360 | 1.74 GB | 90 s |
| 10,000 | blocks-only | 15 | 1,432,774 | 13.34 GiB | 389 s |
| 10,000 | blocks-only | 60 | 1,475,183 | 13.74 GiB | 1377 s |
| 10,000 | mainnet mix, chain, mining | 60 | 1,940,489 | 18.07 GiB | 1302 s |
| 100,000 | blocks-only | 60 | *~1.5 M projected* | *~148 GB* | *~3.8 h* |
| 100,000 | mainnet mix, chain, mining | 60 | *~1.9 M projected* | *~194 GB* | *~3.6 h* |

The 100,000 rows are **projections, not measurements**: per-node cost is flat
across the measured rungs, so the projection is that figure times the node
count, and wall clock scales linearly in both node count and simulated time.
Neither fits in this laptop's 125 GB, which is why they have never been run.
What would make 100k fit here is the AddrMan occupancy bitmap: 656 KB down to
about 16 KB per node takes the blocks-only projection from ~148 GB to ~84 GB.

Tx relay costs 7.4× the memory of blocks-only and almost nothing in CPU
(181 s against 168 s at the 1k rung) — it is the per-peer inventory filter,
not work.

Adding a chain and mining costs about 518 KB per node: the
recent-confirmed-transactions filter that the coinbase lands in. It was 2.96
MiB before the fix in `src/node/txdownloadman_impl.cpp`; see §13.2.

### 16.4 Known hazards

Things that have already bitten, or would.

**Process globals, in rough order of how much they constrain the design.**

- `NetEventsInterface::g_msgproc_mutex` is global and held across all message
  handling, so the simulator is single-threaded by necessity, not by choice.
  This is the binding constraint on ever parallelising it.
- `cs_main` is global. For the simulator this costs nothing — we never
  contend, being single-threaded already — but it is the second thing that
  would have to go to parallelise. Upstream has built the seam:
  `ChainstateManager::GetMutex()` (`validation.h:1042`) returns `::cs_main`,
  and the intent is to migrate every `GUARDED_BY(::cs_main)` to it and then
  make the mutex a member. As of this branch that migration is roughly 5%
  done: 33 `GetMutex()` annotations against 633 mentions of `cs_main`. Not
  something to take on as a side effect.
- Mock time is global *and* whole-second resolution (`SetMockTime` stores
  `std::chrono::seconds`), which is why the event queue runs at microsecond
  resolution independently of what the nodes can observe.
- `g_reachable_nets` is global, so `-onlynet` cannot differ between nodes.
  Every node can reach every network. Right default for studying how a mixed
  network forms; wrong for asking what a Tor-only node experiences.
- `mapLocalHost` *was* global and is now per-`CConnman`; see §14. It had to
  move before Tor and I2P nodes could announce themselves at all.
- `fDiscover` and `GetListenPort()` are still read from globals inside
  `LocalAddresses`. Both are configuration rather than learned state and are
  identical across simulated nodes, so this is harmless today.
- The script-execution and signature caches are process-global. Per-node
  chainstates set both budgets to zero, so one node's validation cannot answer
  for another's.

**Lazy allocation, which makes memory appear later than you expect.**

- The three `TxDownloadManager` rolling blooms are allocated on first use, and
  two of them used to be allocated by `ActiveTipChange` merely to be reset.
  Fixed, and worth 2.47 MiB per node.
- `Peer::TxRelay` and its 527 KiB filter appear on the first peer, not at
  construction. An idle-node probe therefore understates a tx-relay run by
  roughly 8.5 MB.
- `mapRecvBytesPerMsgType` cannot be made lazy: `CNode::ReceiveMsgBytes`
  indexes it without checking and asserts.

**Measurement traps.**

- Only the first RSS measurement in a process is valid (§16.1).
- `/tmp` on this machine is a 13 GB tmpfs; a 10k run fills it. Runs set
  `TMPDIR=/home/core/.cache/netsim-tmp` and delete leftover `test_common`
  datadirs afterwards.
- A per-node `ChainstateManager` defaults to `worker_threads_num = 2` and
  `prevoutfetch_threads_num = 2`. Left alone that is 40,000 threads at 10k
  nodes. `MakeNode` sets both to zero.
- `BlockManagerOpts::blocks_dir` is a real filesystem path — the one part of a
  simulated node that is not in memory. `fast_prune` keeps the files to 16 kB
  chunks rather than preallocating 16 MiB each.

**A CPU trap that looks like a memory problem.** `AddrMan::Select()` probes
random slots until it finds an occupied one, so its cost scales inversely with
table occupancy. A sparsely seeded population appears to hang rather than to
be slow: four bootstrap addresses cost 147 s at the 1k rung where sixteen cost
5 s, for the same resulting topology. §5.2.

---

## 17. Propagation, measured

Both goals the simulator was built for now produce curves rather than
anecdotes. `--blockrelay` turns on per-node chainstates (§13.1), without which
no block is ever requested; `--tracked=N` withholds listener addresses so only
relay can spread them (§4.1).

### 17.1 Blocks

1000 nodes, 200 listening, blocks-only, 120 simulated minutes, ten blocks
mined. 749 seconds of wall clock, 1.97 MB per node.

| Height | 50% of nodes | 90% | last node |
|---|---|---|---|
| 11 | 370 ms | 454 ms | 626 ms |
| 12 | 373 ms | 459 ms | 617 ms |
| 13 | 367 ms | 451 ms | 642 ms |
| 14 | 373 ms | 462 ms | 624 ms |
| 15 | 374 ms | 468 ms | 614 ms |
| 16 | 368 ms | 446 ms | 616 ms |
| 17 | 370 ms | 445 ms | 614 ms |
| 18 | 364 ms | 451 ms | 629 ms |
| 19 | 372 ms | 453 ms | 635 ms |
| 20 | 364 ms | 440 ms | 621 ms |

Every block reached all 1000 nodes. The spread of the median across ten
independent blocks is 364 to 374 ms — about 1% — which says the figure is a
structural property of the topology and the latency model rather than noise,
and that ten blocks is already plenty for a stable reading.

**Propagation scales with the logarithm of the population, and the arithmetic
checks out.** The same configuration at 200 nodes reached half the network in
329 ms against 370 ms at 1000. Five times the population costs 41 ms. Each
node holds about ten outbound peers, so reach grows roughly tenfold per hop:
200 nodes is about 2.3 hops deep and 1000 about 3.0, a difference of 0.7 hops,
and at the model's mean one-way delay of around 60 ms that predicts 42 ms.
Measured 41 ms.

**Block size, and what it is worth.** The table above is 250-byte regtest
blocks with bandwidth unlimited, so it measures hop count times latency. With
`--block-bytes=900000 --bandwidth-mbit=50` at 200 nodes the same block takes
598 ms to half the population rather than 329, and the run moves 190 MB
instead of 15 MB. That is the figure to quote for anything bandwidth-related.

Two honest limits on the padded figure. The filler all sits in the coinbase,
so compact-block reconstruction can shortcut nothing and every hop ships the
whole block — the pessimistic case, equivalent to a block full of transactions
nobody had seen. And 1 MB is a ceiling rather than a setting: filler is
non-witness data and weight counts it four times, so a megabyte is already
`MAX_BLOCK_WEIGHT`. Past that needs real transactions carrying witness data.

`--block-csv` writes one row per (block, node): 10,001 rows for the run above,
which sorted by height then elapsed time is the curve.

### 17.2 Addresses

Four withheld self-announcements, in the same runs:

| Nodes | Minutes | Reached, mean | Worst | Via `tried` |
|---|---|---|---|---|
| 200 | 60 | 80 of 200 (40%) | 73 | 82% |
| 1000 | 120 | 400 of 1000 (40%) | 389 | 58% |

Coverage holds at 40% as the population grows fivefold, and the four
addresses stay within 3% of each other, so this too is structural rather than
a lucky draw.

The `tried` share is the more interesting column, because it separates nodes
that merely heard the address from nodes that connected to it. It falls from
82% to 58% between the two rungs, which is what you would expect: the number
of outbound slots per node is fixed at ten whatever the population, so a
larger network has proportionally more candidates competing for the same
slots.

### 17.3 The artefact this measurement started with

Worth keeping, because the shape of the mistake is reusable. The first block
figures were 1220 ms to half the nodes, 1285 ms to 90%, 2040 ms to the last —
and *identical across two different blocks*, which is the tell. Propagation
was advancing one service interval per hop.

`DeliverNow` serviced only the link the bytes arrived on. A node therefore
reacted to its sender immediately but waited for the next periodic tick before
forwarding to any other peer. `ThreadMessageHandler` does not behave that way:
it calls `SendMessages` for every peer on each pass, so a node that learns
something from one peer forwards it to the rest in the same pass. Servicing
all of the receiver's links removed about 900 ms of pure artefact.

The lesson for anything measured here: a number that does not vary between
independent trials is more likely to be quantised by the simulator than to be
a property of Bitcoin.

### 17.4 The plateau in the curve is the latency model

The propagation curve has a step in it: a burst, then a pause, then a steep
ramp. It is worth writing down what causes it, because it looks like a protocol
effect and is not.

`RegionLatency` puts each node in one of six regions and uses two values: 12 ms
within a region and 90 ms between, a 7.5x jump with nothing in between. A block
transfer is three one-way legs -- the headers announcement, the `getdata`, then
the block -- so:

| | per leg | three legs | first arrival measured |
|---|---|---|---|
| within the region | 12 ms | 36 ms | 31.9 ms |
| across regions | 90 ms | 270 ms | 212.5 ms |

Jitter is plus or minus a quarter, which covers the difference. The block
therefore saturates the miner's own region quickly and then nothing at all can
happen until the first inter-region round trip completes.

Checked rather than assumed, on a 100-node run where the `from` column gives
the propagation tree. The miner was node 0 in region 4, and region 4 held
exactly 18 nodes:

```
rank 1-18   all region 4,  0.0 -> 77.5 ms
            <- 135 ms of nothing ->
rank 19     region 3,    212.5 ms
```

All 18 of the first 18 arrivals were in the miner's region, and that region had
18 nodes. Hop depth says the same thing from another angle: hop 1 reached 72
nodes but spanned 31.9 to 317.7 ms, one hop containing both latency values.

So the staircase has as many steps as the model has latency values, which is
two, rather than one per hop. Real round-trip times are a continuum, so a real
curve is smooth where this one has a cliff.

**What this does and does not invalidate.** The medians and the logarithmic
scaling in §17.1 are averages over all region pairs and stand. The *shape* of
the curve does not: reading the plateau as a property of block relay would be
wrong. The fix is a continuous distribution behind the existing `LatencyModel`
interface -- a per-region-pair matrix, or a lognormal fitted to measured RTTs
-- which `latency.h` has anticipated from the start.

This is the second artefact of this kind, after the service-tick quantisation
in §17.3, and both were caught the same way: a feature of the output that was
too regular to be real.
### 17.5 The address relay tree, from AddrMan's own record

Addresses now carry attribution like blocks do, and the mechanism is worth
recording because no Core change was needed. A block's sender is known exactly:
a node adopts the block while handling bytes from one particular peer and the
simulator knows which link it was servicing. An address has no such instant --
it is noticed by sampling, up to 30 s later. But `AddrInfo::source` already
stores the peer the entry was first heard from, because that is what buckets
it, and `AddrMan::GetEntries` is public (the `getrawaddrman` RPC uses it). So
`Network::AddrSourceOf` reads the field back.

Two costs shape the design. `FindAddressEntry` cannot return the source, so
reading it means walking the holder's tables; and `netsim/network.cpp` has to
include `addrman_impl.h` for `AddrInfo` to be complete, after `addrman.h`,
which declares the `AddressPosition` that `addrman_impl.h` uses without
declaring. The walk is therefore done once per (address, node) -- on the single
sample where a node first appears as a holder -- and only under
`record_addr_sources`, which `main.cpp` enables exactly when `--addr-arrivals`
asks for the CSV. The whole-population sample stays one hash lookup per node,
which is what keeps it affordable at 100,000.

Validated the same way the block tree was, on a 100-node run (134 arrivals,
three addresses): every arrival attributed, no node its own source, no sender
that had not been seen holding it earlier or at the same sample, and every
(receiver, sender) pair a connection present in the final topology snapshot.
Note the reverse map has to cover *every* node, not just listeners -- a node
that only dials out is still the source its peers record. Keying it on
listeners alone left 2 of 28 arrivals unattributed in the first run.

The shape is the finding, and it is nothing like a block's:

| | Block (8 mined) | Address (3 withheld) |
|---|---|---|
| Hops to the farthest node | 3 | 5-6 |
| Nodes reached, of 100 | 100 | 42-47 |
| Time until it stopped | ~840 ms | ~4.5 min |
| Peers a relayer passed it to | 1-34, median 16 | 1-8, median 1 |

Block relay floods: a node forwards to every peer that does not have it, so
hop 2 alone accounts for most of the network. Address relay is capped at two
by `net_processing.cpp:2553` -- `nRelayNodes = (fReachable || (hasher.Finalize()
& 1)) ? 2 : 1` -- so the tree is deep and narrow and dies out once those two
peers already know. The measurement finds the cap without being told: 60 of 68
relayers passed each address to exactly one node or two.

Three loose ends worth keeping:

- **The two-peer cap does not apply to a node's own address.** Announcing
  yourself is `MaybeSendAddr`, called from `SendMessages` once per peer, with no
  selection of two anywhere in it; the cap lives only in `RelayAddress`, which
  handles other nodes' addresses. So an owner tells every addr-relay-enabled
  peer it has -- here the 8 full-relay outbound it dialled, since
  block-relay-only and feeler peers are excluded by `SetupAddressRelay`
  (net_processing.cpp:5964). That is why hop 1 is always exactly 8, and why the
  reach model below uses 8 for the owner and 2 thereafter.
- Eight relayers reached 3 or 4. **Not GETADDR** -- an earlier version of this
  section guessed that and was wrong; with the message hook every one of these
  arrivals is a push. The cap is two *per received copy*: `RelayAddress` skips
  the peer that sent it (`id != originator`), so the chosen pair moves with the
  sender, and the candidate list churns underneath it (1535 connections opened
  to end with 976). Their targets land tens of seconds apart rather than
  together, and all eight are listeners, where churn is greatest.
- Both trees are *first-arrival* trees over a denser gossip graph. Node 54 had
  been connected to node 0 since 4.0 s and node 0 does self-announce, but node
  5's copy landed first, so node 54's edge points at node 5; six other peers of
  node 0 are attributed elsewhere the same way.


### 17.6 How long a self-announcement is actually worth anything

The spread stopping is not the tables filling up and not the run ending. Two
rules in `ProcessAddrs` set it, and they are not the same rule:

- `net_processing.cpp:6044` gates *forwarding* on `addr.nTime > current_time -
  10min && vAddr.size() <= 10`. The forwarded `CAddress` carries the owner's
  original stamp through every hop, nothing refreshes it, and
  `AddrMan::Add(..., time_penalty=2h)` backdates the stored copy, so a stored
  address can never be re-forwarded either.
- Storing is **not** gated. `vAddrOk.push_back(addr)` sits outside that `if`,
  so a bulk GETADDR reply still creates holders at any age.

And the owner stamps a fresh one only once:
`AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL` is 24 h, so within a 20-minute run
there is exactly one burst. Measured over 316,219 arrivals: every arrival whose
recorded source was the address owner itself landed within the first 10
seconds. Zero later ones, in any run.

The distribution, one sample per (seed, withheld address), 20 withheld
addresses per run, 20 simulated minutes, sampled every 10 s:

| Nodes | Samples | min | p25 | median | p75 | p90 | max | mean | sd | gained after the gate |
|---|---|---|---|---|---|---|---|---|---|---|
| 1000 | 240 | 3.8 | 5.8 | 6.5 | 7.2 | 7.8 | 10.2 | 6.51 | 1.02 | 1 of 240 |
| 5000 | 120 | 9.8 | 10.8 | 11.2 | 11.7 | 12.2 | 13.5 | 11.28 | 0.64 | 119 of 120 |

At 1000 nodes the push wave exhausts after about 6.5 of its 10 available
minutes -- it runs out of peers that do not already know, not out of time. At
5000 it is still going when the gate shuts, and then keeps gaining holders
anyway through the ungated storage path, which is why the window runs past 10.
Reach is the same fraction at both rungs: 381/1000 and 1871/5000, both 38%.

Two things I got wrong on the way, both worth keeping:

- **The window is not depth times per-hop delay.** The per-hop cost does come
  out near `AVG_ADDRESS_BROADCAST_INTERVAL` (24.3 s measured against a 30 s
  exponential mean, lower because a node forwards to two peers and the earlier
  flush continues the chain). But within a population, depth and window do not
  co-vary: r = 0.09 at 1000 nodes, r = -0.12 at 5000. Branches run in parallel,
  so the window is an exhaustion time, not a path length.
- **Do not pool the populations to compute that r.** Pooled it is 0.87, which
  would have supported exactly the wrong conclusion; depth and window both rise
  with population, so pooling two groups manufactures the correlation. A
  Simpson paradox, and the kind of mistake this kind of sweep invites.

Re-measure with `scratchpad/addrdist.sh` (runs) and `addrdiststats.sh`
(samples plus quantiles plus the within-population r); `mkdist.sh` folds the
samples into the chart data. 1000 nodes is ~47 s per seed, 5000 is ~370 s.

### 17.7 A closed form for reach, and the size where it stops working

`RelayAddress` picks its targets by hashing the address against each peer id,
and `ROTATE_ADDR_RELAY_DEST_INTERVAL` is 24 h, so within a run every node always
picks the *same* two peers for a given address. The forward path is therefore a
fixed out-degree-2 digraph and reach is just the forward-reachable set from the
owner in it. Only the 8 full-relay outbound slots are eligible:
`SetupAddressRelay` (net_processing.cpp:5964) excludes block-relay-only and
feeler connections.

Among listeners the targets are effectively uniform, so forward exploration is a
branching process with two children and the reachable share is the giant
out-component of a digraph whose in-degree is Poisson(2). Non-listeners cannot
be dialled, so they are only ever picked by the 8 listeners they dialled
themselves. With `s = L/N`:

    theta = 1 - exp(-2 theta)  = 0.7968     giant out-component
    d     = 8 (1 + 1/s)                     mean listener degree
    lam   = 8 * 2/d = 2s/(1+s)              non-listener in-degree
    reach/N = s*theta + (1-s)*(1 - exp(-lam*theta))

`d` depends only on `s`, which is why reach is flat in N at a fixed listening
share: where structure is what limits the spread, reach is set by the reachable
share and not by the population.

| Nodes | Share | listeners m/meas | others m/meas | population m/meas | window | depth |
|---|---|---|---|---|---|---|
| 500 | 20% | 79.7 / 80.9 | 23.3 / 24.9 | 34.6 / 36.1 | 4.98 | 12.4 |
| 1000 | 5% | 79.7 / 82.8 | 7.3 / 8.0 | 10.9 / 11.7 | 6.60 | 11.4 |
| 1000 | 10% | 79.7 / 80.3 | 13.5 / 14.3 | 20.1 / 20.9 | 5.13 | 12.8 |
| 1000 | 40% | 79.7 / 73.9 | 36.6 / 36.1 | 53.8 / **51.2** | 9.36 | 21.2 |
| 1000 | 80% | 79.7 / 59.7 | 50.8 / 38.4 | 73.9 / **55.5** | 11.33 | 26.1 |
| 1000 | 20% | 79.7 / 83.7 | 23.3 / 25.9 | 34.6 / 37.5 | 6.45 | 16.2 |
| 2000 | 20% | 79.7 / 79.4 | 23.3 / 24.9 | 34.6 / 35.8 | 8.92 | 20.2 |
| 4000 | 20% | 79.7 / 76.2 | 23.3 / 24.1 | 34.6 / 34.5 | 10.93 | 26.7 |
| 10000 | 20% | 79.7 / 61.4 | 23.3 / 18.4 | 34.6 / **27.0** | 12.55 | 36.5 |

**This is a ceiling, not a prediction.** It is the reach an announcement would
get with unlimited time to spread, and it has ten minutes. It holds to 1.64
points RMS over the five configurations whose wave finished inside about nine
minutes, nothing fitted, and the share series at N=1000 is the load-bearing
part there: 5%, 10% and 20% listening give 11.7%, 20.9% and 37.5% reach, a
threefold range driven by the share alone, tracked by the formula throughout.

Every configuration that ran longer than that falls *short* of the ceiling, and
by more the longer it ran. The shortfall in listener reach against theta
correlates **0.83** with the window across all nine configurations:

    window <= 6.6 min  ->  listener reach 80.3 - 83.7%   (theta = 79.7)
    window  = 8.9 min  ->  79.4%
    window  = 9.4 min  ->  73.9%
    window  = 10.9 min ->  76.2%
    window  = 11.3 min ->  59.7%
    window  = 12.6 min ->  61.4%

So the two-part answer: **the reachable share sets the ceiling, and the clock
decides how much of it you get.** 80% listening at 1000 nodes is the worst miss
(55.5% against 73.9%) because a denser listener set makes the tree deeper --
26.1 hops -- and 26 hops at ~26 s each needs 11.3 minutes.

The 4000-node row agreeing to 0.1 points at a 10.9-minute window is probably
luck rather than the model working there: its listener reach is 3.5 points below
theta while its non-listener reach is 0.8 above, and the two errors cancel in
the population total. Do not read it as the boundary.

Two 10,000-node seeds agree to within 0.6% of each other (3203 and 3185
holders), so the breakdown there is not seed noise.

**10,000 nodes is where the assumption fails.** The model assumes the wave
finishes; here the network is deeper than the clock allows. Mean arrival climbs
a steady ~20 s per hop through hop 24, which extrapolates to 12+ minutes by hop
33 -- but hops 33-40 all measure a mean of 9.0-9.2 min and stop rising. They
cannot cross the gate, so nothing reaches those depths on an average-speed
chain; only chains that ran fast get there, and everything behind them is never
told. Reach 27.0% against the formula's 34.6%.

Pooled over 40 announcements in two seeds: mean arrival rises 0.340 min (20 s)
per hop from hop 1 to hop 24, which extrapolates to 10.92 min at hop 33 -- past
the gate. Hops 33 to 37 measure 8.99, 9.04, 9.15, 9.22 and 9.32 min and stop
rising. That flattening *is* the truncation, and it is what the drawing shows.

Two things to keep straight at this size:

- **Arrivals past 10 min are not late forwarding.** They were authorised just
  inside the deadline and then waited on `m_next_addr_send` (Poisson, 30 s mean,
  long tail). Forwarding stops at the gate; delivery does not. This is why the
  4000-node window is 10.93 min with reach still matching the model.
- **Do not filter the hop tree to pushed arrivals.** Only first arrivals are
  recorded, and at 10,000 nodes 16% of first arrivals are bulk GETADDR replies.
  A node whose first sight was a pull may still forward a later push copy, so
  push-only filtering orphans its children and lost 40% of the tree (1638 of
  2718 nodes). Build the tree over all first arrivals and label each edge
  instead; push still accounts for 76-100% of every hop.

Re-measure with `scratchpad/addrmodel.sh` and `addr10k.sh`; `addrmodelstats.sh`
tabulates, `addrpredict.sh` compares against the formula, `mk10k.sh` and
`mkmodel.sh` build the chart data. 10,000 nodes is 872 s and 14 GB.

**The 5% listening share is pathologically slow to simulate, not just slow to
spread.** 50 listeners offer 6250 inbound slots against 9500 wanted, so nodes
retry refused connections indefinitely. Two seeds of the same config took 79 s
and 2090 s -- a 26x spread. The reach figures are sound (both seeds agree with
the formula) but do not plan a sweep around that config; budget for it or skip
it. 1000:100 and above are 35-50 s.

### 17.8 Two failed attempts at predicting time-limited reach

The ceiling (§17.7) is derived and holds where the wave finishes. Predicting what
it actually gets once the gate binds is unsolved, and the two attempts are worth
recording so nobody repeats them.

**A hop-by-hop recursion overshot by 12 points and never triggered the gate.**
Two classes, mass-action saturation, two forwards per reached node. It predicted
42.6% unlimited against the closed form's 34.6%, because it resamples targets
every hop while the real picks are fixed for 24 h: a node nobody picked is never
reached, *ever*. Mass action eventually covers everyone; the real digraph does
not. `scratchpad/reachmodel.sh`.

**A faithful simulation of the fixed digraph got reach close but still never
triggered the gate.** Build the 2-out digraph, draw an Exponential(30 s) delay
per link, take arrival as the shortest summed delay (first passage, which is why
the real tree is deeper than mean-time/per-hop suggests), and forbid forwarding
past 600 s. Reach lands within ~3 points for listening shares up to 20% across
500-4000 nodes. But its waves finish in 7-9 minutes where the measured ones take
12.5, so the gate never bites and it cannot reproduce the 10,000-node
truncation. It also runs listener reach 8-15 points high everywhere. The most
likely missing rule: `SetupAddressRelay` enables addr relay for an *inbound*
peer only once that peer has sent an addr-related message, so a listener's
effective peer count is lower than its degree. Unconfirmed.
`scratchpad/reachsim.sh`.

One real bug the attempts did find, worth ten points of reach: **nobody can dial
the owner.** A withheld address is one nobody knows, so a tracked listener has
almost no inbound (measured 5, 5 and 3 against 41-70 for other listeners). Let
it accrue inbound like any listener and it announces to ~48 peers instead of 8.

**And the gate's cost cannot be fitted from what exists.** The four runs that
overran came in 0%, 5%, 25% and 22% below their ceilings; the implied slope of
shortfall against overrun varies tenfold (0.027 to 0.27 per minute). Nine
configurations is not enough. What *is* checkable is the binary question: depth
~ 1.77 * reached^0.385 at 25 s a hop calls "does the clock bind" correctly for
seven of nine, both misses within a minute of the threshold.

So the playground ships the ceiling (exact), the time estimate (good to a hop,
and a reliable verdict away from the boundary), and the measurements themselves
-- and deliberately refuses to print a single predicted reach once the clock
binds.

### 17.9 theta is measured, not derived -- the derivation in 17.7 is wrong

§17.7 presents `theta = 1 - exp(-2 theta) = 0.7968` as a derived prediction of
listener reach with nothing fitted. The number is right for listening shares up
to about 20%. The derivation is not.

It assumes each listener collects about two in-edges in the forwarding digraph,
which is where the Poisson(2) giant component comes from. Count them instead. A
listener has `d = 8 + 8N/L` addr-relay peers, of which 16 are listeners, and it
spends 2 picks among all `d`. Every *non-listener* spends both of its picks on
listeners, because all 8 of its peers are listeners. So per listener:

    in-degree from listeners      = 2 * 16/d
    in-degree from non-listeners  = 2 (N-L)/L
    total at 20% share            = 8.67, not 2

Solving the real two-class fixed point

    x = 1 - exp(-a x - b y),  y = 1 - exp(-c x)
    a = 32/d,  b = 2(N-L)/L,  c = 2L(d-16)/(d(N-L))

gives listener reach 93.7% at 20% share, 96-97% at 5-10%, and 82% at 80%.
Measured: 80-84% at 5-20%, 73.9% at 40%, 59.7% at 80%. So the fixed point
over-predicts by 13-16 points in the band where theta happens to land on the
measurement, and the population totals it implies (40.2% at 20% share) are the
same ~42% the discarded mass-action recursion gave (§17.8).

Time is not the explanation: 500 nodes at 20% finished in 4.98 min of its 10 and
still reached only 80.9% of listeners. Something holds listener reach near 0.80
that neither model captures. Likeliest candidate, still unconfirmed:
`SetupAddressRelay` admits an *inbound* peer to address relay only once that
peer has sent an addr-related message, so a listener's effective peer count --
and therefore everyone's chance of being picked by it -- is lower than its
degree.

**What to carry forward.** Treat 0.797 as a constant measured over the 5-20%
band, and `reach/N = s*theta + (1-s)(1 - exp(-2s/(1+s) * theta))` as an
empirical relation that fits well there, not as theory. Its 1.49-point RMS
stands; its provenance does not. Do not quote the giant-component story.

The truncation sweep (`scratchpad/addrtrunc.sh`, 8 configurations from 6000 to
20000 nodes at 10/20/40% share) varies share and size independently and should
settle whether listener reach is genuinely flat at ~0.80 below 20% or whether
that too is a coincidence of the sizes tried.

### 17.10 More listeners is not always better

Seven more configurations from 6000 to 14000 nodes at 10/20/40% share (the
20000-node run was killed for memory; 29 GB was too much alongside everything
else on the box). 16 configurations total, and the clearest result is one the
ceiling cannot express.

Reach against listening share, at a fixed size:

| Nodes | 5% | 10% | 20% | 40% | 80% |
|---|---|---|---|---|---|
| 1000 | 11.7 | 20.9 | 37.5 | 51.2 | 55.5 |
| 6000 | | 21.9 | **32.9** | 24.0 | |
| 10000 | | 21.7 | **27.0** | 10.3 | |

At a thousand nodes more listeners is monotonically better. At ten thousand it
turns over: 40% listening reaches 10.3% where 20% reaches 27.0%. Twice the
listeners, a third of the reach. The share and the clock pull against each
other -- a larger reachable set means a deeper tree means more hops at ~22 s
each, and past roughly 25 hops the gate shuts first. At 10000:4000 the tree is
37.2 hops and 16.3% of listeners are ever told.

So there is an interior optimum, near 20% at ten thousand nodes, moving down as
the network grows. Mainnet's listening share is in the comfortable region.

Listener reach against size, at a fixed share:

    10% : 1000=80.3  6000=82.5  10000=81.1          flat
    20% : 1000=83.7  2000=79.4  4000=76.2  6000=72.5  8000=67.5  10000=61.4  14000=48.7
    40% : 1000=73.9  6000=36.9  10000=16.3          collapses

The 10% row matters for §17.9: listener reach is flat at ~81% from 1000 to
10000 nodes while the window grows from 5.1 to 10.6 minutes. So the ~0.80 cap
is **not** a time artefact -- it is structural, and still unexplained, since
the honest in-degree fixed point says 96% there. What the correlated-hash idea
would have explained, it cannot: `GetDeterministicRandomizer` is seeded from
each CConnman's own nSeed0/nSeed1, and netsim gives every node its own via
`DeriveUint64(SEED_CONNMAN, id, 0)`, so the peer ranking is per-node as in
production. Not a simulation artefact.

**The shortfall still does not fit, after four attempts.** Window alone:
r = -0.67, RMS 8.4 points -- at a window of 12-13 minutes the ratio of measured
to ceiling ranges from 0.19 to 0.95 depending entirely on share. Normalising by
how much of the required depth fits in the gate does not collapse it either
(2000:400 and 1000:800 have the same availability ratio and ratios of 1.04 and
0.75). The two model attempts are in §17.8. Reach in the truncated regime is an
open problem; the playground interpolates the measured surface and refuses to
extrapolate.
