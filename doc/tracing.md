# User-space, Statically Defined Tracing (USDT) for Bitcoin Core

Bitcoin Core includes statically defined tracepoints to allow for more
observability during development, debugging, code review, and production usage.
These tracepoints make it possible to keep track of custom statistics and
enable detailed monitoring of otherwise hidden internals. They have
little to no performance impact when unused.

```
eBPF and USDT Overview
======================

                ┌──────────────────┐            ┌──────────────┐
                │ tracing script   │            │ bitcoind     │
                │==================│      2.    │==============│
                │  eBPF  │ tracing │      hooks │              │
                │  code  │ logic   │      into┌─┤►tracepoint 1─┼───┐ 3.
                └────┬───┴──▲──────┘          ├─┤►tracepoint 2 │   │ pass args
            1.       │      │ 4.              │ │ ...          │   │ to eBPF
    User    compiles │      │ pass data to    │ └──────────────┘   │ program
    Space    & loads │      │ tracing script  │                    │
    ─────────────────┼──────┼─────────────────┼────────────────────┼───
    Kernel           │      │                 │                    │
    Space       ┌──┬─▼──────┴─────────────────┴────────────┐       │
                │  │  eBPF program                         │◄──────┘
                │  └───────────────────────────────────────┤
                │ eBPF kernel Virtual Machine (sandboxed)  │
                └──────────────────────────────────────────┘

1. The tracing script compiles the eBPF code and loads the eBPF program into a kernel VM
2. The eBPF program hooks into one or more tracepoints
3. When the tracepoint is called, the arguments are passed to the eBPF program
4. The eBPF program processes the arguments and returns data to the tracing script
```

The Linux kernel can hook into the tracepoints during runtime and pass data to
sandboxed [eBPF] programs running in the kernel. These eBPF programs can, for
example, collect statistics or pass data back to user-space scripts for further
processing.

[eBPF]: https://ebpf.io/

The two main eBPF front-ends with support for USDT are [bpftrace] and
[BPF Compiler Collection (BCC)]. BCC is used for complex tools and daemons and
`bpftrace` is preferred for one-liners and shorter scripts. Examples for both can
be found in [contrib/tracing].

[bpftrace]: https://github.com/iovisor/bpftrace
[BPF Compiler Collection (BCC)]: https://github.com/iovisor/bcc
[contrib/tracing]: ../contrib/tracing/

## Tracepoint documentation

The currently available tracepoints are listed here.

### Context `net`

#### Tracepoint `net:inbound_message`

Is called when a message is received from a peer over the P2P network. Passes
information about our peer, the connection and the message as arguments.

Arguments passed:
1. Peer ID as `int64`
2. Peer Address and Port (IPv4, IPv6, Tor v3, I2P, ...) as `pointer to C-style String` (max. length 68 characters)
3. Connection Type (inbound, feeler, outbound-full-relay, ...) as `pointer to C-style String` (max. length 20 characters)
4. Message Type (inv, ping, getdata, addrv2, ...) as `pointer to C-style String` (max. length 20 characters)
5. Message Size in bytes as `uint64`
6. Message Bytes as `pointer to unsigned chars` (i.e. bytes)

Note: The message is passed to the tracepoint in full, however, due to space
limitations in the eBPF kernel VM it might not be possible to pass the message
to user-space in full. Messages longer than a 32kb might be cut off. This can
be detected in tracing scripts by comparing the message size to the length of
the passed message.

#### Tracepoint `net:outbound_message`

Is called when a message is sent to a peer over the P2P network. Passes
information about our peer, the connection and the message as arguments.

Arguments passed:
1. Peer ID as `int64`
2. Peer Address and Port (IPv4, IPv6, Tor v3, I2P, ...) as `pointer to C-style String` (max. length 68 characters)
3. Connection Type (inbound, feeler, outbound-full-relay, ...) as `pointer to C-style String` (max. length 20 characters)
4. Message Type (inv, ping, getdata, addrv2, ...) as `pointer to C-style String` (max. length 20 characters)
5. Message Size in bytes as `uint64`
6. Message Bytes as `pointer to unsigned chars` (i.e. bytes)

Note: The message is passed to the tracepoint in full, however, due to space
limitations in the eBPF kernel VM it might not be possible to pass the message
to user-space in full. Messages longer than a 32kb might be cut off. This can
be detected in tracing scripts by comparing the message size to the length of
the passed message.

### Context `validation`

#### Tracepoint `validation:block_connected`

Is called *after* a block is connected to the chain. Can, for example, be used
to benchmark block connections together with `-reindex`.

Arguments passed:
1. Block Header Hash as `pointer to unsigned chars` (i.e. 32 bytes in little-endian)
2. Block Height as `int32`
3. Transactions in the Block as `uint64`
4. Inputs spend in the Block as `int32`
5. SigOps in the Block (excluding coinbase SigOps) `uint64`
6. Time it took to connect the Block in microseconds (µs) as `uint64`

### Context `utxocache`

The following tracepoints cover the in-memory UTXO cache. UTXOs are, for example,
added to and removed (spent) from the cache when we connect a new block.
**Note**: Bitcoin Core uses temporary clones of the _main_ UTXO cache
(`chainstate.CoinsTip()`). For example, the RPCs `generateblock` and
`getblocktemplate` call `TestBlockValidity()`, which applies the UTXO set
changes to a temporary cache. Similarly, mempool consistency checks, which are
frequent on regtest, also apply the UTXO set changes to a temporary cache.
Changes to the _main_ UTXO cache and to temporary caches trigger the tracepoints.
We can't tell if a temporary cache or the _main_ cache was changed.

#### Tracepoint `utxocache:flush`

Is called *after* the in-memory UTXO cache is flushed.

Arguments passed:
1. Time it took to flush the cache microseconds as `int64`
2. Flush state mode as `uint32`. It's an enumerator class with values `0`
   (`NONE`), `1` (`IF_NEEDED`), `2` (`PERIODIC`), `3` (`ALWAYS`)
3. Cache size (number of coins) before the flush as `uint64`
4. Cache memory usage in bytes as `uint64`
5. If pruning caused the flush as `bool`

#### Tracepoint `utxocache:add`

Is called when a coin is added to a UTXO cache. This can be a temporary UTXO cache too.

Arguments passed:
1. Transaction ID (hash) as `pointer to unsigned chars` (i.e. 32 bytes in little-endian)
2. Output index as `uint32`
3. Block height the coin was added to the UTXO-set as  `uint32`
4. Value of the coin as `int64`
5. If the coin is a coinbase as `bool`

#### Tracepoint `utxocache:spent`

Is called when a coin is spent from a UTXO cache. This can be a temporary UTXO cache too.

Arguments passed:
1. Transaction ID (hash) as `pointer to unsigned chars` (i.e. 32 bytes in little-endian)
2. Output index as `uint32`
3. Block height the coin was spent, as `uint32`
4. Value of the coin as `int64`
5. If the coin is a coinbase as `bool`

#### Tracepoint `utxocache:uncache`

Is called when a coin is purposefully unloaded from a UTXO cache. This
happens, for example, when we load an UTXO into a cache when trying to accept
a transaction that turns out to be invalid. The loaded UTXO is uncached to avoid
filling our UTXO cache up with irrelevant UTXOs.

Arguments passed:
1. Transaction ID (hash) as `pointer to unsigned chars` (i.e. 32 bytes in little-endian)
2. Output index as `uint32`
3. Block height the coin was uncached, as `uint32`
4. Value of the coin as `int64`
5. If the coin is a coinbase as `bool`

### Context `coin_selection`

#### Tracepoint `coin_selection:selected_coins`

Is called when `SelectCoins` completes.

Arguments passed:
1. Wallet name as `pointer to C-style string`
2. Coin selection algorithm name as `pointer to C-style string`
3. Selection target value as `int64`
4. Calculated waste metric of the solution as `int64`
5. Total value of the selected inputs as `int64`

#### Tracepoint `coin_selection:normal_create_tx_internal`

Is called when the first `CreateTransactionInternal` completes.

Arguments passed:
1. Wallet name as `pointer to C-style string`
2. Whether `CreateTransactionInternal` succeeded as `bool`
3. The expected transaction fee as an `int64`
4. The position of the change output as an `int32`

#### Tracepoint `coin_selection:attempting_aps_create_tx`

Is called when `CreateTransactionInternal` is called the second time for the optimistic
Avoid Partial Spends selection attempt. This is used to determine whether the next
tracepoints called are for the Avoid Partial Spends solution, or a different transaction.

Arguments passed:
1. Wallet name as `pointer to C-style string`

#### Tracepoint `coin_selection:aps_create_tx_internal`

Is called when the second `CreateTransactionInternal` with Avoid Partial Spends enabled completes.

Arguments passed:
1. Wallet name as `pointer to C-style string`
2. Whether the Avoid Partial Spends solution will be used as `bool`
3. Whether `CreateTransactionInternal` succeeded as` bool`
4. The expected transaction fee as an `int64`
5. The position of the change output as an `int32`

### Context `mempool`

#### Tracepoint `mempool:added`

Is called when a transaction is added to the node's mempool. Passes information
about the transaction.

Arguments passed:
1. Transaction ID (hash) as `pointer to unsigned chars` (i.e. 32 bytes in little-endian)
2. Transaction virtual size as `uint64`
3. Transaction fee as `int64`

#### Tracepoint `mempool:removed`

Is called when a transaction is removed from the node's mempool. Passes information
about the transaction.

Arguments passed:
1. Transaction ID (hash) as `pointer to unsigned chars` (i.e. 32 bytes in little-endian)
2. Removal reason as `pointer to C-style String` (max. length 9 characters)
3. Transaction virtual size as `uint64`
4. Transaction fee as `int64`

#### Tracepoint `mempool:replaced`

Is called when a transaction in the node's mempool is getting replaced by another.
Passed information about the replaced and replacement transactions.

Arguments passed:
1. Replacement transaction ID (hash) as `pointer to unsigned chars` (i.e. 32 bytes in little-endian)
2. Replacement transaction virtual size as `uint64`
3. Replacement transaction fee as `int64`
4. Replaced transaction ID (hash) as `pointer to unsigned chars` (i.e. 32 bytes in little-endian)
5. Replaced transaction virtual size as `uint64`
6. Replaced transaction fee as `int64`

Note: In cases where a single replacement transaction replaces multiple
existing transactions in the mempool, the tracepoint is called once for each
replaced transaction, with data of the replacement transaction being the same
in each call.

#### Tracepoint `mempool:rejected`

Is called when a transaction received by a peer is rejected and does not enter
the mempool. Passed information about the rejected transaction and its sender.

Arguments passed:
1. Transaction ID (hash) as `pointer to unsigned chars` (i.e. 32 bytes in little-endian)
2. Reject reason as `pointer to C-style String` (max. length 118 characters)
3. Peer id of sending node as `int64`
4. Peer address and port (IPv4, IPv6, Tor v3, I2P, ...) as `pointer to C-style String` (max. length 68 characters)

## Adding tracepoints to Bitcoin Core

All tracepoint-related macros are defined in `src/util/trace.h`. To use these
macros, `#include <util/trace.h>` in the compilation unit where the tracepoint
is inserted. A tracepoint has a `context` and `event`, which specify the name by
which a tracepoint is referred to. Make sure the tracepoint names make sense
even without detailed knowledge of implementation details. Please use
`snake_case` for the `context` and `event`.

The `trace.h` header file contains the macro definitions
`TRACEPOINT0(context, event)` for a tracepoint without arguments and
`TRACEPOINT(context, event, ...)` for a tracepoint with up to twelve arguments
(`...` is a variadic). These arguments can pass data to tracing scripts and are
typically boolean, integer, or pointer to bytes or C-style strings. Often, the
arguments need to be prepared by, for example, converting a C++ `std::string`
to a C-style string with `c_str()`, calling getter functions, or doing some
other light calculations. To avoid computational overhead by perparing
tracepoint arguments for users not using the tracepoints, the arguments should
only be prepared if there is something attached to the tracepoint.

On Linux, this is solved with a counting semaphore for each tracepoint. When a
tracing toolkit like bpftrace, bcc, or libbpf attaches to a tracepoint, the
respective semaphore is increased. It's decreased when the tracing toolkit
detaches from the tracepoint. By checking if the semaphore is greater than
zero, we can cheaply gate the preparation of the tracepoint. The macro
`TRACEPOINT_SEMAPHORE(context, event)` produces such a semaphore as a global
variable. It must be placed in the same file as the tracepoint macro. The
`TRACEPOINT(context, event, ...)` macro already includes the check if the
tracepoint is being used.

```C++
// The `net:outbound_message` tracepoint with 6 arguments in `src/net.cpp`.

TRACEPOINT_SEMAPHORE(net, outbound_message);
…
void CConnman::PushMessage(…) {
  …
  TRACEPOINT(net, outbound_message,
      pnode->GetId(),
      pnode->m_addr_name.c_str(),
      pnode->ConnectionTypeAsString().c_str(),
      sanitizedType.c_str(),
      msg.data.size(),
      msg.data.data()
  );
  …
}
```

If needed, an extra `if(TRACEPOINT_ACTIVE(context, event) {..}` check can be
used to prepare arguments right before the tracepoint.

```C++
// A fictitious `multiline:argument_preparation` tracepoint with a single argument.

TRACEPOINT_SEMAPHORE(multiline, argument_preparation);
…
if(TRACEPOINT_ACTIVE(multiline, argument_preparation) {
  argument = slightly_expensive_calulation();
  TRACEPOINT(multiline, argument_preparation, argument);
}
```

```C++
// The `test:zero_args` tracepoint without arguments in `src/test/util_trace_tests.cpp`.
TRACEPOINT_SEMAPHORE(test, zero_args);
…
TRACEPOINT0(test, zero_args);
```


Step-by-step orientation for adding a new tracepoint:

1. Familiarize yourself with the tracepoint macros mentioned above and the
   tracepoint guidelines and best practices below.
2. Do you need a tracepoint? Tracepoints are a machine-to-machine
   interface. Would a machine-to-human interface like logging work too? Is this
   something others could need too?
3. Think about where to place the new tracepoint and which arguments you want to
   pass. Where are the arguments already available? How expensive are the
   arguments to compute?
4. Pick descriptive names for the `context` and `event`. Check the list of
   existing tracepoints too. Your tracepoint might fit into an existing context.
5. Place the tracepoint, `#include <util/trace.h>`, and place a
   `TRACEPOINT_SEMAPHORE(context, event)`.
6. Document the tracepoint with its arguments and what event it traces in the
   list in this document.
7. Add a functional test for the tracepoint in
   `test/functional/interface_usdt_{context}.py`.
8. Add a tracepoint usage example in `contrib/tracing/`.

### Guidelines and best practices

#### Clear motivation and use case
Tracepoints need a clear motivation and use case. The motivation should
outweigh the impact on, for example, code readability. There is no point in
adding tracepoints that don't end up being used. Additionally, adding many of
lines of code just for tracepoint argument preparation probably comes with a high
cost on code readability. During review, such a change might be rejected.

#### Provide an example
When adding a new tracepoint, provide an example. Examples can show the use case
and help reviewers testing that the tracepoint works as intended. The examples
can be kept simple but should give others a starting point when working with
the tracepoint. See existing examples in [contrib/tracing/].

[contrib/tracing/]: ../contrib/tracing/

#### Limit expensive computations for tracepoints
While the tracepoint arguments are only prepared when we attach something to the
tracepoint, an argument preparation should never hang the process. Hashing and
serialization of data structures is probably fine, a `sleep(10s)` not.

#### Semi-stable API
Tracepoints should have a semi-stable API. Users should be able to rely on the
tracepoints for scripting. This means tracepoints need to be documented, and the
argument order ideally should not change. If there is an important reason to
change argument order, make sure to document the change and update the examples
using the tracepoint.

#### eBPF Virtual Machine limits
Keep the eBPF Virtual Machine limits in mind. eBPF programs receiving data from
the tracepoints run in a sandboxed Linux kernel VM. This VM has a limited stack
size of 512 bytes. Check if it makes sense to pass larger amounts of data, for
example, with a tracing script that can handle the passed data.

#### `bpftrace` argument limit
While tracepoints can have up to 12 arguments, bpftrace scripts currently only
support reading from the first six arguments (`arg0` till `arg5`) on `x86_64`.
bpftrace currently lacks real support for handling and printing binary data,
like block header hashes and txids. When a tracepoint passes more than six
arguments, then string and integer arguments should preferably be placed in the
first six argument fields. Binary data can be placed in later arguments. The BCC
supports reading from all 12 arguments.

#### Strings as C-style String
Generally, strings should be passed into the `TRACEPOINT()` macros as pointers
to C-style strings (a null-terminated sequence of characters). For C++
`std::strings`, [`c_str()`]  can be used. It's recommended to document the
maximum expected string size if known.

[`c_str()`]: https://www.cplusplus.com/reference/string/string/c_str/


## Listing available tracepoints

Multiple tools can list the available tracepoints in a `bitcoind` binary with
USDT support.

### GDB - GNU Project Debugger

To list probes in Bitcoin Core, use `info probes` in `gdb`:

```
$ gdb ./src/bitcoind
…
(gdb) info probes
Type Provider   Name             Where              Semaphore Object
stap net        inbound_message  0x000000000014419e /src/bitcoind
stap net        outbound_message 0x0000000000107c05 /src/bitcoind
stap validation block_connected  0x00000000002fb10c /src/bitcoind
…
```

### With `readelf`

The `readelf` tool can be used to display the USDT tracepoints in Bitcoin Core.
Look for the notes with the description `NT_STAPSDT`.

```
$ readelf -n ./src/bitcoind | grep NT_STAPSDT -A 4 -B 2
Displaying notes found in: .note.stapsdt
  Owner                Data size	Description
  stapsdt              0x0000005d	NT_STAPSDT (SystemTap probe descriptors)
    Provider: net
    Name: outbound_message
    Location: 0x0000000000107c05, Base: 0x0000000000579c90, Semaphore: 0x0000000000a69780
    Arguments: -8@%r12 8@%rbx 8@%rdi 8@192(%rsp) 8@%rax 8@%rdx
…
```

### With `tplist`

The `tplist` tool is provided by BCC (see [Installing BCC]). It displays kernel
tracepoints or USDT probes and their formats (for more information, see the
[`tplist` usage demonstration]). There are slight binary naming differences
between distributions. For example, on
[Ubuntu the binary is called `tplist-bpfcc`][ubuntu binary].

[Installing BCC]: https://github.com/iovisor/bcc/blob/master/INSTALL.md
[`tplist` usage demonstration]: https://github.com/iovisor/bcc/blob/master/tools/tplist_example.txt
[ubuntu binary]: https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---binary

```
$ tplist -l ./src/bitcoind -v
b'net':b'outbound_message' [sema 0xa69780]
  1 location(s)
  6 argument(s)
…
```
