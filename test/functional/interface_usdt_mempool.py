#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""  Tests the mempool:* tracepoint API interface.
     See https://github.com/bitcoin/bitcoin/blob/master/doc/tracing.md#context-mempool
"""

from decimal import Decimal

# Test will be skipped if we don't have bcc installed
try:
    from bcc import BPF, USDT # type: ignore[import]
except ImportError:
    pass

from test_framework.blocktools import COINBASE_MATURITY, MAX_BLOCK_SIGOPS
from test_framework.messages import COIN, DEFAULT_MEMPOOL_EXPIRY_HOURS
from test_framework.p2p import P2PDataStore
from test_framework.script import OP_CHECKSIG, CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

MEMPOOL_TRACEPOINTS_PROGRAM = """
# include <uapi/linux/ptrace.h>

// The longest address type is tor v3 at 62 chars + 6 chars for the port (':12345').
#define MAX_PEER_ADDR_LENGTH            (62+6)
// The longest rejection reason is 118 chars and is generated in case of SCRIPT_ERR_EVAL_FALSE by
// strprintf("mandatory-script-verify-flag-failed (%s)", ScriptErrorString(check.GetScriptError()))
#define MAX_REJECT_REASON_LENGTH        118
// The longest string returned by RemovalReasonToString() is 'sizelimit'
#define MAX_REMOVAL_REASON_LENGTH       9
#define HASH_LENGTH                     32
// For this test, we don't expect transactions larger than MAX_TX_SIZE byte.
// On mainnet, transactions can certainly be larger.
#define MAX_TX_SIZE                     32768

#define MIN(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })

struct added_event
{
  u8    hash[HASH_LENGTH];
  u64   vsize;
  s64   fee;
  u64   size;
  u8    tx[MAX_TX_SIZE];
};

struct removed_event
{
  u8    hash[HASH_LENGTH];
  char  reason[MAX_REMOVAL_REASON_LENGTH];
  u64   vsize;
  s64   fee;
  u64   size;
  u8    tx[MAX_TX_SIZE];
};

struct rejected_event
{
  u8    hash[HASH_LENGTH];
  char  reason[MAX_REJECT_REASON_LENGTH];
  s64   peer_id;
  char  peer_addr[MAX_PEER_ADDR_LENGTH];
  u64   size;
  u8    tx[MAX_TX_SIZE];
};

struct replaced_event
{
  u8    replacement_hash[HASH_LENGTH];
  u64   replacement_vsize;
  s64   replacement_fee;
  u8    replaced_hash[HASH_LENGTH];
  u64   replaced_vsize;
  s64   replaced_fee;
  u64   replaced_added_time;
  u64   replacement_size;
  u8    replacement_tx[MAX_TX_SIZE]; // swap?
  u64   replaced_size; // ^^^
  u8    replaced_tx[MAX_TX_SIZE];
};

// BPF ring buffer to push the data to user space. The ring buffer allows us to
// allocated enough space for the raw transactions compared to a
// BPF_PERFBUF_OUTPUT.
BPF_RINGBUF_OUTPUT(added_events, 128);
BPF_RINGBUF_OUTPUT(removed_events, 128);
BPF_RINGBUF_OUTPUT(rejected_events, 128);
BPF_RINGBUF_OUTPUT(replaced_events, 128);

int trace_added(struct pt_regs *ctx) {
  struct added_event *added = added_events.ringbuf_reserve(sizeof(struct added_event));
  if (!added) return -1;

  bpf_usdt_readarg_p(1, ctx, &added->hash, HASH_LENGTH);
  bpf_usdt_readarg(2, ctx, &added->vsize);
  bpf_usdt_readarg(3, ctx, &added->fee);
  bpf_usdt_readarg(4, ctx, &added->size);
  // If the transaction is larger than MAX_TX_SIZE, it's cut-off after MAX_TX_SIZE bytes.
  bpf_usdt_readarg_p(5, ctx, &added->tx, MIN(added->size, MAX_TX_SIZE));
  added_events.ringbuf_submit(added, 0);
  return 0;
}

int trace_removed(struct pt_regs *ctx) {
  struct removed_event *removed = removed_events.ringbuf_reserve(sizeof(struct removed_event));
  if (!removed) return -1;

  bpf_usdt_readarg_p(1, ctx, &removed->hash, HASH_LENGTH);
  bpf_usdt_readarg_p(2, ctx, &removed->reason, MAX_REMOVAL_REASON_LENGTH);
  bpf_usdt_readarg(3, ctx, &removed->vsize);
  bpf_usdt_readarg(4, ctx, &removed->fee);
  bpf_usdt_readarg(5, ctx, &removed->size);
  // If the transaction is larger than MAX_TX_SIZE, it's cut-off after MAX_TX_SIZE bytes.
  bpf_usdt_readarg_p(6, ctx, &removed->tx, MIN(removed->size, MAX_TX_SIZE));

  removed_events.ringbuf_submit(removed, 0);
  return 0;
}

int trace_rejected(struct pt_regs *ctx) {
  struct rejected_event *rejected = rejected_events.ringbuf_reserve(sizeof(struct rejected_event));
  if (!rejected) return -1;

  bpf_usdt_readarg_p(1, ctx, &rejected->hash, HASH_LENGTH);
  bpf_usdt_readarg_p(2, ctx, &rejected->reason, MAX_REJECT_REASON_LENGTH);
  bpf_usdt_readarg(3, ctx, &rejected->peer_id);
  bpf_usdt_readarg_p(4, ctx, &rejected->peer_addr, MAX_PEER_ADDR_LENGTH);
  bpf_usdt_readarg(5, ctx, &rejected->size);
  // If the transaction is larger than MAX_TX_SIZE, it's cut-off after MAX_TX_SIZE bytes.
  bpf_usdt_readarg_p(6, ctx, &rejected->tx, MIN(rejected->size, MAX_TX_SIZE));

  rejected_events.ringbuf_submit(rejected, 0);
  return 0;
}

int trace_replaced(struct pt_regs *ctx) {
  struct replaced_event *replaced = replaced_events.ringbuf_reserve(sizeof(struct replaced_event));
  if (!replaced) return -1;

  bpf_usdt_readarg_p(1, ctx, &replaced->replacement_hash, HASH_LENGTH);
  bpf_usdt_readarg(2, ctx, &replaced->replacement_vsize);
  bpf_usdt_readarg(3, ctx, &replaced->replacement_fee);
  bpf_usdt_readarg_p(4, ctx, &replaced->replaced_hash, HASH_LENGTH);
  bpf_usdt_readarg(5, ctx, &replaced->replaced_vsize);
  bpf_usdt_readarg(6, ctx, &replaced->replaced_fee);
  bpf_usdt_readarg(7, ctx, &replaced->replaced_time_added);
  bpf_usdt_readarg(8, ctx, &replaced->replacement_size);
  bpf_usdt_readarg_p(9, ctx, &replaced->replacement_tx, MIN(replaced->replacement_size, MAX_TX_SIZE));
  bpf_usdt_readarg(10, ctx, &replaced->replaced_size);
  bpf_usdt_readarg_p(11, ctx, &replaced->replaced_tx, MIN(replaced->replaced_size, MAX_TX_SIZE));

  replaced_events.ringbuf_submit(replaced, 0);
  return 0;
}
"""


class MempoolTracepointTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [
            [
                "-acceptnonstdtxn=1",
            ]
        ]
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_linux()
        self.skip_if_no_bitcoind_tracepoints()
        self.skip_if_no_python_bcc()
        self.skip_if_no_bpf_permissions()

    def added_test(self):
        """Add a transaction to the mempool and make sure the tracepoint returns
        the expected txid, vsize, fee, and raw transaction."""

        EXPECTED_ADDED_EVENTS = 1
        handled_added_events = 0

        self.log.info("Hooking into mempool:added tracepoint...")
        node = self.nodes[0]
        ctx = USDT(pid=node.process.pid)
        ctx.enable_probe(probe="mempool:added", fn_name="trace_added")
        bpf = BPF(text=MEMPOOL_TRACEPOINTS_PROGRAM, usdt_contexts=[ctx], debug=0)

        def handle_added_event(_, data, __):
            nonlocal handled_added_events
            event = bpf["added_events"].event(data)
            assert_equal(txid, bytes(event.hash)[::-1].hex())
            assert_equal(vsize, event.vsize)
            assert_equal(fee, event.fee)
            tx_size = event.size
            assert_equal(tx_hex, bytes(event.tx)[:tx_size].hex())
            handled_added_events += 1

        bpf["added_events"].open_ring_buffer(handle_added_event)

        self.log.info("Sending transaction...")
        fee = Decimal(31200)
        tx = self.wallet.send_self_transfer(from_node=node, fee=fee/COIN)
        # expected data
        txid = tx["txid"]
        vsize = tx["tx"].get_vsize()
        tx_hex = tx["hex"]

        self.log.info("Polling buffer...")
        bpf.ring_buffer_poll(timeout=200)

        self.log.info("Cleaning up mempool...")
        self.generate(node, 1)

        bpf.cleanup()

        self.log.info("Ensuring mempool:added event was handled successfully...")
        assert_equal(EXPECTED_ADDED_EVENTS, handled_added_events)

    def removed_test(self):
        """Expire a transaction from the mempool and make sure the tracepoint returns
        the expected txid, expiry reason, vsize, and fee."""

        EXPECTED_REMOVED_EVENTS = 1
        handled_removed_events = 0

        self.log.info("Hooking into mempool:removed tracepoint...")
        node = self.nodes[0]
        ctx = USDT(pid=node.process.pid)
        ctx.enable_probe(probe="mempool:removed", fn_name="trace_removed")
        bpf = BPF(text=MEMPOOL_TRACEPOINTS_PROGRAM, usdt_contexts=[ctx], debug=0)

        def handle_removed_event(_, data, __):
            nonlocal handled_removed_events
            event = bpf["removed_events"].event(data)
            assert_equal(txid, bytes(event.hash)[::-1].hex())
            assert_equal(reason, event.reason.decode("UTF-8"))
            assert_equal(vsize, event.vsize)
            assert_equal(fee, event.fee)
            tx_size = event.size
            assert_equal(tx_hex, bytes(event.tx)[:tx_size].hex())
            handled_removed_events += 1

        bpf["removed_events"].open_ring_buffer(handle_removed_event)

        self.log.info("Sending transaction...")
        fee = Decimal(31200)
        tx = self.wallet.send_self_transfer(from_node=node, fee=fee/COIN)
        # expected data
        txid = tx["txid"]
        reason = "expiry"
        vsize = tx["tx"].get_vsize()
        tx_hex = tx["hex"]

        self.log.info("Fast-forwarding time to mempool expiry...")
        entry_time = node.getmempoolentry(txid)["time"]
        expiry_time = entry_time + 60 * 60 * DEFAULT_MEMPOOL_EXPIRY_HOURS + 5
        node.setmocktime(expiry_time)

        self.log.info("Triggering expiry...")
        self.wallet.get_utxo(txid=txid)
        self.wallet.send_self_transfer(from_node=node)

        self.log.info("Polling buffer...")
        bpf.ring_buffer_poll(timeout=200)

        bpf.cleanup()

        self.log.info("Ensuring mempool:removed event was handled successfully...")
        assert_equal(EXPECTED_REMOVED_EVENTS, handled_removed_events)

    def replaced_test(self):
        """Replace one and two transactions in the mempool and make sure the tracepoint
        returns the expected txids, vsizes, and fees."""

        EXPECTED_REPLACED_EVENTS = 1
        handled_replaced_events = 0

        self.log.info("Hooking into mempool:replaced tracepoint...")
        node = self.nodes[0]
        ctx = USDT(pid=node.process.pid)
        ctx.enable_probe(probe="mempool:replaced", fn_name="trace_replaced")
        bpf = BPF(text=MEMPOOL_TRACEPOINTS_PROGRAM, usdt_contexts=[ctx], debug=0)

        def handle_replaced_event(_, data, __):
            nonlocal handled_replaced_events
            event = bpf["replaced_events"].event(data)
            assert_equal(replaced_txid, bytes(event.replaced_hash)[::-1].hex())
            assert_equal(replaced_vsize, event.replaced_vsize)
            assert_equal(replaced_fee, event.replaced_fee)
            assert_equal(replacement_txid, bytes(event.replacement_hash)[::-1].hex())
            assert_equal(replacement_vsize, event.replacement_vsize)
            assert_equal(replacement_fee, event.replacement_fee)
            replacement_size = event.replacement_size
            assert_equal(replacement_hex, bytes(event.replacement_tx)[:replacement_size].hex())
            replaced_size = event.replaced_size
            assert_equal(replaced_hex, bytes(event.replaced_tx)[:replaced_size].hex())
            handled_replaced_events += 1

        bpf["replaced_events"].open_ring_buffer(handle_replaced_event)

        self.log.info("Sending RBF transaction...")
        utxo = self.wallet.get_utxo(mark_as_spent=True)
        original_fee = Decimal(40000)
        original_tx = self.wallet.send_self_transfer(
            from_node=node, utxo_to_spend=utxo, fee=original_fee/COIN
        )

        self.log.info("Sending replacement transaction...")
        replacement_fee = Decimal(45000)
        replacement_tx = self.wallet.send_self_transfer(
            from_node=node, utxo_to_spend=utxo, fee=replacement_fee/COIN
        )

        # expected data
        replaced_txid = original_tx["txid"]
        replaced_vsize = original_tx["tx"].get_vsize()
        replaced_fee = original_fee
        replaced_hex = original_tx["hex"]
        replacement_txid = replacement_tx["txid"]
        replacement_vsize = replacement_tx["tx"].get_vsize()
        replacement_hex = replacement_tx["hex"]

        self.log.info("Polling buffer...")
        bpf.ring_buffer_poll(timeout=200)

        bpf.cleanup()

        self.log.info("Ensuring mempool:replaced event was handled successfully...")
        assert_equal(EXPECTED_REPLACED_EVENTS, handled_replaced_events)

    def rejected_test(self):
        """Create an invalid transaction and make sure the tracepoint returns
        the expected txid, rejection reason, peer id, and peer address."""

        EXPECTED_REJECTED_EVENTS = 1
        handled_rejected_events = 0

        self.log.info("Adding P2P connection...")
        node = self.nodes[0]
        node.add_p2p_connection(P2PDataStore())

        self.log.info("Hooking into mempool:rejected tracepoint...")
        ctx = USDT(pid=node.process.pid)
        ctx.enable_probe(probe="mempool:rejected", fn_name="trace_rejected")
        bpf = BPF(text=MEMPOOL_TRACEPOINTS_PROGRAM, usdt_contexts=[ctx], debug=0)

        def handle_rejected_event(_, data, __):
            nonlocal handled_rejected_events
            event = bpf["rejected_events"].event(data)
            assert_equal(txid, bytes(event.hash)[::-1].hex())
            assert_equal(reason, event.reason.decode("UTF-8"))
            assert_equal(peer_id, event.peer_id)
            assert_equal(peer_addr, event.peer_addr.decode("UTF-8"))
            tx_size = event.size
            assert_equal(tx_hex, bytes(event.tx)[:tx_size].hex())
            handled_rejected_events += 1

        bpf["rejected_events"].open_ring_buffer(handle_rejected_event)

        self.log.info("Sending invalid transaction...")
        tx = self.wallet.create_self_transfer()["tx"]
        tx.vout[0].scriptPubKey = CScript([OP_CHECKSIG] * (MAX_BLOCK_SIGOPS))
        tx.rehash()
        node.p2ps[0].send_txs_and_test([tx], node, success=False)

        # expected data
        txid = tx.hash
        reason = "bad-txns-too-many-sigops"
        peer_id = 0
        tx_hex = tx.serialize().hex()
        # extract ip and port used to connect to node
        socket = node.p2ps[0]._transport._sock
        peer_addr = ":".join([str(x) for x in socket.getsockname()])

        self.log.info("Polling buffer...")
        bpf.ring_buffer_poll(timeout=200)

        bpf.cleanup()

        self.log.info("Ensuring mempool:rejected event was handled successfully...")
        assert_equal(EXPECTED_REJECTED_EVENTS, handled_rejected_events)

    def run_test(self):
        """Tests the mempool:added, mempool:removed, mempool:replaced,
        and mempool:rejected tracepoints."""

        # Create some coinbase transactions and mature them so they can be spent
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.generate(self.wallet, 4)
        self.generate(node, COINBASE_MATURITY)

        # Test individual tracepoints
        self.added_test()
        self.removed_test()
        self.replaced_test()
        self.rejected_test()


if __name__ == "__main__":
    MempoolTracepointTest().main()
