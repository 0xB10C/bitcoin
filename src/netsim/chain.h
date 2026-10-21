// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETSIM_CHAIN_H
#define BITCOIN_NETSIM_CHAIN_H

#include <netsim/clock.h>
#include <netsim/node.h>
#include <random.h>
#include <uint256.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>

namespace netsim {

/** A chain that advances, and the miner that advances it.
 *
 * Why this exists at all: with a genesis-only chain no node ever announces
 * anything, and `ConsiderEviction` disconnects every outbound peer that has
 * not announced a chain as long as ours within twenty minutes. That is Core
 * behaving correctly given a static chain, but it made any run longer than
 * twenty simulated minutes useless. A chain that advances removes the problem
 * at its source rather than gating the check off.
 *
 * ## One chain or one each
 *
 * With `Network::Options::per_node_chain` off, the whole population shares a
 * `ChainstateManager`, so every node sees the same tip at the same instant.
 * Block *announcement* is real — each node's `PeerManager` gets
 * `UpdatedBlockTip` and pushes headers to its own peers, which is what
 * advances `pindexBestKnownBlock` on the receiving side and keeps the
 * chain-sync timer satisfied. Block *transfer* is not: `AlreadyHaveBlock` asks
 * only whether the header sits in the block index, so every node already has
 * every block and none is ever requested. Cheap, and enough for topology and
 * address relay, which only need the tip to move.
 *
 * With it on, every node validates its own chain and a block genuinely has to
 * travel: announce, `getdata`, `block`, validate, announce onward. That is
 * what makes propagation measurable, and it costs 122,816 bytes per node.
 */
class Chain
{
public:
    struct Options {
        /** Blocks to build before the run starts.
         *
         * Zero leaves the genesis-only chain, which is the historical
         * behaviour and needs `disable_chain_sync_timeout`. */
        uint32_t initial_blocks{0};
        /** Mean simulated interval between blocks, for the initial chain and
         *  for the ongoing mining alike. Bitcoin's target. */
        std::chrono::seconds spacing{600};
        /** Draw each interval from an exponential distribution with that mean,
         *  rather than spacing blocks evenly.
         *
         * Bitcoin's block arrivals are a Poisson process, so the gap between
         * two blocks is exponentially distributed and the count in any window
         * is Poisson. Even spacing is the one thing mining is definitely not,
         * and it would hide exactly the clustering that makes a twenty-minute
         * timeout interesting. Off only to let a test pin the block count. */
        bool poisson{true};
        /** Grow each block to about this many serialised bytes. Zero leaves it
         *  at the natural ~250 of an empty regtest block.
         *
         * Propagation is the reason. A 250-byte block travels at the speed of
         * latency alone, which is not how the real network behaves: for a
         * megabyte block, transfer time dominates and is what a propagation
         * curve is mostly made of. Padding gets the bytes onto the wire
         * without a mempool and transaction relay to fill blocks honestly.
         *
         * The ceiling is about 1 MB. Filler is non-witness data and weight
         * counts that four times, so a megabyte of it is already
         * MAX_BLOCK_WEIGHT. */
        size_t target_block_bytes{0};
        uint256 rng_seed{uint256{1}};
    };

    /** `chainman` and `templates` are where blocks are built.
     *
     * With one shared chain that is the population's; with a chain per node it
     * is the miner's, and the blocks reach everyone else by relay. Either may
     * be null: no templates means the chain cannot be extended, and no signals
     * means nothing is announced. */
    Chain(ChainstateManager& chainman, node::BlockTemplateManager* templates,
          ValidationSignals* signals, const Options& opts);

    /** Build `Options::initial_blocks` blocks, the last landing on `end`.
     *
     * Timestamps run up to `end` rather than from it so that the tip is fresh
     * when the run starts: `IsInitialBlockDownload` calls a tip older than
     * `max_tip_age`, a day by default, still-syncing, and a node in initial
     * block download never announces its own address.
     *
     * Mock time is moved for each block, because that is where
     * `CreateNewTemplate` takes `nTime` from, and left at `end` afterwards.
     *
     * Does nothing if the chain is already at least that tall, so whoever
     * needs it first may build it.
     */
    void Prefill(std::chrono::seconds end, const std::function<void(const std::shared_ptr<const CBlock>&)>& also = nullptr);

    /** Mine one block on the tip, timestamped at the current mock time.
     *
     * Returns the block, or null if it was not accepted, which would be a bug
     * rather than an expected outcome. The caller gets the block back so that
     * a prefill can hand it to every other node directly, which is how a
     * population with a chain each starts out synced.
     */
    std::shared_ptr<const CBlock> MineOne();

    /** How long until the next block, drawn from `Options`. */
    std::chrono::seconds NextInterval();

    int Height() const;
    /** Blocks mined during the run, excluding the prefilled chain. */
    uint64_t Mined() const { return m_mined - m_prefilled; }

private:
    ChainstateManager& m_chainman;
    node::BlockTemplateManager* m_templates;
    ValidationSignals* m_signals;
    const Options m_opts;
    FastRandomContext m_rng;
    uint64_t m_mined{0};
    uint64_t m_prefilled{0};
};

} // namespace netsim

#endif // BITCOIN_NETSIM_CHAIN_H
