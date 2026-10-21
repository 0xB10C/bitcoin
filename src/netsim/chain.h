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

namespace netsim {

/** The chain every simulated node shares, and the miner that extends it.
 *
 * Why this exists at all: with a genesis-only chain no node ever announces
 * anything, and `ConsiderEviction` disconnects every outbound peer that has
 * not announced a chain as long as ours within twenty minutes. That is Core
 * behaving correctly given a static chain, but it made any run longer than
 * twenty simulated minutes useless. A chain that advances removes the problem
 * at its source rather than gating the check off.
 *
 * ## The deviation worth knowing about
 *
 * There is **one** `ChainstateManager` for the whole population, so every node
 * sees the same tip at the same instant. Block *announcement* is therefore
 * real — each node's `PeerManager` is registered with the validation signals,
 * gets `UpdatedBlockTip`, and pushes headers to its own peers, which is what
 * advances `pindexBestKnownBlock` on the receiving side and keeps the
 * chain-sync timer satisfied. Block *transfer* is not: a peer offered a header
 * it already has will never ask for the block, so no `getdata`/`block`
 * exchange happens and initial block download cannot be simulated.
 *
 * Making that real needs one `Chainstate` per node — separable in principle,
 * since assumeutxo already runs two over one `BlockManager`, but each still
 * wants its own `CCoinsViewDB`. At ten thousand nodes that is ten thousand
 * LevelDB instances, so it is out of reach at the sizes this simulator exists
 * for. For topology and address relay it costs nothing, because both only need
 * the tip to move.
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
        uint256 rng_seed{uint256{1}};
    };

    Chain(const SharedContext& ctx, const Options& opts);

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
    void Prefill(std::chrono::seconds end);

    /** Mine one block on the tip, timestamped at the current mock time.
     *
     * Returns false if the block was not accepted, which would be a bug rather
     * than an expected outcome.
     */
    bool MineOne();

    /** How long until the next block, drawn from `Options`. */
    std::chrono::seconds NextInterval();

    int Height() const;
    /** Blocks mined during the run, excluding the prefilled chain. */
    uint64_t Mined() const { return m_mined - m_prefilled; }

private:
    const SharedContext& m_ctx;
    const Options m_opts;
    FastRandomContext m_rng;
    uint64_t m_mined{0};
    uint64_t m_prefilled{0};
};

} // namespace netsim

#endif // BITCOIN_NETSIM_CHAIN_H
