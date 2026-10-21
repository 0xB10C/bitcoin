// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netsim/chain.h>

#include <chain.h>
#include <hash.h>
#include <node/block_template_manager.h>
#include <node/miner.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <script/script.h>
#include <sync.h>
#include <util/check.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

#include <memory>
#include <string>
#include <algorithm>
#include <vector>

namespace netsim {

namespace {
/** Its own stream off the run's seed, so the block schedule is reproducible
 *  and does not shift when anything else changes how often it draws. */
uint256 ChainSeed(const uint256& run_seed)
{
    HashWriter writer{};
    writer << std::string{"netsim/chain"} << run_seed;
    return writer.GetHash();
}
/** Grow the coinbase with unspendable filler until the block is near `target`.
 *
 * Zero-value OP_RETURN outputs. They are consensus-valid: an OP_RETURN output
 * script is never executed, so the 10,000-byte `MAX_SCRIPT_SIZE` limit does
 * not apply to it, and nothing in `CheckTransaction` or `CheckBlock` caps the
 * number or size of outputs beyond the block weight. They are also free to
 * validate, which matters when a thousand nodes each validate every block.
 *
 * Deliberately crude, and the honest alternative is a mempool with real
 * transaction relay filling blocks the way the network does. What this buys is
 * the right number of bytes on the wire, which is what a propagation curve is
 * made of.
 */
void PadCoinbase(CBlock& block, size_t target)
{
    constexpr size_t CHUNK{9000};
    CMutableTransaction coinbase{*block.vtx[0]};

    size_t have{::GetSerializeSize(TX_WITH_WITNESS(block))};
    while (have < target) {
        const size_t want{std::min(CHUNK, target - have)};
        // Each output costs a little more than its script: the 8-byte value
        // and the script-length prefix. Overshooting the target by a few bytes
        // on the last chunk is not worth arithmetic.
        CScript filler;
        filler << OP_RETURN << std::vector<unsigned char>(want, 0x00);
        coinbase.vout.emplace_back(0, filler);
        have += want + 16;
    }

    block.vtx[0] = MakeTransactionRef(std::move(coinbase));
}
} // namespace

Chain::Chain(ChainstateManager& chainman, node::BlockTemplateManager* templates,
             ValidationSignals* signals, const Options& opts)
    : m_chainman{chainman}, m_templates{templates}, m_signals{signals}, m_opts{opts},
      m_rng{ChainSeed(opts.rng_seed)}
{
}

std::chrono::seconds Chain::NextInterval()
{
    if (!m_opts.poisson) return m_opts.spacing;
    // The same primitive MaybeSendAddr uses for its own Poisson timers. Mock
    // time is whole seconds, so a draw rounds down to zero about once every
    // six hundred blocks at the ten-minute mean; the template's nTime rule
    // then puts the block one second past the median anyway, so a zero gap is
    // harmless rather than something to clamp away.
    return std::chrono::duration_cast<std::chrono::seconds>(
        m_rng.rand_exp_duration(std::chrono::duration_cast<std::chrono::microseconds>(m_opts.spacing)));
}

int Chain::Height() const
{
    LOCK(cs_main);
    return m_chainman.ActiveChain().Height();
}

std::shared_ptr<const CBlock> Chain::MineOne()
{
    auto& templates{*Assert(m_templates)};
    // The same route the test fixture and the real miner take. Going through
    // BlockTemplateManager rather than assembling a block here means the
    // coinbase, the witness commitment, the difficulty and the timestamp rules
    // are all Core's.
    auto tmpl{templates.CreateNewTemplate({
        .use_mempool = false,
        // Anyone-can-spend. Nothing in the simulation ever spends a coinbase,
        // and a real output script would mean carrying a key around.
        .coinbase_output_script = CScript{} << OP_TRUE,
    })};
    if (!tmpl) return nullptr;

    CBlock block{tmpl->block};
    if (m_opts.target_block_bytes > 0) PadCoinbase(block, m_opts.target_block_bytes);
    // After the padding, so the merkle root and the witness commitment cover it.
    node::RegenerateCommitments(block, m_chainman);
    // Regtest's target is trivial, so this finds a nonce in a handful of tries.
    while (!CheckProofOfWork(block.GetHash(), block.nBits, m_chainman.GetConsensus())) {
        ++block.nNonce;
    }

    const auto shared{std::make_shared<const CBlock>(block)};
    if (!m_chainman.ProcessNewBlock(shared, /*force_processing=*/true, /*min_pow_checked=*/true,
                                    /*new_block=*/nullptr)) {
        return nullptr;
    }
    ++m_mined;

    // Drain the queue rather than letting the scheduler thread deliver
    // UpdatedBlockTip whenever it gets round to it. Every node's PeerManager is
    // a subscriber, so without this the announcements would land at an
    // arbitrary point in the event loop and the run would stop being
    // reproducible.
    if (m_signals != nullptr) {
        m_signals->SyncWithValidationInterfaceQueue();
    }
    return shared;
}

void Chain::Prefill(std::chrono::seconds end,
                    const std::function<void(const std::shared_ptr<const CBlock>&)>& also)
{
    const uint32_t count{m_opts.initial_blocks};
    if (count == 0) return;
    Assert(m_opts.spacing.count() > 0);
    // Already there. The chainstate is shared, so whoever asked first built
    // it; the driver does so before it reads the memory baseline, which keeps
    // a thousand blocks of block index and LevelDB cache out of the per-node
    // figure.
    if (Height() >= static_cast<int>(count)) return;

    // Draw the intervals first, so the last block can be made to land exactly
    // on `end` whatever they add up to.
    std::vector<std::chrono::seconds> gaps;
    gaps.reserve(count);
    std::chrono::seconds span{0};
    for (uint32_t i{1}; i < count; ++i) {
        gaps.push_back(NextInterval());
        span += gaps.back();
    }

    const uint64_t before{m_mined};
    std::chrono::seconds when{end - span};
    for (uint32_t i{0}; i < count; ++i) {
        SetMockTime(when);
        const auto block{MineOne()};
        Assert(block);
        // Hand the block to everyone else, so a population with a chain each
        // starts out synced instead of each node having to download the whole
        // prefill by relay before anything under study happens.
        if (also) also(block);
        if (i < gaps.size()) when += gaps[i];
    }
    SetMockTime(end);
    // Not counted as mining: these blocks are the chain the run starts from.
    m_prefilled += m_mined - before;
}

} // namespace netsim
