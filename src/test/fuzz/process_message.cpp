// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addrman.h>
#include <banman.h>
#include <kernel/chainparams.h>
#include <net.h>
#include <net_processing.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/cost.h>
#include <test/fuzz/util/net.h>
#include <test/util/net.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <test/util/validation.h>
#include <uint256.h>
#include <util/check.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {
TestingSetup* g_setup;
std::string_view LIMIT_TO_MESSAGE_TYPE{};

} // namespace

extern void MakeRandDeterministicDANGEROUS(const uint256& seed) noexcept;

void initialize_process_message()
{
    FakeNodeClock init_clock{}; // Uses the existing mock time
    if (const auto val{std::getenv("LIMIT_TO_MESSAGE_TYPE")}) {
        LIMIT_TO_MESSAGE_TYPE = val;
        Assert(std::count(ALL_NET_MESSAGE_TYPES.begin(), ALL_NET_MESSAGE_TYPES.end(), LIMIT_TO_MESSAGE_TYPE)); // Unknown message type passed
    }

    static const auto testing_setup{
        MakeNoLogFileContext<TestingSetup>(
            /*chain_type=*/ChainType::REGTEST,
            {}),
    };
    g_setup = testing_setup.get();
    ResetChainmanAndMempool(*g_setup, init_clock, {.init_block_filter_basic = true});

    fuzz_cost::Init(ALL_NET_MESSAGE_TYPES);
}

namespace {
//! Sum what the measured block queued for sending back, per reply type.
//! Must run before the trial closes, i.e. inside the measured loop.
void AddQueuedReplies(fuzz_cost::Trial& cost, CNode& node)
{
    if (!fuzz_cost::Enabled()) return;
    LOCK(node.cs_vSend);
    for (const auto& msg : node.vSendMsg) {
        cost.AddBytesOut(msg.m_type, msg.data.size() + CMessageHeader::HEADER_SIZE);
    }
}
} // namespace

FUZZ_TARGET(process_message, .init = initialize_process_message)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    auto& node{g_setup->m_node};
    auto& connman{static_cast<ConnmanTestMsg&>(*node.connman)};
    connman.Reset();
    auto& chainman{static_cast<TestChainstateManager&>(*node.chainman)};
    const auto block_index_size{WITH_LOCK(chainman.GetMutex(), return chainman.BlockIndex().size())};
    const auto initial_sequence{WITH_LOCK(node.mempool->cs, return node.mempool->GetSequence())};
    FakeNodeClock node_clock{1610000000s}; // 2021-01-07, arbitrary
    FakeSteadyClock steady_clock;
    chainman.ResetIbd();
    chainman.DisableNextWrite();

    // Reset, so that dangling pointers can be detected by sanitizers.
    node.banman.reset();
    node.addrman.reset();
    node.peerman.reset();
    node.addrman = std::make_unique<AddrMan>(*node.netgroupman, /*deterministic=*/true, /*consistency_check_ratio=*/0);
    node.peerman = PeerManager::make(connman, *node.addrman,
                                     /*banman=*/nullptr, chainman,
                                     *node.mempool, *node.warnings,
                                     PeerManager::Options{
                                         .reconcile_txs = true,
                                         .deterministic_rng = true,
                                     });

    connman.SetMsgProc(node.peerman.get());
    connman.SetAddrman(*node.addrman);
    LOCK(NetEventsInterface::g_msgproc_mutex);

    const std::string random_message_type{fuzzed_data_provider.ConsumeBytesAsString(CMessageHeader::MESSAGE_TYPE_SIZE).c_str()};
    if (!LIMIT_TO_MESSAGE_TYPE.empty() && random_message_type != LIMIT_TO_MESSAGE_TYPE) {
        return;
    }

    node.validation_signals->RegisterValidationInterface(node.peerman.get());

    CNode& p2p_node = *ConsumeNodeAsUniquePtr(fuzzed_data_provider, steady_clock).release();

    connman.AddTestNode(p2p_node);
    FillNode(fuzzed_data_provider, connman, p2p_node);

    node_clock.set(ConsumeTime(fuzzed_data_provider));

    CSerializedNetMsg net_msg;
    net_msg.m_type = random_message_type;
    net_msg.data = ConsumeRandomLengthByteVector(fuzzed_data_provider, MAX_PROTOCOL_MESSAGE_LENGTH);
    const size_t net_msg_size{net_msg.data.size()};

    connman.FlushSendBuffer(p2p_node);
    (void)connman.ReceiveMsgFrom(p2p_node, std::move(net_msg));

    if (fuzzed_data_provider.ConsumeBool()) {
        chainman.JumpOutOfIbd();
    }

    // Measure only the processing loop: not the node setup above, not the
    // validation-queue drain or the chainstate reset below. Processing mutates
    // mempool, chainstate and peer state, so it must not be re-run; champion
    // timings are re-measured by replaying the input in a fresh process.
    fuzz_cost::Trial cost{fuzz_cost::LabelIndex(random_message_type),
                          net_msg_size + CMessageHeader::HEADER_SIZE,
                          buffer, /*repeatable=*/false};
    while (cost.Next()) {
        bool more_work{true};
        while (more_work) {
            p2p_node.fPauseSend = false;
            try {
                more_work = connman.ProcessMessagesOnce(p2p_node);
            } catch (const std::ios_base::failure&) {
            }
            node.peerman->SendMessages(p2p_node);
        }
        AddQueuedReplies(cost, p2p_node);
        cost.SetDisconnect(p2p_node.fDisconnect);
        cost.SetConnected(p2p_node.fSuccessfullyConnected);
    }
    node.validation_signals->SyncWithValidationInterfaceQueue();
    node.validation_signals->UnregisterValidationInterface(node.peerman.get());
    node.connman->StopNodes();
    const auto end_sequence{WITH_LOCK(node.mempool->cs, return node.mempool->GetSequence())};
    if (block_index_size != WITH_LOCK(chainman.GetMutex(), return chainman.BlockIndex().size()) || initial_sequence != end_sequence) {
        // Reuse the global chainman and mempool, but reset them when dirty.
        MakeRandDeterministicDANGEROUS(uint256::ZERO);
        ResetChainmanAndMempool(*g_setup, node_clock, {.init_block_filter_basic = true});
    }
}
