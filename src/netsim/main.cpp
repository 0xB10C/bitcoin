// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Standalone driver for the in-process network simulator.
//!
//! Lives outside the test binary on purpose. A run is long, takes many knobs
//! and produces measurements, none of which fits comfortably inside a Boost
//! test case: Boost owns main(), its timeouts fight a long run, and ctest
//! would start running simulations. The regression tests in
//! test/netsim_tests.cpp exercise the same library.
//!
//! It still builds on TestingSetup, which is not a contradiction: the test
//! scaffolding is a plain static library with no Boost.Test dependency, and it
//! is the shortest route to a wired-up ChainstateManager. The fuzz binary
//! leans on it the same way.

#include <chainparams.h>
#include <net.h>
#include <netgroup.h>
#include <netsim/addresses.h>
#include <netsim/chain.h>
#include <netsim/clock.h>
#include <netsim/export.h>
#include <netsim/latency.h>
#include <netsim/metrics.h>
#include <netsim/network.h>
#include <netsim/node.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/fs.h>

#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <functional>
#include <limits>
#include <vector>

namespace {

struct Args {
    uint32_t nodes{100};
    uint32_t listeners{20};
    uint32_t minutes{30};
    uint32_t bootstrap{16};
    bool blocks_only{false};
    uint8_t seed{1};
    bool csv{false};
    bool header{false};
    std::string export_prefix;
    uint32_t service_ms{1000};
    uint32_t tracked{0};
    uint32_t sample_sec{60};
    std::string addr_csv;
    bool mainnet_mix{false};
    bool mainnet_netgroups{false};
    uint32_t chain{0};
    uint32_t block_sec{600};
    bool mine{false};
};

void PrintUsage()
{
    std::fprintf(stderr,
                 "bitcoin-netsim: in-process Bitcoin network simulator\n\n"
                 "  --nodes=N        population size (default 100)\n"
                 "  --listeners=N    how many of them accept inbound (default 20)\n"
                 "  --minutes=N      simulated minutes to run (default 30)\n"
                 "  --bootstrap=N    seed addresses per node's AddrMan (default 16; lower\n"
                 "                   values are dramatically slower, see network.h)\n"
                 "  --blocksonly     advertise fRelay=false, which avoids the\n"
                 "                   527 KiB per-peer tx inventory filter\n"
                 "  --seed=N         RNG seed byte (default 1)\n"
                 "  --csv            one machine-readable line instead of a report\n"
                 "  --csv-header     print the CSV column names and exit\n"
                 "  --service-ms=N   how often each node flushes queued sends (default 1000)\n"
                 "  --export=PREFIX  write PREFIX-nodes.csv and PREFIX-edges.csv,\n"
                 "                   readable directly by networkx or igraph\n"
                 "  --tracked=N      withhold the first N listener addresses from the\n"
                 "                   bootstrap seeding, so address relay is the only way\n"
                 "                   they can spread, and measure how far they get\n"
                 "  --sample-sec=N   how often to count who holds a tracked address\n"
                 "                   (default 60)\n"
                 "  --addr-csv=FILE  write the coverage samples there\n"
                 "  --mainnet-mix    spread addresses over IPv4, IPv6, Tor and I2P in the\n"
                 "                   measured mainnet proportions instead of IPv4 only\n"
                 "  --mainnet-groups draw /16 and /32 occupancy from the measured mainnet\n"
                 "                   distribution instead of one node per netgroup\n"
                 "  --mainnet        both of the above\n"
                 "  --chain=N        build a chain of N blocks before the run, so the\n"
                 "                   nodes start out with something to announce\n"
                 "  --mine           mine a block every --block-sec of simulated time\n"
                 "  --block-sec=N    simulated seconds between blocks (default 600)\n");
}

bool ParseUint(std::string_view text, uint32_t& out)
{
    const auto result{std::from_chars(text.data(), text.data() + text.size(), out)};
    return result.ec == std::errc{} && result.ptr == text.data() + text.size();
}

bool ParseArgs(int argc, char* argv[], Args& args)
{
    for (int i{1}; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        uint32_t value{0};

        if (arg == "--blocksonly") {
            args.blocks_only = true;
        } else if (arg == "--mainnet-mix") {
            args.mainnet_mix = true;
        } else if (arg == "--mainnet-groups") {
            args.mainnet_netgroups = true;
        } else if (arg == "--mainnet") {
            args.mainnet_mix = true;
            args.mainnet_netgroups = true;
        } else if (arg == "--mine") {
            args.mine = true;
        } else if (arg.starts_with("--chain=") && ParseUint(arg.substr(8), value)) {
            args.chain = value;
        } else if (arg.starts_with("--block-sec=") && ParseUint(arg.substr(12), value) && value > 0) {
            args.block_sec = value;
        } else if (arg == "--csv") {
            args.csv = true;
        } else if (arg == "--csv-header") {
            args.header = true;
        } else if (arg.starts_with("--nodes=") && ParseUint(arg.substr(8), value)) {
            args.nodes = value;
        } else if (arg.starts_with("--listeners=") && ParseUint(arg.substr(12), value)) {
            args.listeners = value;
        } else if (arg.starts_with("--minutes=") && ParseUint(arg.substr(10), value)) {
            args.minutes = value;
        } else if (arg.starts_with("--bootstrap=") && ParseUint(arg.substr(12), value)) {
            args.bootstrap = value;
        } else if (arg.starts_with("--seed=") && ParseUint(arg.substr(7), value) && value <= 255) {
            args.seed = static_cast<uint8_t>(value);
        } else if (arg.starts_with("--service-ms=") && ParseUint(arg.substr(13), value) && value > 0) {
            args.service_ms = value;
        } else if (arg.starts_with("--export=") && arg.size() > 9) {
            args.export_prefix = std::string{arg.substr(9)};
        } else if (arg.starts_with("--tracked=") && ParseUint(arg.substr(10), value)) {
            args.tracked = value;
        } else if (arg.starts_with("--sample-sec=") && ParseUint(arg.substr(13), value)) {
            args.sample_sec = value;
        } else if (arg.starts_with("--addr-csv=") && arg.size() > 11) {
            args.addr_csv = std::string{arg.substr(11)};
        } else {
            std::fprintf(stderr, "unrecognised argument: %s\n\n", argv[i]);
            return false;
        }
    }
    if (args.listeners > args.nodes) {
        std::fprintf(stderr, "--listeners cannot exceed --nodes\n");
        return false;
    }
    if (args.tracked > args.listeners) {
        std::fprintf(stderr, "--tracked cannot exceed --listeners\n");
        return false;
    }
    return true;
}

constexpr const char* CSV_HEADER{
    "nodes,listeners,blocks_only,minutes,links,outbound,saturated,isolated,"
    "addrman_total,known_strangers,failed,rejected,refused,bytes,"
    "rss_before_kb,rss_after_kb,sim_kb,bytes_per_node,peak_kb"};

} // namespace

// The test scaffolding expects its host binary to supply these two hooks:
// extra arguments for the node context, and a name to build a unique datadir
// from. The test and fuzz binaries define them from their own harnesses; here
// they are fixed, because a run takes its configuration from argv above.
const std::function<std::vector<const char*>()> G_TEST_COMMAND_LINE_ARGUMENTS{[] {
    return std::vector<const char*>{};
}};
const std::function<std::string()> G_TEST_GET_FULL_NAME{[] {
    return std::string{"netsim"};
}};

int main(int argc, char* argv[])
{
    Args args;
    if (!ParseArgs(argc, argv, args)) {
        PrintUsage();
        return EXIT_FAILURE;
    }
    if (args.header) {
        std::printf("%s\n", CSV_HEADER);
        return EXIT_SUCCESS;
    }

    TestOpts setup_opts;
    // Every node builds its own CConnman and PeerManager.
    setup_opts.setup_net = false;
    // Otherwise ValidationCache eagerly allocates and touches 32.25 MiB, which
    // would sit inside the memory figures below.
    setup_opts.min_validation_cache = true;
    auto context{MakeNoLogFileContext<TestingSetup>(ChainType::REGTEST, setup_opts)};

    // Self-announcement is gated on not being in initial block download, and
    // it is the only thing that propagates an address more than one hop. A run
    // with a chain leaves initial block download on its own, because its tip
    // lands on the instant the run starts; one without needs to be told.
    if (args.chain == 0) {
        static_cast<TestChainstateManager&>(*context->m_node.chainman).JumpOutOfIbd();
    }

    auto netgroupman{NetGroupManager::NoAsmap()};
    netsim::SharedContext shared{*context->m_node.chainman, *context->m_node.mempool,
                                 *context->m_node.warnings, netgroupman};
    // Only when there is a chain. Subscribing ten thousand PeerManagers to tip
    // notifications costs nothing on a chain that never moves, but it is also
    // pointless, and leaving them unsubscribed is what selects the
    // chain-sync-timeout gate in MakeNode.
    if (args.chain > 0 || args.mine) {
        shared.validation_signals = context->m_node.validation_signals.get();
        shared.block_templates = context->m_node.block_template_manager.get();
    }

    // Built here rather than left to the Network, so that the block index,
    // the block files and LevelDB's caches for a thousand blocks sit outside
    // the memory baseline below instead of being charged to the nodes. The
    // Network's own prefill then finds the chain already at height and does
    // nothing.
    const netsim::SimTime sim_start{netsim::Network::Options{}.start};
    if (args.chain > 0) {
        netsim::Chain{shared}.Prefill(args.chain, std::chrono::seconds{args.block_sec},
                                      std::chrono::duration_cast<std::chrono::seconds>(sim_start));
    }

    // Read before the population exists, so the host process and its shared
    // chainstate are excluded from the delta.
    const uint64_t rss_before{netsim::ResidentSetBytes().value_or(0)};

    netsim::Network::Options opts;
    opts.num_nodes = args.nodes;
    opts.num_listening = args.listeners;
    opts.bootstrap_addrs = args.bootstrap;
    opts.blocks_only = args.blocks_only;
    opts.rng_seed = uint256{args.seed};
    opts.service_interval = std::chrono::duration_cast<netsim::SimTime>(std::chrono::milliseconds{args.service_ms});
    opts.num_tracked = args.tracked;
    opts.addr_sample_interval = std::chrono::duration_cast<netsim::SimTime>(std::chrono::seconds{args.sample_sec});
    if (args.mainnet_mix) opts.addresses.UseMainnetMix();
    opts.addresses.mainnet_netgroups = args.mainnet_netgroups;
    opts.chain.initial_blocks = args.chain;
    opts.chain.spacing = std::chrono::seconds{args.block_sec};
    opts.mine = args.mine;

    netsim::Network net{opts, shared};
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        net.RunFor(std::chrono::duration_cast<netsim::SimTime>(std::chrono::minutes{args.minutes}));
    }

    // Before the memory reading, so the graph reflects the state that was
    // measured, and after the run so closed connections are in it.
    if (!args.export_prefix.empty()) {
        if (!netsim::WriteGraph(net, fs::PathFromString(args.export_prefix))) {
            std::fprintf(stderr, "failed to write the graph to %s-nodes.csv / -edges.csv\n",
                         args.export_prefix.c_str());
            return EXIT_FAILURE;
        }
    }
    if (!args.addr_csv.empty()) {
        if (!netsim::WriteAddrSamples(net, fs::PathFromString(args.addr_csv))) {
            std::fprintf(stderr, "failed to write the coverage samples to %s\n", args.addr_csv.c_str());
            return EXIT_FAILURE;
        }
    }

    const uint64_t rss_after{netsim::ResidentSetBytes().value_or(0)};
    const uint64_t peak{netsim::PeakResidentSetBytes().value_or(0)};
    const uint64_t sim_bytes{rss_after > rss_before ? rss_after - rss_before : 0};

    uint64_t total_outbound{0};
    uint64_t saturated{0};
    uint64_t isolated{0};
    uint64_t addrman_total{0};
    uint64_t known_strangers{0};
    for (uint32_t id{0}; id < net.NumNodes(); ++id) {
        const int outbound{net.At(id).connman->GetFullOutboundConnCount()};
        total_outbound += static_cast<uint64_t>(outbound);
        if (outbound >= MAX_OUTBOUND_FULL_RELAY_CONNECTIONS) ++saturated;
        if (outbound == 0) ++isolated;
        for (const CAddress& addr : net.At(id).addrman->GetAddr(0, 0, std::nullopt, /*filtered=*/false)) {
            ++addrman_total;
            if (!net.ListenerAt(addr).has_value()) ++known_strangers;
        }
    }

    if (args.csv) {
        std::printf("%u,%u,%d,%u,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",
                    args.nodes, args.listeners, args.blocks_only ? 1 : 0, args.minutes, static_cast<unsigned long long>(net.TotalOpened()),
                    static_cast<unsigned long long>(total_outbound), static_cast<unsigned long long>(saturated),
                    static_cast<unsigned long long>(isolated), static_cast<unsigned long long>(addrman_total),
                    static_cast<unsigned long long>(known_strangers),
                    static_cast<unsigned long long>(net.FailedAttempts()),
                    static_cast<unsigned long long>(net.RejectedAttempts()),
                    static_cast<unsigned long long>(net.InboundRefusals()),
                    static_cast<unsigned long long>(net.BytesTransferred()),
                    static_cast<unsigned long long>(rss_before / 1024),
                    static_cast<unsigned long long>(rss_after / 1024),
                    static_cast<unsigned long long>(sim_bytes / 1024),
                    static_cast<unsigned long long>(args.nodes > 0 ? sim_bytes / args.nodes : 0),
                    static_cast<unsigned long long>(peak / 1024));
        return EXIT_SUCCESS;
    }

    std::printf("population      %u nodes, %u listening%s\n", args.nodes, args.listeners,
                args.blocks_only ? ", blocks-only" : "");
    {
        using Net = netsim::AddressUniverse::Net;
        const auto& universe{net.Addresses()};
        std::printf("addresses       %u ipv4, %u ipv6, %u onion, %u i2p, in %u netgroups\n",
                    universe.CountOn(Net::IPv4), universe.CountOn(Net::IPv6),
                    universe.CountOn(Net::Onion), universe.CountOn(Net::I2P),
                    net.NumNetgroups());
    }
    std::printf("simulated       %u minutes\n", args.minutes);
    if (args.chain > 0 || args.mine) {
        std::printf("chain           height %d, %llu blocks mined during the run\n",
                    net.ChainHeight(), static_cast<unsigned long long>(net.GetChain().Mined()));
    }
    std::printf("connections     %llu opened, %llu still up, %llu saturated, %llu isolated\n",
                static_cast<unsigned long long>(net.TotalOpened()),
                static_cast<unsigned long long>(net.LiveLinks()),
                static_cast<unsigned long long>(saturated), static_cast<unsigned long long>(isolated));
    std::printf("link slots      %zu peak concurrent, %llu closed and recycled\n",
                net.LinkSlots(), static_cast<unsigned long long>(net.ClosedLinks()));
    std::printf("addrman         %llu held, %llu of them unreachable\n",
                static_cast<unsigned long long>(addrman_total),
                static_cast<unsigned long long>(known_strangers));
    if (!net.TrackedNodes().empty()) {
        // The last sample for each tracked address, which is where its
        // propagation curve ended.
        const size_t n{net.TrackedNodes().size()};
        const auto& samples{net.AddrSamples()};
        uint64_t holders{0}, in_tried{0}, worst{std::numeric_limits<uint64_t>::max()};
        for (size_t i{samples.size() >= n ? samples.size() - n : 0}; i < samples.size(); ++i) {
            holders += samples[i].holders;
            in_tried += samples[i].in_tried;
            worst = std::min<uint64_t>(worst, samples[i].holders);
        }
        std::printf("addr relay      %u withheld addresses reached %llu nodes on average, "
                    "%llu at worst, %llu%% of those via tried\n",
                    static_cast<unsigned>(n), static_cast<unsigned long long>(holders / n),
                    static_cast<unsigned long long>(worst),
                    static_cast<unsigned long long>(holders > 0 ? in_tried * 100 / holders : 0));
    }
    std::printf("attempts        %llu failed, %llu refused as duplicates, %llu turned away\n",
                static_cast<unsigned long long>(net.FailedAttempts()),
                static_cast<unsigned long long>(net.RejectedAttempts()),
                static_cast<unsigned long long>(net.InboundRefusals()));
    std::printf("traffic         %llu bytes\n", static_cast<unsigned long long>(net.BytesTransferred()));
    std::printf("memory          %llu KiB for the simulation, %llu bytes per node, %llu KiB peak\n",
                static_cast<unsigned long long>(sim_bytes / 1024),
                static_cast<unsigned long long>(args.nodes > 0 ? sim_bytes / args.nodes : 0),
                static_cast<unsigned long long>(peak / 1024));
    return EXIT_SUCCESS;
}
