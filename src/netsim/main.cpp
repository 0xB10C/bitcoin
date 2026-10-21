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
#include <netsim/setup.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/fs.h>

#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <functional>
#include <limits>
#include <map>
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
    bool per_node_chain{false};
    std::string block_csv;
    uint32_t block_bytes{0};
    uint32_t bandwidth_mbit{0};
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
                 "  --mine           mine blocks as a Poisson process, one every\n"
                 "                   --block-sec of simulated time on average\n"
                 "  --block-sec=N    mean simulated seconds between blocks (default 600)\n"
                 "  --blockrelay     give every node its own chainstate, so a block has to\n"
                 "                   travel: announce, getdata, block, validate, announce\n"
                 "                   on. Costs 123 KB per node; implies --mine and --chain\n"
                 "  --block-csv=FILE write one row per (block, node) arrival there\n"
                 "  --block-bytes=N  pad each block to about N serialised bytes, so that\n"
                 "                   transfer time counts (ceiling ~1000000, see chain.h)\n"
                 "  --bandwidth-mbit=N  per-link bandwidth, which is what turns block size\n"
                 "                   into transfer time. Zero, the default, is unlimited\n");
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
        } else if (arg == "--blockrelay") {
            args.per_node_chain = true;
            args.mine = true;
            if (args.chain == 0) args.chain = 10;
        } else if (arg.starts_with("--block-csv=") && arg.size() > 12) {
            args.block_csv = std::string{arg.substr(12)};
        } else if (arg.starts_with("--block-bytes=") && ParseUint(arg.substr(14), value)) {
            args.block_bytes = value;
        } else if (arg.starts_with("--bandwidth-mbit=") && ParseUint(arg.substr(17), value)) {
            args.bandwidth_mbit = value;
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

/** The machine-readable columns, in order.
 *
 * `CsvValues` returns an array sized from this, so a column added to one and
 * not the other is a compile error rather than a silently shifted CSV.
 */
constexpr std::array CSV_COLUMNS{
    "nodes", "listeners", "blocks_only", "minutes", "links", "outbound",
    "saturated", "isolated", "addrman_total", "known_strangers", "failed",
    "rejected", "refused", "bytes", "rss_before_kb", "rss_after_kb", "sim_kb",
    "bytes_per_node", "peak_kb",
};

/** Whole-population aggregates, counted once and reported twice. */
struct Totals {
    uint64_t outbound{0};
    uint64_t saturated{0};
    uint64_t isolated{0};
    uint64_t addrman{0};
    /** Addresses held that name no listening node. Should be zero. */
    uint64_t unreachable{0};
};

Totals CountTotals(const netsim::Network& net)
{
    Totals totals;
    for (uint32_t id{0}; id < net.NumNodes(); ++id) {
        const int outbound{net.At(id).connman->GetFullOutboundConnCount()};
        totals.outbound += static_cast<uint64_t>(outbound);
        if (outbound >= MAX_OUTBOUND_FULL_RELAY_CONNECTIONS) ++totals.saturated;
        if (outbound == 0) ++totals.isolated;
        for (const CAddress& addr : net.At(id).addrman->GetAddr(0, 0, std::nullopt, /*filtered=*/false)) {
            ++totals.addrman;
            if (!net.ListenerAt(addr).has_value()) ++totals.unreachable;
        }
    }
    return totals;
}

/** Resident set either side of the population existing. */
struct Memory {
    uint64_t before{0};
    uint64_t after{0};
    uint64_t peak{0};

    uint64_t Simulation() const { return after > before ? after - before : 0; }
    uint64_t PerNode(uint32_t nodes) const { return nodes > 0 ? Simulation() / nodes : 0; }
};

std::array<uint64_t, CSV_COLUMNS.size()> CsvValues(const Args& args, const netsim::Network& net,
                                                   const Totals& totals, const Memory& mem)
{
    return {args.nodes,
            args.listeners,
            args.blocks_only ? 1u : 0u,
            args.minutes,
            net.TotalOpened(),
            totals.outbound,
            totals.saturated,
            totals.isolated,
            totals.addrman,
            totals.unreachable,
            net.FailedAttempts(),
            net.RejectedAttempts(),
            net.InboundRefusals(),
            net.BytesTransferred(),
            mem.before / 1024,
            mem.after / 1024,
            mem.Simulation() / 1024,
            mem.PerNode(args.nodes),
            mem.peak / 1024};
}

/** How long each mined block took to reach a given share of the population. */
struct Propagation {
    int height{0};
    uint32_t reached{0};
    int64_t p50_us{0};
    int64_t p90_us{0};
    int64_t last_us{0};
};

/** One row per block that had to travel, in height order.
 *
 * The arrival list is already in time order, so for each block the kth
 * arrival is the kth node to adopt it and the percentiles are just offsets
 * into that run of rows. Timed from the first arrival, which is the miner's
 * own, rather than from the start of the run.
 */
std::vector<Propagation> SummarisePropagation(const netsim::Network& net)
{
    std::map<int, std::vector<int64_t>> by_height;
    std::map<int, int64_t> first_seen;
    for (const auto& arrival : net.BlockArrivals()) {
        const int64_t us{arrival.at.count()};
        auto [it, fresh] = first_seen.try_emplace(arrival.height, us);
        by_height[arrival.height].push_back(us - it->second);
    }

    std::vector<Propagation> out;
    out.reserve(by_height.size());
    for (auto& [height, offsets] : by_height) {
        // Already ascending, since the arrivals were appended in time order.
        const size_t n{offsets.size()};
        Propagation p;
        p.height = height;
        p.reached = static_cast<uint32_t>(n);
        p.p50_us = offsets[(n - 1) / 2];
        p.p90_us = offsets[(n * 9 - 1) / 10];
        p.last_us = offsets.back();
        out.push_back(p);
    }
    return out;
}

/** How far the withheld addresses got, as the last sample of each. */
struct Coverage {
    size_t tracked{0};
    uint64_t mean{0};
    uint64_t worst{0};
    uint64_t tried_percent{0};
};

Coverage SummariseCoverage(const netsim::Network& net)
{
    const auto& samples{net.AddrSamples()};
    Coverage out;
    out.tracked = net.TrackedNodes().size();
    if (out.tracked == 0 || samples.size() < out.tracked) return out;

    uint64_t holders{0}, in_tried{0};
    out.worst = std::numeric_limits<uint64_t>::max();
    for (size_t i{samples.size() - out.tracked}; i < samples.size(); ++i) {
        holders += samples[i].holders;
        in_tried += samples[i].in_tried;
        out.worst = std::min<uint64_t>(out.worst, samples[i].holders);
    }
    out.mean = holders / out.tracked;
    out.tried_percent = holders > 0 ? in_tried * 100 / holders : 0;
    return out;
}

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
        for (size_t i{0}; i < CSV_COLUMNS.size(); ++i) {
            std::printf("%s%s", i == 0 ? "" : ",", CSV_COLUMNS[i]);
        }
        std::printf("\n");
        return EXIT_SUCCESS;
    }

    auto context{MakeNoLogFileContext<TestingSetup>(ChainType::REGTEST, netsim::SimTestOpts())};

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
    // Always: a node needs these only to build its own chain, and whether it
    // does is decided per run, but they cost nothing to hand over.
    shared.kernel_notifications = context->m_node.notifications.get();
    shared.interrupt = context->m_node.shutdown_signal;
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
    if (args.chain > 0) {
        netsim::Chain::Options chain_opts;
        chain_opts.initial_blocks = args.chain;
        chain_opts.spacing = std::chrono::seconds{args.block_sec};
        chain_opts.rng_seed = uint256{args.seed};
        netsim::Chain{*context->m_node.chainman, context->m_node.block_template_manager.get(),
                      context->m_node.validation_signals.get(), chain_opts}
            .Prefill(
            std::chrono::duration_cast<std::chrono::seconds>(netsim::Network::Options{}.start));
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
    opts.per_node_chain = args.per_node_chain;
    opts.chain.target_block_bytes = args.block_bytes;
    // Megabits per second to bytes per second.
    opts.latency.bandwidth_bytes_per_second = uint64_t{args.bandwidth_mbit} * 1000000 / 8;
    // Under the datadir TestingSetup already made, so it is cleaned up with it.
    opts.datadir = context->m_args.GetDataDirNet() / "netsim-chains";

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
    if (!args.block_csv.empty()) {
        if (!netsim::WriteBlockArrivals(net, fs::PathFromString(args.block_csv))) {
            std::fprintf(stderr, "failed to write the block arrivals to %s\n", args.block_csv.c_str());
            return EXIT_FAILURE;
        }
    }
    if (!args.addr_csv.empty()) {
        if (!netsim::WriteAddrSamples(net, fs::PathFromString(args.addr_csv))) {
            std::fprintf(stderr, "failed to write the coverage samples to %s\n", args.addr_csv.c_str());
            return EXIT_FAILURE;
        }
    }

    const Memory mem{.before = rss_before,
                     .after = netsim::ResidentSetBytes().value_or(0),
                     .peak = netsim::PeakResidentSetBytes().value_or(0)};
    const Totals totals{CountTotals(net)};

    if (args.csv) {
        const auto values{CsvValues(args, net, totals, mem)};
        for (size_t i{0}; i < values.size(); ++i) {
            std::printf("%s%llu", i == 0 ? "" : ",", static_cast<unsigned long long>(values[i]));
        }
        std::printf("\n");
        return EXIT_SUCCESS;
    }

    // One labelled line per topic. `line` keeps the label column aligned in
    // one place instead of in every format string.
    const auto line{[](const char* label, const char* fmt, auto... values) {
        std::printf("%-15s ", label);
        std::printf(fmt, values...);
        std::printf("\n");
    }};
    const auto u64{[](uint64_t v) { return static_cast<unsigned long long>(v); }};

    line("population", "%u nodes, %u listening%s", args.nodes, args.listeners,
         args.blocks_only ? ", blocks-only" : "");
    {
        using Net = netsim::AddressUniverse::Net;
        const auto& universe{net.Addresses()};
        line("addresses", "%u ipv4, %u ipv6, %u onion, %u i2p, in %u netgroups",
             universe.CountOn(Net::IPv4), universe.CountOn(Net::IPv6),
             universe.CountOn(Net::Onion), universe.CountOn(Net::I2P), net.NumNetgroups());
    }
    line("simulated", "%u minutes", args.minutes);
    if (args.chain > 0 || args.mine) {
        line("chain", "height %d, %llu blocks mined during the run",
             net.ChainHeight(), u64(net.GetChain().Mined()));
    }
    line("connections", "%llu opened, %llu still up, %llu saturated, %llu isolated",
         u64(net.TotalOpened()), u64(net.LiveLinks()), u64(totals.saturated), u64(totals.isolated));
    line("link slots", "%zu peak concurrent, %llu closed and recycled",
         net.LinkSlots(), u64(net.ClosedLinks()));
    line("addrman", "%llu held, %llu of them unreachable",
         u64(totals.addrman), u64(totals.unreachable));
    if (const Coverage cov{SummariseCoverage(net)}; cov.tracked > 0) {
        line("addr relay", "%zu withheld addresses reached %llu nodes on average, "
                           "%llu at worst, %llu%% of those via tried",
             cov.tracked, u64(cov.mean), u64(cov.worst), u64(cov.tried_percent));
    }
    for (const Propagation& p : SummarisePropagation(net)) {
        line("block propagation", "height %d reached %u nodes: 50%% in %lld ms, "
                                  "90%% in %lld ms, last at %lld ms",
             p.height, p.reached, static_cast<long long>(p.p50_us / 1000),
             static_cast<long long>(p.p90_us / 1000), static_cast<long long>(p.last_us / 1000));
    }
    line("attempts", "%llu failed, %llu refused as duplicates, %llu turned away",
         u64(net.FailedAttempts()), u64(net.RejectedAttempts()), u64(net.InboundRefusals()));
    line("traffic", "%llu bytes", u64(net.BytesTransferred()));
    line("memory", "%llu KiB for the simulation, %llu bytes per node, %llu KiB peak",
         u64(mem.Simulation() / 1024), u64(mem.PerNode(args.nodes)), u64(mem.peak / 1024));
    return EXIT_SUCCESS;
}
