// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/license_info.h>
#include <common/system.h>
#include <compat/compat.h>
#include <crypto/hex_base.h>
#include <interfaces/echo.h>
#include <interfaces/handler.h>
#include <interfaces/init.h>
#include <interfaces/ipc.h>
#include <interfaces/tracing.h>
#include <logging.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/signalinterrupt.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <util/translation.h>

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

static const char* const HELP_USAGE{R"(
bitcoin-trace subscribes to P2P message trace events of a bitcoin-node process via IPC.

Usage:
  bitcoin-trace [options]
)"};

static const char* HELP_EXAMPLES{R"(
Examples:
  # Start separate bitcoin-node that bitcoin-trace can connect to.
  bitcoin-node -regtest -ipcbind=unix

  # Print every message event as text.
  bitcoin-trace -regtest

  # Print every message event as one JSON object per line, including up to 32 payload bytes.
  bitcoin-trace -regtest -json -payload=32

  # Print per-second statistics for 60 seconds, then a JSON summary.
  bitcoin-trace -regtest -stats -duration=60
)"};

const TranslateFn G_TRANSLATION_FUN{nullptr};

static std::optional<util::SignalInterrupt> g_shutdown;

static void HandleSignal(int)
{
    // Return value is intentionally ignored because there is not a better way
    // of handling this failure in a signal handler.
    (void)(*Assert(g_shutdown))();
}

static void AddArgs(ArgsManager& args)
{
    SetupHelpOptions(args);
    SetupChainParamsBaseOptions(args);
    args.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-datadir=<dir>", "Specify data directory", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-ipcconnect=<address>", "Connect to bitcoin-node process. Valid <address> values are 'unix' to connect to the default socket, 'unix:<socket path>' to connect to a socket at a nonstandard path. Default value: unix", ArgsManager::ALLOW_ANY, OptionsCategory::IPC);
    args.AddArg("-inbound", "Receive inbound message events (default: 1)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-outbound", "Receive outbound message events (default: 1)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-payload=<n>", "Receive up to <n> bytes of each message payload (default: 0)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-queue=<n>", "Maximum number of events buffered in the node before events are dropped (default: 65536)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-batch=<n>", "Maximum number of events delivered per IPC call (default: 1024)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-queuebytes=<n>", "Maximum payload bytes buffered in the node before events are dropped (default: 67108864)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-batchbytes=<n>", "Stop filling a batch once its payload bytes reach <n> (default: 4194304)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-batchwait=<us>", "Let the node wait up to <us> microseconds for a batch to fill before delivering it (default: 1000)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-stats", "Print per-second statistics instead of individual events (default: 0)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-json", "Print events and statistics as JSON lines (default: 0)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-duration=<seconds>", "Exit after <seconds>, or on SIGINT/SIGTERM if 0 (default: 0)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-out=<file>", "Write the JSON summary to <file> on exit instead of stdout", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-debug=<category>", "Output debug log information (default: 0). Use -debug=ipc to log IPC requests and responses, or -debug=1 for all categories", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    args.AddArg("-debuglogfile=<file>", "Write the debug log to <file> (default: none, only the console is used). Relative paths will be prefixed by a net-specific datadir location", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    args.AddArg("-printtoconsole", "Send trace/debug info to console (default: 1 when -debug is set, 0 otherwise)", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
}

namespace {

int64_t NowUs()
{
    return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

struct Counters {
    uint64_t events{0};
    uint64_t events_in{0};
    uint64_t events_out{0};
    uint64_t bytes{0};
    uint64_t ping_in{0};
    uint64_t pong_out{0};
    uint64_t dropped{0};
    uint64_t batches{0};
    uint64_t lat_sum_us{0};
    uint64_t lat_max_us{0};

    void Add(const Counters& o)
    {
        events += o.events;
        events_in += o.events_in;
        events_out += o.events_out;
        bytes += o.bytes;
        ping_in += o.ping_in;
        pong_out += o.pong_out;
        dropped += o.dropped;
        batches += o.batches;
        lat_sum_us += o.lat_sum_us;
        lat_max_us = std::max(lat_max_us, o.lat_max_us);
    }

    UniValue ToJson(double seconds) const
    {
        UniValue o{UniValue::VOBJ};
        o.pushKV("events", events);
        o.pushKV("events_in", events_in);
        o.pushKV("events_out", events_out);
        o.pushKV("ping_in", ping_in);
        o.pushKV("pong_out", pong_out);
        o.pushKV("bytes", bytes);
        o.pushKV("dropped", dropped);
        o.pushKV("batches", batches);
        o.pushKV("duration_s", seconds);
        o.pushKV("events_per_s", seconds > 0 ? events / seconds : 0.0);
        UniValue lat{UniValue::VOBJ};
        lat.pushKV("mean", events > 0 ? static_cast<double>(lat_sum_us) / events : 0.0);
        lat.pushKV("max", lat_max_us);
        o.pushKV("latency_us", std::move(lat));
        return o;
    }
};

class TraceCallback : public interfaces::NetMessageTrace
{
public:
    TraceCallback(bool print_events, bool json) : m_print_events{print_events}, m_json{json} {}

    void messages(const std::vector<interfaces::NetMessageInfo>& messages, uint64_t dropped) override
    {
        const int64_t now_us{NowUs()};
        Counters c;
        c.batches = 1;
        c.dropped = dropped;
        for (const auto& m : messages) {
            ++c.events;
            if (m.inbound) {
                ++c.events_in;
                if (m.msg_type == "ping") ++c.ping_in;
            } else {
                ++c.events_out;
                if (m.msg_type == "pong") ++c.pong_out;
            }
            c.bytes += m.msg_size;
            const uint64_t lat{now_us > m.timestamp_us ? static_cast<uint64_t>(now_us - m.timestamp_us) : 0};
            c.lat_sum_us += lat;
            c.lat_max_us = std::max(c.lat_max_us, lat);
            if (m_print_events) Print(m, lat);
        }
        if (m_print_events && dropped > 0) {
            if (m_json) {
                UniValue o{UniValue::VOBJ};
                o.pushKV("event", "dropped");
                o.pushKV("count", dropped);
                tfm::format(std::cout, "%s\n", o.write());
            } else {
                tfm::format(std::cout, "-- %d events dropped\n", dropped);
            }
        }
        // Flush per batch so consumers reading a pipe see events promptly.
        if (m_print_events) std::cout.flush();
        std::lock_guard lock{m_mutex};
        m_total.Add(c);
        m_interval.Add(c);
    }

    Counters TakeInterval()
    {
        std::lock_guard lock{m_mutex};
        Counters c{m_interval};
        m_interval = Counters{};
        return c;
    }

    Counters Total()
    {
        std::lock_guard lock{m_mutex};
        return m_total;
    }

private:
    void Print(const interfaces::NetMessageInfo& m, uint64_t lat_us)
    {
        if (m_json) {
            UniValue o{UniValue::VOBJ};
            o.pushKV("t", m.timestamp_us);
            o.pushKV("dir", m.inbound ? "in" : "out");
            o.pushKV("peer", m.peer_id);
            o.pushKV("addr", m.peer_addr);
            o.pushKV("conn", m.conn_type);
            o.pushKV("type", m.msg_type);
            o.pushKV("size", m.msg_size);
            o.pushKV("payload", HexStr(m.payload));
            o.pushKV("lat_us", lat_us);
            tfm::format(std::cout, "%s\n", o.write());
        } else {
            tfm::format(std::cout, "%s '%s' msg %s peer %d (%s, %s) with %d bytes%s\n",
                        m.inbound ? "inbound" : "outbound", m.msg_type, m.inbound ? "from" : "to",
                        m.peer_id, m.conn_type, m.peer_addr, m.msg_size,
                        m.payload.empty() ? "" : strprintf(" payload %s", HexStr(m.payload)));
        }
    }

    const bool m_print_events;
    const bool m_json;
    std::mutex m_mutex;
    Counters m_total;
    Counters m_interval;
};

} // namespace

MAIN_FUNCTION
{
    ArgsManager& args = gArgs;
    AddArgs(args);
    std::string error_message;
    if (!args.ParseParameters(argc, argv, error_message)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error_message);
        return EXIT_FAILURE;
    }
    if (!args.ReadConfigFiles(error_message, true)) {
        tfm::format(std::cerr, "Error reading config files: %s\n", error_message);
        return EXIT_FAILURE;
    }
    if (HelpRequested(args) || args.IsArgSet("-version")) {
        std::string output{strprintf("%s bitcoin-trace version", CLIENT_NAME) + " " + FormatFullVersion() + "\n"};
        if (args.IsArgSet("-version")) {
            output += FormatParagraph(LicenseInfo());
        } else {
            output += HELP_USAGE;
            output += args.GetHelpMessage();
            output += HELP_EXAMPLES;
        }
        tfm::format(std::cout, "%s", output);
        return EXIT_SUCCESS;
    }
    if (!CheckDataDirOption(args)) {
        tfm::format(std::cerr, "Error: Specified data directory \"%s\" does not exist.\n", args.GetArg("-datadir", ""));
        return EXIT_FAILURE;
    }
    SelectParams(args.GetChainType());

    // Set up logging. Unlike bitcoin-node, do not log to a file unless
    // -debuglogfile is given explicitly, because the default file would be the
    // node's own debug.log in the shared datadir.
    const bool log_to_file{args.IsArgSet("-debuglogfile") && !args.IsArgNegated("-debuglogfile")};
    LogInstance().m_print_to_file = log_to_file;
    if (log_to_file) LogInstance().m_file_path = AbsPathForConfigVal(args, args.GetPathArg("-debuglogfile"));
    LogInstance().m_print_to_console = args.GetBoolArg("-printtoconsole", args.IsArgSet("-debug"));
    for (const std::string& cat : args.GetArgs("-debug")) {
        if (cat == "0" || cat == "none") continue;
        if (cat == "1" || cat == "all") {
            LogInstance().EnableCategory(BCLog::ALL);
        } else if (!LogInstance().EnableCategory(cat)) {
            tfm::format(std::cerr, "Error: Unsupported logging category -debug=%s\n", cat);
            return EXIT_FAILURE;
        }
    }
    if (!LogInstance().StartLogging()) {
        tfm::format(std::cerr, "Error: Could not open debug log file %s\n", fs::PathToString(LogInstance().m_file_path));
        return EXIT_FAILURE;
    }

    const bool json{args.GetBoolArg("-json", false)};
    const bool stats{args.GetBoolArg("-stats", false)};
    const int64_t duration_s{args.GetIntArg("-duration", 0)};
    interfaces::NetMessageTraceOptions options;
    options.inbound = args.GetBoolArg("-inbound", true);
    options.outbound = args.GetBoolArg("-outbound", true);
    options.max_payload_bytes = static_cast<uint32_t>(std::max<int64_t>(0, args.GetIntArg("-payload", 0)));
    options.max_queue_events = static_cast<uint32_t>(std::max<int64_t>(1, args.GetIntArg("-queue", options.max_queue_events)));
    options.max_batch_events = static_cast<uint32_t>(std::max<int64_t>(1, args.GetIntArg("-batch", options.max_batch_events)));
    options.max_batch_wait_us = static_cast<uint32_t>(std::max<int64_t>(0, args.GetIntArg("-batchwait", options.max_batch_wait_us)));
    options.max_queue_bytes = static_cast<uint64_t>(std::max<int64_t>(1, args.GetIntArg("-queuebytes", options.max_queue_bytes)));
    options.max_batch_bytes = static_cast<uint64_t>(std::max<int64_t>(1, args.GetIntArg("-batchbytes", options.max_batch_bytes)));

    // Connect to bitcoin-node process, or fail and print an error.
    std::unique_ptr<interfaces::Init> local_init{interfaces::MakeBasicInit("bitcoin-trace", argc > 0 ? argv[0] : "")};
    if (!local_init || !local_init->ipc()) {
        tfm::format(std::cerr, "Error: bitcoin-trace was not built with IPC support\n");
        return EXIT_FAILURE;
    }
    std::unique_ptr<interfaces::Init> node_init;
    try {
        std::string address{args.GetArg("-ipcconnect", "unix")};
        node_init = local_init->ipc()->connectAddress(address);
    } catch (const std::exception& e) {
        tfm::format(std::cerr, "Error: %s\n", e.what());
        tfm::format(std::cerr, "Probably bitcoin-node is not running or not listening on a unix socket. Can be started with:\n\n");
        tfm::format(std::cerr, "    bitcoin-node -chain=%s -ipcbind=unix\n", args.GetChainTypeString());
        return EXIT_FAILURE;
    }
    if (!node_init) {
        tfm::format(std::cerr, "Error: could not connect to bitcoin-node\n");
        return EXIT_FAILURE;
    }

    g_shutdown.emplace();
    struct sigaction sa{};
    sa.sa_handler = HandleSignal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    int exit_status{EXIT_SUCCESS};
    {
        // Echo object used as a cheap liveness check of the node connection.
        std::unique_ptr<interfaces::Echo> echo{node_init->makeEcho()};
        std::unique_ptr<interfaces::Tracing> tracing{node_init->makeTracing()};
        if (!echo || !tracing) {
            tfm::format(std::cerr, "Error: bitcoin-node does not provide the tracing interface\n");
            return EXIT_FAILURE;
        }
        auto callback{std::make_unique<TraceCallback>(/*print_events=*/!stats, json)};
        TraceCallback& cb{*callback};
        std::unique_ptr<interfaces::Handler> handler{tracing->traceNetMessages(options, std::move(callback))};
        const auto start{std::chrono::steady_clock::now()};
        if (json) {
            tfm::format(std::cout, "{\"event\":\"ready\"}\n");
        } else {
            tfm::format(std::cout, "Subscribed to net message events of bitcoin-node\n");
        }
        std::cout.flush();

        auto next_tick{start + std::chrono::seconds{1}};
        while (!*g_shutdown) {
            const auto now{std::chrono::steady_clock::now()};
            if (duration_s > 0 && now - start >= std::chrono::seconds{duration_s}) break;
            if (now >= next_tick) {
                next_tick += std::chrono::seconds{1};
                try {
                    echo->echo("");
                } catch (const std::exception& e) {
                    tfm::format(std::cerr, "Error: lost connection to bitcoin-node: %s\n", e.what());
                    exit_status = EXIT_FAILURE;
                    break;
                }
                if (stats) {
                    const Counters c{cb.TakeInterval()};
                    const double elapsed{std::chrono::duration<double>(now - start).count()};
                    if (json) {
                        UniValue o{c.ToJson(1.0)};
                        o.pushKV("event", "stats");
                        o.pushKV("elapsed_s", elapsed);
                        tfm::format(std::cout, "%s\n", o.write());
                    } else {
                        tfm::format(std::cout, "t=%.0fs events=%d (in=%d out=%d) bytes=%d dropped=%d batches=%d lat_mean_us=%.1f lat_max_us=%d\n",
                                    elapsed, c.events, c.events_in, c.events_out, c.bytes, c.dropped, c.batches,
                                    c.events > 0 ? static_cast<double>(c.lat_sum_us) / c.events : 0.0, c.lat_max_us);
                    }
                    std::cout.flush();
                }
            }
            UninterruptibleSleep(std::chrono::milliseconds{20});
        }

        const double elapsed{std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count()};
        UniValue summary{cb.Total().ToJson(elapsed)};
        summary.pushKV("mode", "ipc");
        summary.pushKV("event", "summary");
        summary.pushKV("payload_bytes", options.max_payload_bytes);
        summary.pushKV("queue_events", options.max_queue_events);
        summary.pushKV("batch_events", options.max_batch_events);
        summary.pushKV("batch_wait_us", options.max_batch_wait_us);
        summary.pushKV("queue_bytes", options.max_queue_bytes);
        summary.pushKV("batch_bytes", options.max_batch_bytes);
        const std::string out_path{args.GetArg("-out", "")};
        if (!out_path.empty()) {
            std::ofstream out{fs::PathToString(fs::PathFromString(out_path))};
            out << summary.write() << "\n";
        } else if (json || stats) {
            tfm::format(std::cout, "%s\n", summary.write());
        } else {
            tfm::format(std::cout, "Received %d events (%d dropped) in %.1fs\n", cb.Total().events, cb.Total().dropped, elapsed);
        }
        std::cout.flush();

        // Unsubscribe (if the node is still there), then release the interfaces
        // in reverse order of creation.
        if (exit_status == EXIT_SUCCESS) handler.reset();
    }
    return exit_status;
}
