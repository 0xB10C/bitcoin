// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Per-block (de)serialization benchmark over a real block store.
//!
//! Walks every record in a node's blocks/blk?????.dat files, times
//! `CBlock` deserialization (and optionally serialization) for each block
//! individually, and reports where the time goes: the slowest blocks in
//! absolute terms, the slowest per byte, and how cost per byte develops over
//! the chain. Optionally dumps one CSV row per block for further analysis.
//!
//! The block files are read directly, so this does not need a running node
//! (but the node should not be writing to the directory while it runs). Since
//! v28 block files are XOR-obfuscated with the key in blocks/xor.dat, which is
//! read and applied if it exists. Note that block files also contain stale
//! blocks, so more than one block may be reported for a height.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <common/args.h>
#include <common/system.h>
#include <crypto/sha256.h>
#include <kernel/chainparams.h>
#include <kernel/messagestartchars.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/fs.h>
#include <util/obfuscation.h>
#include <util/strencodings.h>
#include <util/syserror.h>
#include <util/time.h>
#include <util/translation.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {
//! Number of timed repetitions per block; the fastest one is reported.
constexpr int DEFAULT_REPS{3};
//! Minimum block size for the "slowest per byte" ranking, so that the ranking
//! is not dominated by tiny blocks where fixed overhead outweighs the payload.
constexpr int64_t DEFAULT_RANK_MIN_SIZE{100'000};
//! Generous upper bound on the size of a serialized block, used to recognize
//! bogus record headers while resynchronizing on the network magic.
constexpr uint32_t MAX_RECORD_SIZE{8'000'000};
//! Number of rows in the ranking tables.
constexpr size_t DEFAULT_TOP{25};

struct Options {
    fs::path blocksdir;
    MessageStartChars magic{};
    Obfuscation obfuscation; //!< from blocks/xor.dat, a no-op if there is none
    int reps{DEFAULT_REPS};
    bool serialize{false};
    int32_t from_height{-1};
    int32_t to_height{std::numeric_limits<int32_t>::max()};
    uint32_t min_size{0};
    uint32_t rank_min_size{DEFAULT_RANK_MIN_SIZE};
    size_t top{DEFAULT_TOP};
};

struct BlockRecord {
    uint256 hash;
    int32_t height{-1}; //!< from the coinbase (BIP34), -1 if not available
    uint32_t ntime{0};
    uint32_t size{0};
    uint32_t ntx{0};
    uint64_t deser_ns{0};
    uint64_t ser_ns{0}; //!< 0 unless -serialize
    int file{0};
    uint64_t pos{0}; //!< offset of the block data within the file
};

//! Keeps the compiler from optimizing the measured work away.
std::atomic<uint64_t> g_sink{0};

std::atomic<size_t> g_next_file{0};
std::atomic<size_t> g_files_done{0};
std::atomic<uint64_t> g_blocks_seen{0};
std::atomic<uint64_t> g_blocks_timed{0};
std::atomic<uint64_t> g_bytes_read{0};

/**
 * Read the next block record from an open block file, resynchronizing on the
 * network magic. This skips the zero padding that preallocated block files end
 * with, as well as anything else that is not a plausible record header.
 *
 * `offset` is the position in the file that reading continues at, and is kept
 * up to date; it is also the key offset the obfuscation is applied with.
 * Returns false at end of file. `pos_out` is set to the offset of the block
 * data itself (what a FlatFilePos would point at).
 */
bool NextRecord(std::FILE* file, const Options& opts, uint64_t& offset, std::vector<std::byte>& raw, uint64_t& pos_out)
{
    std::array<uint8_t, 4> window{};
    size_t filled{0};
    while (true) {
        const int c{std::fgetc(file)};
        if (c == EOF) return false;
        std::byte byte{static_cast<std::byte>(c)};
        opts.obfuscation(std::span{&byte, 1}, offset++);
        window = {window[1], window[2], window[3], std::to_integer<uint8_t>(byte)};
        if (filled < 4) {
            if (++filled < 4) continue;
        }
        if (window != opts.magic) continue;

        std::array<std::byte, 4> len_buf{};
        if (std::fread(len_buf.data(), 1, len_buf.size(), file) != len_buf.size()) return false;
        opts.obfuscation(len_buf, offset);
        offset += len_buf.size();
        const uint32_t size{std::to_integer<uint32_t>(len_buf[0]) |
                            std::to_integer<uint32_t>(len_buf[1]) << 8 |
                            std::to_integer<uint32_t>(len_buf[2]) << 16 |
                            std::to_integer<uint32_t>(len_buf[3]) << 24};
        // A block is at least a header plus a transaction count.
        if (size < 81 || size > MAX_RECORD_SIZE) {
            filled = 0; // not a record header after all, keep scanning
            continue;
        }
        pos_out = offset;
        raw.resize(size);
        if (std::fread(raw.data(), 1, size, file) != size) return false;
        opts.obfuscation(raw, offset);
        offset += size;
        return true;
    }
}

/**
 * Read the height out of a BIP34 coinbase. Returns -1 if it cannot be read.
 *
 * BIP34 became active on mainnet at height 227931 (March 2013). Before that the
 * coinbase scriptSig has no defined meaning, so don't try to interpret it; the
 * timestamp is used to decide, since the height is what we are looking for.
 */
int32_t CoinbaseHeight(const CMutableTransaction& coinbase, uint32_t ntime)
{
    if (ntime < 1363000000) return -1; // shortly before BIP34 activation
    if (coinbase.vin.empty()) return -1;
    const CScript& script{coinbase.vin[0].scriptSig};
    CScript::const_iterator it{script.begin()};
    opcodetype opcode;
    std::vector<unsigned char> data;
    if (!script.GetOp(it, opcode, data)) return -1;
    if (data.empty() || data.size() > 4) return -1;
    if (data.back() & 0x80) return -1; // negative script number, not a height
    int64_t height{0};
    for (size_t i{0}; i < data.size(); ++i) {
        height |= static_cast<int64_t>(data[i]) << (8 * i);
    }
    if (height <= 0 || height > 100'000'000) return -1;
    return static_cast<int32_t>(height);
}

//! Cheap pass over a block to get its identity, without timing anything: hash,
//! timestamp, transaction count and (if available) height.
bool Identify(std::span<const std::byte> raw, BlockRecord& rec)
{
    try {
        SpanReader reader{raw};
        CBlockHeader header;
        reader >> header;
        rec.hash = header.GetHash();
        rec.ntime = header.nTime;
        rec.ntx = static_cast<uint32_t>(ReadCompactSize(reader));
        if (rec.ntx == 0) return false;
        const CMutableTransaction coinbase{deserialize, TX_WITH_WITNESS, reader};
        rec.height = CoinbaseHeight(coinbase, rec.ntime);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

//! Time `reps` full deserializations of a block, returning the fastest.
uint64_t TimeDeserialize(std::span<const std::byte> raw, int reps, uint64_t& sink)
{
    uint64_t best{std::numeric_limits<uint64_t>::max()};
    for (int i{0}; i < reps; ++i) {
        CBlock block;
        const auto start{std::chrono::steady_clock::now()};
        SpanReader{raw} >> TX_WITH_WITNESS(block);
        const auto stop{std::chrono::steady_clock::now()};
        sink += block.vtx.size();
        best = std::min<uint64_t>(best, std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count());
    }
    return best;
}

//! Time `reps` serializations of an already deserialized block, returning the
//! fastest. The output buffer keeps its capacity between repetitions.
uint64_t TimeSerialize(std::span<const std::byte> raw, int reps, uint64_t& sink)
{
    CBlock block;
    SpanReader{raw} >> TX_WITH_WITNESS(block);
    DataStream stream;
    stream.reserve(raw.size());
    uint64_t best{std::numeric_limits<uint64_t>::max()};
    for (int i{0}; i < reps; ++i) {
        stream.clear();
        const auto start{std::chrono::steady_clock::now()};
        stream << TX_WITH_WITNESS(block);
        const auto stop{std::chrono::steady_clock::now()};
        sink += stream.size();
        best = std::min<uint64_t>(best, std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count());
    }
    return best;
}

void ScanFile(const fs::path& path, int file_number, const Options& opts, std::vector<BlockRecord>& out, uint64_t& sink)
{
    std::FILE* file{fsbridge::fopen(path, "rb")};
    if (!file) {
        tfm::format(std::cerr, "Warning: cannot open %s\n", fs::PathToString(path));
        return;
    }
    std::vector<std::byte> raw;
    uint64_t offset{0};
    uint64_t pos{0};
    while (NextRecord(file, opts, offset, raw, pos)) {
        ++g_blocks_seen;
        g_bytes_read += raw.size();
        BlockRecord rec;
        rec.file = file_number;
        rec.pos = pos;
        rec.size = static_cast<uint32_t>(raw.size());
        if (!Identify(raw, rec)) {
            tfm::format(std::cerr, "Warning: undeserializable record in %s at %d\n", fs::PathToString(path), pos);
            continue;
        }
        if (rec.size < opts.min_size) continue;
        if (rec.height < opts.from_height || rec.height > opts.to_height) continue;
        rec.deser_ns = TimeDeserialize(raw, opts.reps, sink);
        if (opts.serialize) rec.ser_ns = TimeSerialize(raw, opts.reps, sink);
        ++g_blocks_timed;
        out.push_back(rec);
    }
    std::fclose(file);
}

std::vector<fs::path> ListBlockFiles(const fs::path& blocksdir)
{
    std::vector<fs::path> files;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator{blocksdir, ec}) {
        const std::string name{fs::PathToString(entry.path().filename())};
        if (name.size() != 12 || !name.starts_with("blk") || !name.ends_with(".dat")) continue;
        if (!std::all_of(name.begin() + 3, name.begin() + 8, [](char c) { return c >= '0' && c <= '9'; })) continue;
        files.push_back(entry.path());
    }
    if (ec) {
        tfm::format(std::cerr, "Error: cannot list %s: %s\n", fs::PathToString(blocksdir), ec.message());
        return {};
    }
    std::sort(files.begin(), files.end());
    return files;
}

int BlockFileNumber(const fs::path& path)
{
    const std::string name{fs::PathToString(path.filename())};
    return std::atoi(name.substr(3, 5).c_str());
}

/**
 * Read the obfuscation key that block files have been XORed with since v28. A
 * missing xor.dat is not an error: block directories written by older versions
 * or with -blocksxor=0 have none, and the key is then all zeros.
 */
bool ReadObfuscation(const fs::path& blocksdir, Obfuscation& obfuscation)
{
    const fs::path path{blocksdir / "xor.dat"};
    if (!fs::exists(path)) return true;
    AutoFile file{fsbridge::fopen(path, "rb")};
    if (file.IsNull()) {
        tfm::format(std::cerr, "Error: cannot open %s: %s\n", fs::PathToString(path), SysErrorString(errno));
        return false;
    }
    // The key is written without a length indicator, so the file is exactly
    // Obfuscation::KEY_SIZE bytes long. See InitBlocksdirXorKey().
    std::array<std::byte, Obfuscation::KEY_SIZE> key{};
    try {
        file >> key;
    } catch (const std::exception& e) {
        tfm::format(std::cerr, "Error: cannot read %s: %s\n", fs::PathToString(path), e.what());
        return false;
    }
    obfuscation = Obfuscation{key};
    return true;
}

//! Determine the network from the magic the first readable block file starts
//! with, which also verifies that the obfuscation key is the right one.
std::optional<MessageStartChars> DetectMagic(const std::vector<fs::path>& files, const Obfuscation& obfuscation)
{
    for (const auto& path : files) {
        std::FILE* file{fsbridge::fopen(path, "rb")};
        if (!file) {
            tfm::format(std::cerr, "Error: cannot open %s: %s\n", fs::PathToString(path), SysErrorString(errno));
            continue;
        }
        std::array<std::byte, std::tuple_size_v<MessageStartChars>> start{};
        const bool read{std::fread(start.data(), 1, start.size(), file) == start.size()};
        std::fclose(file);
        if (!read) continue;
        obfuscation(start);
        MessageStartChars magic{};
        for (size_t i{0}; i < magic.size(); ++i) magic[i] = std::to_integer<uint8_t>(start[i]);
        if (GetNetworkForMagic(magic)) return magic;
        tfm::format(std::cerr, "Error: %s does not start with a known network magic (found %s)\n",
                    fs::PathToString(path), HexStr(start));
        return std::nullopt;
    }
    return std::nullopt;
}

double NsPerByte(const BlockRecord& rec) { return static_cast<double>(rec.deser_ns) / rec.size; }

void PrintTable(const std::string& title, std::span<const BlockRecord> rows, bool with_serialize)
{
    tfm::format(std::cout, "\n%s\n", title);
    tfm::format(std::cout, "%9s  %10s  %9s  %8s  %7s  %9s  %8s%s  %s\n",
                "height", "date", "size", "txs", "b/tx", "deser ms", "ns/byte",
                with_serialize ? "    ser ms" : "", "hash");
    for (const BlockRecord& rec : rows) {
        tfm::format(std::cout, "%9d  %10s  %9d  %8d  %7d  %9.3f  %8.2f%s  %s\n",
                    rec.height, FormatISO8601Date(rec.ntime), rec.size, rec.ntx,
                    rec.ntx ? rec.size / rec.ntx : 0,
                    rec.deser_ns / 1e6, NsPerByte(rec),
                    with_serialize ? strprintf("  %8.3f", rec.ser_ns / 1e6) : "",
                    rec.hash.ToString());
    }
}

void Report(std::vector<BlockRecord>& records, const Options& opts, double wall_seconds)
{
    if (records.empty()) {
        tfm::format(std::cout, "No blocks measured.\n");
        return;
    }
    std::sort(records.begin(), records.end(), [](const BlockRecord& a, const BlockRecord& b) {
        return std::tie(a.height, a.ntime, a.hash) < std::tie(b.height, b.ntime, b.hash);
    });

    uint64_t total_bytes{0};
    uint64_t total_deser_ns{0};
    uint64_t total_ser_ns{0};
    for (const BlockRecord& rec : records) {
        total_bytes += rec.size;
        total_deser_ns += rec.deser_ns;
        total_ser_ns += rec.ser_ns;
    }

    tfm::format(std::cout, "\nBlocks measured:      %d\n", records.size());
    tfm::format(std::cout, "Total size:           %.2f GiB\n", total_bytes / 1024.0 / 1024.0 / 1024.0);
    tfm::format(std::cout, "Sum of best deser:    %.1f s (%.1f MB/s, %.0f blocks/s, single threaded)\n",
                total_deser_ns / 1e9, total_bytes / (total_deser_ns / 1e9) / 1e6,
                records.size() / (total_deser_ns / 1e9));
    if (opts.serialize) {
        tfm::format(std::cout, "Sum of best ser:      %.1f s (%.1f MB/s, single threaded)\n",
                    total_ser_ns / 1e9, total_bytes / (total_ser_ns / 1e9) / 1e6);
    }
    tfm::format(std::cout, "Wall clock:           %.1f s\n", wall_seconds);

    // Distribution of deserialization cost per byte.
    std::vector<double> per_byte;
    per_byte.reserve(records.size());
    for (const BlockRecord& rec : records) per_byte.push_back(NsPerByte(rec));
    std::sort(per_byte.begin(), per_byte.end());
    const auto quantile{[&](double q) { return per_byte[std::min<size_t>(per_byte.size() - 1, q * per_byte.size())]; }};
    tfm::format(std::cout, "\nDeserialization ns/byte: p50 %.2f  p90 %.2f  p99 %.2f  max %.2f\n",
                quantile(0.5), quantile(0.9), quantile(0.99), per_byte.back());

    // Slowest blocks in absolute terms: what a single block costs.
    std::vector<BlockRecord> by_total{records};
    std::partial_sort(by_total.begin(), by_total.begin() + std::min(opts.top, by_total.size()), by_total.end(),
                      [](const BlockRecord& a, const BlockRecord& b) { return a.deser_ns > b.deser_ns; });
    by_total.resize(std::min(opts.top, by_total.size()));
    PrintTable("Slowest blocks by total deserialization time:", by_total, opts.serialize);

    // Slowest blocks per byte: blocks that are expensive for their size.
    std::vector<BlockRecord> by_rate;
    for (const BlockRecord& rec : records) {
        if (rec.size >= opts.rank_min_size) by_rate.push_back(rec);
    }
    std::partial_sort(by_rate.begin(), by_rate.begin() + std::min(opts.top, by_rate.size()), by_rate.end(),
                      [](const BlockRecord& a, const BlockRecord& b) { return NsPerByte(a) > NsPerByte(b); });
    by_rate.resize(std::min(opts.top, by_rate.size()));
    PrintTable(strprintf("Slowest blocks per byte (size >= %d bytes):", opts.rank_min_size), by_rate, opts.serialize);

    // Development over the chain, so it is visible whether recent blocks are
    // getting cheaper or more expensive to deserialize.
    struct Bucket {
        size_t blocks{0};
        uint64_t bytes{0};
        uint64_t deser_ns{0};
        const BlockRecord* worst{nullptr};
    };
    std::map<std::string, Bucket> months;
    for (const BlockRecord& rec : records) {
        Bucket& bucket{months[FormatISO8601Date(rec.ntime).substr(0, 7)]};
        ++bucket.blocks;
        bucket.bytes += rec.size;
        bucket.deser_ns += rec.deser_ns;
        if (!bucket.worst || NsPerByte(rec) > NsPerByte(*bucket.worst)) bucket.worst = &rec;
    }
    tfm::format(std::cout, "\nPer month:\n%7s  %7s  %9s  %11s  %11s  %9s  %s\n",
                "month", "blocks", "MiB", "mean ns/B", "worst ns/B", "worst ms", "worst block");
    for (const auto& [month, bucket] : months) {
        tfm::format(std::cout, "%7s  %7d  %9.1f  %11.2f  %11.2f  %9.3f  %s\n",
                    month, bucket.blocks, bucket.bytes / 1024.0 / 1024.0,
                    static_cast<double>(bucket.deser_ns) / bucket.bytes,
                    NsPerByte(*bucket.worst), bucket.worst->deser_ns / 1e6,
                    bucket.worst->hash.ToString());
    }
}

bool WriteCsv(const fs::path& path, const std::vector<BlockRecord>& records)
{
    std::ofstream out{path.std_path()};
    if (!out.good()) {
        tfm::format(std::cerr, "Error: cannot write %s\n", fs::PathToString(path));
        return false;
    }
    tfm::format(out, "height,hash,time,date,size,ntx,deser_ns,ser_ns,deser_ns_per_byte,deser_ns_per_tx,file,pos\n");
    for (const BlockRecord& rec : records) {
        tfm::format(out, "%d,%s,%d,%s,%d,%d,%d,%d,%.4f,%.1f,%d,%d\n",
                    rec.height, rec.hash.ToString(), rec.ntime, FormatISO8601DateTime(rec.ntime),
                    rec.size, rec.ntx, rec.deser_ns, rec.ser_ns,
                    NsPerByte(rec), rec.ntx ? static_cast<double>(rec.deser_ns) / rec.ntx : 0.0,
                    rec.file, rec.pos);
    }

    return true;
}

void SetupArgs(ArgsManager& args)
{
    SetupHelpOptions(args);
    args.AddArg("-blocksdir=<dir>", "Directory holding the blk?????.dat files (default: ~/.bitcoin/blocks)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-par=<n>", "Number of block files to process in parallel (default: number of cores). Use -par=1 for the lowest-noise timings.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-reps=<n>", strprintf("Timed repetitions per block, fastest is reported (default: %d)", DEFAULT_REPS), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-serialize", "Also measure serializing each block back out (default: no)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-csv=<file>", "Write one row per block to this file", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-fromheight=<n>", "Skip blocks below this height (default: no limit)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-toheight=<n>", "Skip blocks above this height (default: no limit)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-minsize=<n>", "Skip blocks smaller than this many bytes (default: 0)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-startfile=<n>", "First blk?????.dat file to read (default: 0)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-endfile=<n>", "Last blk?????.dat file to read (default: no limit)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-ranksize=<n>", strprintf("Minimum block size for the per-byte ranking (default: %d)", DEFAULT_RANK_MIN_SIZE), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-top=<n>", strprintf("Rows per ranking table (default: %d)", DEFAULT_TOP), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
}
} // namespace

int main(int argc, char* argv[])
{
    SetupEnvironment();
    SHA256AutoDetect(); // transaction ids are computed while deserializing

    ArgsManager args;
    SetupArgs(args);
    std::string error;
    if (!args.ParseParameters(argc, argv, error)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error);
        return EXIT_FAILURE;
    }
    if (HelpRequested(args)) {
        tfm::format(std::cout,
                    "Measures CBlock deserialization for every block in a node's block files.\n"
                    "\n"
                    "Usage: bench_blocks [options]\n"
                    "\n%s",
                    args.GetHelpMessage());
        return EXIT_SUCCESS;
    }

    Options opts;
    opts.blocksdir = args.GetPathArg("-blocksdir", fs::PathFromString("~/.bitcoin/blocks"));
    if (fs::PathToString(opts.blocksdir).starts_with("~/")) {
        const char* home{std::getenv("HOME")};
        if (home) opts.blocksdir = fs::PathFromString(home) / fs::PathFromString(fs::PathToString(opts.blocksdir).substr(2));
    }
    opts.reps = std::max<int>(1, args.GetIntArg("-reps", DEFAULT_REPS));
    opts.serialize = args.GetBoolArg("-serialize", false);
    opts.from_height = args.GetIntArg("-fromheight", -1);
    opts.to_height = args.GetIntArg("-toheight", std::numeric_limits<int32_t>::max());
    opts.min_size = args.GetIntArg("-minsize", 0);
    opts.rank_min_size = args.GetIntArg("-ranksize", DEFAULT_RANK_MIN_SIZE);
    opts.top = args.GetIntArg("-top", DEFAULT_TOP);
    const int start_file{static_cast<int>(args.GetIntArg("-startfile", 0))};
    const int end_file{static_cast<int>(args.GetIntArg("-endfile", std::numeric_limits<int32_t>::max()))};
    const size_t par{std::max<size_t>(1, args.GetIntArg("-par", std::max(1u, std::thread::hardware_concurrency())))};

    std::vector<fs::path> files;
    for (const fs::path& path : ListBlockFiles(opts.blocksdir)) {
        const int number{BlockFileNumber(path)};
        if (number >= start_file && number <= end_file) files.push_back(path);
    }
    if (files.empty()) {
        tfm::format(std::cerr, "Error: no blk?????.dat files found in %s\n", fs::PathToString(opts.blocksdir));
        return EXIT_FAILURE;
    }
    if (!ReadObfuscation(opts.blocksdir, opts.obfuscation)) return EXIT_FAILURE;
    const auto magic{DetectMagic(files, opts.obfuscation)};
    if (!magic) {
        tfm::format(std::cerr, "Error: %s does not look like a block directory of a %s node%s\n",
                    fs::PathToString(opts.blocksdir), CLIENT_NAME,
                    opts.obfuscation ? "" : " (no xor.dat found: for a v28 or later directory it must be present and readable)");
        return EXIT_FAILURE;
    }
    opts.magic = *magic;

    tfm::format(std::cout, "Chain:                %s\n", ChainTypeToString(*GetNetworkForMagic(opts.magic)));
    tfm::format(std::cout, "Obfuscation key:      %s\n", opts.obfuscation ? opts.obfuscation.HexKey() : "none");
    tfm::format(std::cout, "Block files:          %d (%s .. %s)\n", files.size(),
                fs::PathToString(files.front().filename()), fs::PathToString(files.back().filename()));
    tfm::format(std::cout, "Threads:              %d\n", par);
    tfm::format(std::cout, "Repetitions:          %d (fastest reported)\n", opts.reps);

    const auto started{std::chrono::steady_clock::now()};
    std::vector<std::vector<BlockRecord>> per_thread(par);
    std::vector<std::thread> threads;
    for (size_t i{0}; i < par; ++i) {
        threads.emplace_back([&, i] {
            uint64_t sink{0};
            while (true) {
                const size_t index{g_next_file++};
                if (index >= files.size()) break;
                ScanFile(files[index], BlockFileNumber(files[index]), opts, per_thread[i], sink);
                ++g_files_done;
            }
            g_sink += sink;
        });
    }

    // Progress, because a full mainnet scan reads hundreds of gigabytes.
    for (int tick{0}; g_files_done < files.size(); ++tick) {
        std::this_thread::sleep_for(std::chrono::milliseconds{200});
        if (tick % 10 != 0) continue;
        const double elapsed{std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count()};
        tfm::format(std::cerr, "\r%d/%d files, %d blocks (%d timed), %.1f GiB read, %.0f s   ",
                    g_files_done.load(), files.size(), g_blocks_seen.load(), g_blocks_timed.load(),
                    g_bytes_read.load() / 1024.0 / 1024.0 / 1024.0, elapsed);
    }
    for (std::thread& thread : threads) thread.join();
    tfm::format(std::cerr, "\r%120s\r", "");
    const double wall{std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count()};

    std::vector<BlockRecord> records;
    for (const auto& part : per_thread) records.insert(records.end(), part.begin(), part.end());
    Report(records, opts, wall);

    const fs::path csv{args.GetPathArg("-csv")};
    if (!csv.empty()) {
        if (!WriteCsv(csv, records)) return EXIT_FAILURE;
        tfm::format(std::cout, "\nWrote %d rows to %s\n", records.size(), fs::PathToString(csv));
    }
    return EXIT_SUCCESS;
}
