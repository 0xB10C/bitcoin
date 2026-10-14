// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/util/cost.h>

#include <logging.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#endif

#if defined(__SANITIZE_ADDRESS__)
#define FUZZ_COST_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define FUZZ_COST_ASAN 1
#endif
#endif

// The allocator counters are only built when the meter is on and no sanitizer
// owns the allocator already.
#if defined(FUZZ_COST) && !defined(FUZZ_COST_ASAN) && defined(__GLIBC__)
#define FUZZ_COST_MALLOC_HOOKS 1
#include <malloc.h>
#endif

namespace fuzz_cost {
namespace {

constexpr size_t N_LABELS_MAX{64};
constexpr size_t N_LEVELS{16};

// ---------------------------------------------------------------- counters --
// Relaxed atomics: the measured block is usually single threaded, but
// validation may hand work to other threads and we want that work counted.
std::atomic<uint64_t> g_alloc_bytes{0};
std::atomic<uint64_t> g_alloc_count{0};
std::atomic<uint64_t> g_alloc_max{0};
std::atomic<int64_t> g_live{0};
std::atomic<int64_t> g_peak{0};
std::atomic<uint64_t> g_log_bytes{0};

inline void NoteAlloc(size_t requested, size_t usable)
{
    g_alloc_bytes.fetch_add(requested, std::memory_order_relaxed);
    g_alloc_count.fetch_add(1, std::memory_order_relaxed);
    if (requested > g_alloc_max.load(std::memory_order_relaxed)) {
        g_alloc_max.store(requested, std::memory_order_relaxed);
    }
    const int64_t live{g_live.fetch_add(int64_t(usable), std::memory_order_relaxed) + int64_t(usable)};
    if (live > g_peak.load(std::memory_order_relaxed)) {
        g_peak.store(live, std::memory_order_relaxed);
    }
}

inline void NoteFree(size_t usable)
{
    g_live.fetch_sub(int64_t(usable), std::memory_order_relaxed);
}

// -------------------------------------------------------------------- time --
inline uint64_t ReadTicks()
{
#if defined(__x86_64__) || defined(__i386__)
    unsigned aux;
    return __rdtscp(&aux);
#elif defined(__aarch64__)
    uint64_t v;
    asm volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
#else
    return uint64_t(std::chrono::steady_clock::now().time_since_epoch().count());
#endif
}

double g_ns_per_tick{1.0};

//! Read the process-wide rchar/wchar counters (bytes passed to read()/write()
//! syscalls, cached or not). ~1-2 us per read: fine for triage and replay, and
//! cheap enough to take every input here. Returns false if /proc is unavailable
//! (e.g. a non-Linux host), in which case the disk measures stay zero.
bool ReadProcIo(uint64_t& rchar, uint64_t& wchar)
{
    FILE* f{std::fopen("/proc/self/io", "rb")};
    if (!f) return false;
    char line[128];
    bool got_r{false}, got_w{false};
    while (std::fgets(line, sizeof line, f)) {
        if (std::sscanf(line, "rchar: %" SCNu64, &rchar) == 1) got_r = true;
        else if (std::sscanf(line, "wchar: %" SCNu64, &wchar) == 1) got_w = true;
    }
    std::fclose(f);
    return got_r && got_w;
}

void CalibrateTicks()
{
    using clock = std::chrono::steady_clock;
    const auto t0{clock::now()};
    const uint64_t c0{ReadTicks()};
    // Busy wait rather than sleep: short, and keeps the thread on one core.
    while (clock::now() - t0 < std::chrono::milliseconds(20)) {
    }
    const uint64_t c1{ReadTicks()};
    const auto t1{clock::now()};
    const auto ns{std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count()};
    if (c1 > c0 && ns > 0) g_ns_per_tick = double(ns) / double(c1 - c0);
}

// ------------------------------------------------------------------- state --
bool g_enabled{false};
std::vector<std::string> g_labels;

enum Kind : uint8_t { ABS, RATIO, N_KINDS };

struct MaxRecord {
    double value{0};
    uint64_t bytes_in{0};
    uint64_t raw{0};
};
MaxRecord g_max[N_LABELS_MAX][N_MEASURES][N_KINDS];

uint64_t g_seen[N_LABELS_MAX]{};
//! Measurements from the first few inputs of a label pay one-time costs (lazy
//! init, first-touch page faults), so they are guided on but never recorded.
constexpr uint64_t WARMUP_INPUTS{8};
//! A candidate timing maximum is re-run this many times and the minimum kept.
constexpr unsigned MAX_RUNS{5};
//! ... unless one run already took this long, where the noise does not matter
//! and the repeats would just burn the campaign's time budget.
constexpr uint64_t NO_REPEAT_ABOVE_NS{20'000'000};

std::string g_maxdir;
std::string g_logpath;
bool g_measure_mode{false};
//! Control for the A/B that tests whether cost guidance actually helps.
bool g_no_guide{false};
//! In measure mode, run repeatable work this many times and keep the fastest.
unsigned g_measure_repeat{1};
uint64_t g_inputs{0};
//! Depth of live Trials. Only the outermost one measures, so a generic
//! whole-target scope and a hand-placed inner scope never double count.
unsigned g_depth{0};

#ifdef FUZZ_COST
// libFuzzer treats every byte in this section as extra coverage: setting a byte
// no earlier input set makes the input "interesting" and keeps it in the corpus.
__attribute__((section("__libfuzzer_extra_counters"), used)) uint8_t
    g_cost_levels[N_LABELS_MAX][N_MEASURES][N_KINDS][N_LEVELS];
#endif

// log2 of the value at which level 1 starts, per measure.
constexpr int ABS_FLOOR_LOG2[N_MEASURES]{8, 10, 0, 10, 10, 10, 0, 0, 10, 10};
// Same, for (value * 256 / bytes_in).
constexpr int RATIO_FLOOR_LOG2[N_MEASURES]{4, 7, 0, 7, 7, 7, 0, 0, 7, 7};
// Below this a maximum is not worth saving.
constexpr uint64_t ABS_MIN[N_MEASURES]{2000, 4096, 16, 4096, 4096, 1024, 1, 1, 4096, 4096};

size_t LevelOf(uint64_t scaled, int floor_log2)
{
    if (scaled == 0) return 0;
    const int l{63 - __builtin_clzll(scaled) - floor_log2};
    if (l <= 0) return 0;
    return size_t(std::min(l, int(N_LEVELS) - 1));
}

void WriteInput(const std::string& path, std::span<const uint8_t> input)
{
    FILE* f{std::fopen(path.c_str(), "wb")};
    if (!f) return;
    if (!input.empty()) std::fwrite(input.data(), 1, input.size(), f);
    std::fclose(f);
}

void AppendLine(const std::string& line)
{
    if (g_logpath.empty()) {
        std::fputs(line.c_str(), stderr);
        return;
    }
    FILE* f{std::fopen(g_logpath.c_str(), "ab")};
    if (!f) return;
    std::fputs(line.c_str(), f);
    std::fclose(f);
}

void PrintSummary()
{
    if (!g_enabled) return;
    std::string out{"\n=== fuzz_cost summary (" + std::to_string(g_inputs) + " inputs) ===\n"};
    char buf[512];
    for (size_t li = 0; li < g_labels.size(); ++li) {
        for (size_t m = 0; m < N_MEASURES; ++m) {
            for (size_t k = 0; k < N_KINDS; ++k) {
                const auto& r{g_max[li][m][k]};
                if (r.value == 0) continue;
                std::snprintf(buf, sizeof buf,
                              "%-12s %-11s %-5s max=%.4g raw=%" PRIu64 " bytes_in=%" PRIu64 "\n",
                              g_labels[li].c_str(), MeasureName(Measure(m)),
                              k == ABS ? "abs" : "ratio", r.value, r.raw, r.bytes_in);
                out += buf;
            }
        }
    }
    std::fputs(out.c_str(), stderr);
    if (const char* p{std::getenv("FUZZ_COST_SUMMARY")}) {
        FILE* f{std::fopen(p, "wb")};
        if (f) {
            std::fputs(out.c_str(), f);
            std::fclose(f);
        }
    }
}

} // namespace

const char* MeasureName(Measure m)
{
    switch (m) {
    case TIME: return "time_ns";
    case ALLOC_BYTES: return "alloc_bytes";
    case ALLOC_COUNT: return "alloc_count";
    case ALLOC_MAX: return "alloc_max";
    case HEAP_PEAK: return "heap_peak";
    case HEAP_KEPT: return "heap_kept";
    case LOG: return "log_bytes";
    case OUT: return "out_bytes";
    case DISK_R: return "disk_read";
    case DISK_W: return "disk_write";
    case N_MEASURES: break;
    }
    return "?";
}

bool Enabled() { return g_enabled; }

size_t LabelIndex(std::string_view label)
{
    for (size_t i = 0; i < g_labels.size(); ++i) {
        if (g_labels[i] == label) return i;
    }
    return N_LABELS_MAX;
}

void Init(std::span<const std::string> labels)
{
#ifndef FUZZ_COST
    (void)labels;
#else
    if (g_enabled) {
        // Already running: append any labels not registered yet. This lets the
        // generic per-target scope add the target name alongside whatever
        // labels a hand-instrumented target registered for itself.
        for (const auto& l : labels) {
            if (g_labels.size() >= N_LABELS_MAX) break;
            if (std::find(g_labels.begin(), g_labels.end(), l) == g_labels.end()) {
                g_labels.push_back(l);
            }
        }
        return;
    }
    const char* mode{std::getenv("FUZZ_COST_MODE")};
    if (mode && std::strcmp(mode, "off") == 0) return;
    g_measure_mode = mode && std::strcmp(mode, "measure") == 0;
    g_no_guide = std::getenv("FUZZ_COST_NO_GUIDE") != nullptr;

    g_labels.assign(labels.begin(), labels.end());
    if (g_labels.size() > N_LABELS_MAX) g_labels.resize(N_LABELS_MAX);

    if (const char* r{std::getenv("FUZZ_COST_REPEAT")}) {
        g_measure_repeat = unsigned(std::max(1, std::atoi(r)));
    }
    if (const char* d{std::getenv("FUZZ_COST_MAXDIR")}) g_maxdir = d;
    if (const char* l{std::getenv("FUZZ_COST_LOG")}) g_logpath = l;

    CalibrateTicks();

    if (std::getenv("FUZZ_COST_LOG_CAPTURE")) {
        LogInstance().m_log_sourcelocations = true;
        LogInstance().PushBackCallback([](const std::string& s) {
            g_log_bytes.fetch_add(s.size(), std::memory_order_relaxed);
        });
    }

    g_enabled = true;
    std::atexit(PrintSummary);
    std::fprintf(stderr, "fuzz_cost: enabled, %zu labels, %.4f ns/tick, mode=%s\n",
                 g_labels.size(), g_ns_per_tick, g_measure_mode ? "measure" : "guide");
#endif
}

Trial::Trial(size_t label_index, uint64_t bytes_in, std::span<const uint8_t> input, bool repeatable)
    : m_label{label_index}, m_bytes_in{std::max<uint64_t>(bytes_in, 1)}, m_input{input},
      m_repeatable{repeatable}
{
    // Only the outermost Trial measures (see g_depth).
    m_enabled = g_enabled && m_label < g_labels.size() && g_depth == 0;
    if (m_enabled) ++g_depth;
}

void Trial::AddBytesOut(std::string_view reply_type, uint64_t n)
{
    m_out += n;
    for (size_t i = 0; i < m_n_reply_types; ++i) {
        if (m_out_by_type[i].first == reply_type) {
            m_out_by_type[i].second += n;
            return;
        }
    }
    if (m_n_reply_types < MAX_REPLY_TYPES) {
        m_out_by_type[m_n_reply_types++] = {std::string{reply_type}, n};
    }
}

void Trial::OpenRun()
{
    m_log_at_start = g_log_bytes.load(std::memory_order_relaxed);
    m_alloc_bytes_at_start = g_alloc_bytes.load(std::memory_order_relaxed);
    m_alloc_count_at_start = g_alloc_count.load(std::memory_order_relaxed);
    g_alloc_max.store(0, std::memory_order_relaxed);
    m_live_at_start = g_live.load(std::memory_order_relaxed);
    g_peak.store(m_live_at_start, std::memory_order_relaxed);
    m_rchar_at_start = 0; m_wchar_at_start = 0;
    ReadProcIo(m_rchar_at_start, m_wchar_at_start);
    m_open = true;
    m_ticks_at_start = ReadTicks();
}

void Trial::CloseRun()
{
    const uint64_t ticks{ReadTicks()};
    m_open = false;
    Sample s;
    s.value[TIME] = uint64_t(double(ticks - m_ticks_at_start) * g_ns_per_tick);
    s.value[ALLOC_BYTES] = g_alloc_bytes.load(std::memory_order_relaxed) - m_alloc_bytes_at_start;
    s.value[ALLOC_COUNT] = g_alloc_count.load(std::memory_order_relaxed) - m_alloc_count_at_start;
    s.value[ALLOC_MAX] = g_alloc_max.load(std::memory_order_relaxed);
    const int64_t peak{g_peak.load(std::memory_order_relaxed) - m_live_at_start};
    const int64_t kept{g_live.load(std::memory_order_relaxed) - m_live_at_start};
    s.value[HEAP_PEAK] = uint64_t(std::max<int64_t>(peak, 0));
    s.value[HEAP_KEPT] = uint64_t(std::max<int64_t>(kept, 0));
    s.value[LOG] = g_log_bytes.load(std::memory_order_relaxed) - m_log_at_start;
    s.value[OUT] = m_out;
    uint64_t rchar{m_rchar_at_start}, wchar{m_wchar_at_start};
    ReadProcIo(rchar, wchar);
    s.value[DISK_R] = rchar - m_rchar_at_start;
    s.value[DISK_W] = wchar - m_wchar_at_start;

    if (m_runs == 1) {
        m_best = s;
    } else {
        // Deterministic measures come from the first run; the timing is a
        // minimum over the runs. Disk I/O can vary (page cache), so keep the max.
        m_best.value[TIME] = std::min(m_best.value[TIME], s.value[TIME]);
        m_best.value[DISK_R] = std::max(m_best.value[DISK_R], s.value[DISK_R]);
        m_best.value[DISK_W] = std::max(m_best.value[DISK_W], s.value[DISK_W]);
    }
}

bool Trial::Next()
{
    if (!m_enabled) {
        // Still run the body exactly once.
        return m_runs++ == 0;
    }
    if (m_runs > 0) {
        CloseRun();
        if (g_measure_mode) {
            if (!m_repeatable || m_runs >= g_measure_repeat) return false;
            ++m_runs;
            OpenRun();
            return true;
        }
        bool repeat{m_repeatable && m_runs < MAX_RUNS &&
                    m_best.value[TIME] < NO_REPEAT_ABOVE_NS &&
                    g_seen[m_label] >= WARMUP_INPUTS};
        if (repeat) {
            // Only worth repeating if this could become the timing champion.
            const auto& abs_rec{g_max[m_label][TIME][ABS]};
            const auto& rat_rec{g_max[m_label][TIME][RATIO]};
            const double ratio{double(m_best.value[TIME]) / double(m_bytes_in)};
            repeat = (m_best.value[TIME] >= ABS_MIN[TIME]) &&
                     (double(m_best.value[TIME]) > abs_rec.value * 1.125 ||
                      ratio > rat_rec.value * 1.125);
        }
        if (!repeat) return false;
    }
    ++m_runs;
    OpenRun();
    return true;
}

Trial::~Trial()
{
    if (!m_enabled) return;
    --g_depth;
    if (m_open) CloseRun(); // the body broke out of the loop
    const Sample& s{m_best};

    ++g_inputs;
    const uint64_t seen{g_seen[m_label]++};

#ifdef FUZZ_COST
    char buf[640];
    for (size_t m = 0; m < N_MEASURES; ++m) {
        const uint64_t v{s.value[m]};
        const double ratio{double(v) / double(m_bytes_in)};

        // Guide: a new cost level reads as new coverage.
        if (!g_no_guide) {
            const size_t labs{LevelOf(v, ABS_FLOOR_LOG2[m])};
            for (size_t l = 1; l <= labs; ++l) g_cost_levels[m_label][m][ABS][l] = 1;
            const size_t lrat{LevelOf((v * 256) / m_bytes_in, RATIO_FLOOR_LOG2[m])};
            for (size_t l = 1; l <= lrat; ++l) g_cost_levels[m_label][m][RATIO][l] = 1;
        }

        if (g_measure_mode || seen < WARMUP_INPUTS) continue;
        if (v < ABS_MIN[m]) continue;

        // Record: keep the champion per (label, measure, kind).
        for (size_t k = 0; k < N_KINDS; ++k) {
            const double cand{k == ABS ? double(v) : ratio};
            if (k == RATIO && m_bytes_in < 16) continue;
            MaxRecord& rec{g_max[m_label][m][k]};
            if (cand <= rec.value * 1.125) continue;
            rec = MaxRecord{cand, m_bytes_in, v};
            const std::string name{g_labels[m_label] + "-" + MeasureName(Measure(m)) +
                                   "-" + (k == ABS ? "abs" : "ratio")};
            if (!g_maxdir.empty()) WriteInput(g_maxdir + "/" + name + ".dat", m_input);
            std::string replies;
            for (size_t i = 0; i < m_n_reply_types; ++i) {
                replies += (i ? "," : "");
                replies += m_out_by_type[i].first + ":" +
                           std::to_string(m_out_by_type[i].second);
            }
            std::snprintf(buf, sizeof buf,
                          "{\"label\":\"%s\",\"measure\":\"%s\",\"kind\":\"%s\",\"value\":%" PRIu64
                          ",\"bytes_in\":%" PRIu64 ",\"ratio\":%.6g,\"input_bytes\":%zu,\"runs\":%u"
                          ",\"replies\":\"%s\",\"disconnect\":%d,\"connected\":%d}\n",
                          g_labels[m_label].c_str(), MeasureName(Measure(m)),
                          k == ABS ? "abs" : "ratio", v, m_bytes_in, ratio, m_input.size(), m_runs,
                          replies.c_str(), m_disconnect ? 1 : 0, m_connected ? 1 : 0);
            AppendLine(buf);
        }
    }

    if (g_measure_mode) {
        std::snprintf(buf, sizeof buf,
                      "{\"label\":\"%s\",\"bytes_in\":%" PRIu64 ",\"time_ns\":%" PRIu64
                      ",\"alloc_bytes\":%" PRIu64 ",\"alloc_count\":%" PRIu64
                      ",\"alloc_max\":%" PRIu64 ",\"heap_peak\":%" PRIu64 ",\"heap_kept\":%" PRIu64
                      ",\"log_bytes\":%" PRIu64 ",\"out_bytes\":%" PRIu64 ",\"disk_read\":%" PRIu64 ",\"disk_write\":%" PRIu64 ",\"disconnect\":%d,\"connected\":%d}\n",
                      g_labels[m_label].c_str(), m_bytes_in, s.value[TIME], s.value[ALLOC_BYTES],
                      s.value[ALLOC_COUNT], s.value[ALLOC_MAX], s.value[HEAP_PEAK], s.value[HEAP_KEPT],
                      s.value[LOG], s.value[OUT], s.value[DISK_R], s.value[DISK_W],
                      m_disconnect ? 1 : 0, m_connected ? 1 : 0);
        AppendLine(buf);
    }
#else
    (void)s;
    (void)seen;
#endif
}

} // namespace fuzz_cost

// ------------------------------------------------- allocator interposition --
#ifdef FUZZ_COST_MALLOC_HOOKS
extern "C" {
void* __libc_malloc(size_t);
void __libc_free(void*);
void* __libc_calloc(size_t, size_t);
void* __libc_realloc(void*, size_t);
void* __libc_memalign(size_t, size_t);

__attribute__((used)) void* malloc(size_t n)
{
    void* p{__libc_malloc(n)};
    if (p) fuzz_cost::NoteAlloc(n, malloc_usable_size(p));
    return p;
}

__attribute__((used)) void free(void* p)
{
    if (p) fuzz_cost::NoteFree(malloc_usable_size(p));
    __libc_free(p);
}

__attribute__((used)) void* calloc(size_t a, size_t b)
{
    void* p{__libc_calloc(a, b)};
    if (p) fuzz_cost::NoteAlloc(a * b, malloc_usable_size(p));
    return p;
}

__attribute__((used)) void* realloc(void* old, size_t n)
{
    const size_t old_usable{old ? malloc_usable_size(old) : 0};
    void* p{__libc_realloc(old, n)};
    if (!p) return p;
    fuzz_cost::NoteFree(old_usable);
    fuzz_cost::NoteAlloc(n, malloc_usable_size(p));
    return p;
}

__attribute__((used)) void* memalign(size_t a, size_t n)
{
    void* p{__libc_memalign(a, n)};
    if (p) fuzz_cost::NoteAlloc(n, malloc_usable_size(p));
    return p;
}

__attribute__((used)) void* aligned_alloc(size_t a, size_t n) { return memalign(a, n); }

__attribute__((used)) int posix_memalign(void** out, size_t a, size_t n)
{
    void* p{memalign(a, n)};
    if (!p) return 12 /*ENOMEM*/;
    *out = p;
    return 0;
}
} // extern "C"
#endif // FUZZ_COST_MALLOC_HOOKS

// ------------------------------------------------------ structure mutator --
// Part 2 of the report measured that cost per input saturates at the allocation
// ceiling one lying length prefix buys (~2 x 5 MiB batched reserve). Getting
// past it needs a structurally valid multi-megabyte message made of millions of
// repeated minimal elements, which random byte mutation will not build. These
// three operations build exactly that shape. Enabled by FUZZ_COST_STRUCT_MUTATOR
// so the default mutator stays available as an A/B control.
#ifdef FUZZ_COST
extern "C" {
//! Provided by libFuzzer. Weak so the binary still links without it.
__attribute__((weak)) size_t LLVMFuzzerMutate(uint8_t* data, size_t size, size_t max_size);

size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size, size_t max_size, unsigned int seed)
{
    static const bool enabled{std::getenv("FUZZ_COST_STRUCT_MUTATOR") != nullptr};

    auto delegate = [&]() -> size_t {
        if (LLVMFuzzerMutate) return LLVMFuzzerMutate(data, size, max_size);
        // No engine mutator: flip one byte so the campaign still progresses.
        if (size == 0) return 0;
        data[seed % size] ^= uint8_t(1u << (seed % 8));
        return size;
    };
    if (!enabled || max_size <= size || size == 0) return delegate();

    // splitmix64, so the stream is reproducible from libFuzzer's seed.
    uint64_t s{seed * 0x9E3779B97F4A7C15ull + 0x12345678ull};
    auto next = [&s]() {
        s += 0x9E3779B97F4A7C15ull;
        uint64_t z{s};
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    };

    switch (next() % 100) {
    case 0 ... 24: {
        // Overwrite a position with a large CompactSize, i.e. claim a huge
        // element count. This is the "lying length prefix" on its own.
        if (size < 9) return delegate();
        const size_t off{size_t(next() % (size - 8))};
        const uint64_t pick{next() % 3};
        if (pick == 0) {
            data[off] = 0xfd;
            data[off + 1] = 0xff;
            data[off + 2] = 0xff;
        } else if (pick == 1) {
            data[off] = 0xfe;
            const uint32_t v{uint32_t(0x00ffffffu | (next() & 0xff000000u))};
            std::memcpy(data + off + 1, &v, sizeof v);
        } else {
            data[off] = 0xff;
            const uint64_t v{uint64_t(next() % 0x2000000ull) + 0x1000000ull};
            std::memcpy(data + off + 1, &v, sizeof v);
        }
        return size;
    }
    case 25 ... 59: {
        // Grow the input with a run of one repeated byte. With 0x00 this is a
        // run of zero-length elements, the densest expensive body there is.
        const size_t off{size_t(next() % (size + 1))};
        const size_t room{max_size - size};
        size_t add{size_t(next() % room) + 1};
        if (next() % 2) add = room; // often go straight to the limit
        const uint8_t v{uint8_t((next() % 4) ? 0x00 : uint8_t(next()))};
        std::memmove(data + off + add, data + off, size - off);
        std::memset(data + off, v, add);
        return size + add;
    }
    case 60 ... 84: {
        // Repeat an existing chunk until the input is nearly full: turns one
        // well-formed element into millions of them.
        const size_t a{size_t(next() % size)};
        size_t len{size_t(next() % std::min<size_t>(size - a, 64)) + 1};
        const size_t room{max_size - size};
        const size_t reps{std::min(room / len, size_t(next() % 4'000'000) + 1)};
        if (reps == 0) return delegate();
        uint8_t* out{data + size};
        for (size_t i = 0; i < reps; ++i) {
            std::memcpy(out, data + a, len);
            out += len;
        }
        return size + reps * len;
    }
    default:
        return delegate();
    }
}
} // extern "C"
#endif // FUZZ_COST
