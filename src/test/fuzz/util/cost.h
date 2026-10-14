// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_FUZZ_UTIL_COST_H
#define BITCOIN_TEST_FUZZ_UTIL_COST_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <string_view>

//! Per-input resource accounting for fuzz targets ("cost meter").
//!
//! A Scope measures the resources consumed by the block it guards and then
//!   - Guide():  turns the cost into extra coverage features, so libFuzzer keeps
//!               inputs that reach a new cost level,
//!   - Record(): keeps a per (label, measure) running maximum and saves the input
//!               bytes of every new maximum,
//!   - Check():  compares against optional thresholds and abort()s on a breach,
//!               so the engine files the input as a crash.
//!
//! Everything is off unless FUZZ_COST is defined at build time.
namespace fuzz_cost {

enum Measure : uint8_t {
    TIME,        //!< nanoseconds, derived from the timestamp counter (noisy)
    ALLOC_BYTES, //!< bytes requested from the allocator (deterministic)
    ALLOC_COUNT, //!< allocator calls (deterministic)
    ALLOC_MAX,   //!< largest single allocation (deterministic)
    HEAP_PEAK,   //!< maximum live bytes above the scope's entry level
    HEAP_KEPT,   //!< live bytes still held when the scope ends
    LOG,         //!< bytes handed to the logger
    OUT,         //!< bytes queued for sending back
    DISK_R,      //!< bytes read via syscalls (/proc/self/io rchar), e.g. blocks served from disk
    DISK_W,      //!< bytes written via syscalls (/proc/self/io wchar), e.g. db / block / log writes
    N_MEASURES,
};

const char* MeasureName(Measure m);

struct Sample {
    std::array<uint64_t, N_MEASURES> value{};
};

//! Must be called once from a target's init function, before any Scope.
//! `labels` are the cost buckets reported on (e.g. the P2P message types).
void Init(std::span<const std::string> labels);

//! Index of a label registered with Init(), or N_LABELS_MAX if unknown.
size_t LabelIndex(std::string_view label);

//! Measures one input. Usage:
//!
//!     fuzz_cost::Trial trial{type_index, bytes_in, buffer, /*repeatable=*/true};
//!     while (trial.Next()) { ... the work being measured ... }
//!
//! The loop normally runs once. When a run looks like a new timing maximum and
//! the caller promised the work is repeatable (no global state touched), the
//! trial repeats it a few times and keeps the minimum, because a single
//! timestamp-counter reading on a shared machine is worth very little. The
//! deterministic measures are taken from the first run.
class Trial
{
public:
    //! `input` is the raw fuzz input, saved verbatim when this trial sets a new maximum.
    Trial(size_t label_index, uint64_t bytes_in, std::span<const uint8_t> input, bool repeatable = false);
    ~Trial();

    Trial(const Trial&) = delete;
    Trial& operator=(const Trial&) = delete;

    bool Next();

    //! Add bytes that the measured block queued for sending back to the peer.
    //! The reply type is kept so a champion can be read as "this 61-byte addrv2
    //! provoked 1.2 MB of `addr`", not just "it sent bytes".
    void AddBytesOut(std::string_view reply_type, uint64_t n);
    void AddBytesOut(uint64_t n) { m_out += n; }

    //! Record whether handling this input would disconnect the peer. A
    //! disconnect makes the cost one-shot per connection, so repeatable
    //! (non-disconnecting) findings are the ones that matter for DoS.
    void SetDisconnect(bool d) { m_disconnect = d; }
    //! Whether the peer had completed the version/verack handshake. A disconnect
    //! only attributes to the message itself when the peer was connected;
    //! otherwise it is just handshake-ordering (a message before VERACK).
    void SetConnected(bool c) { m_connected = c; }

    static constexpr size_t MAX_REPLY_TYPES{8};

private:
    void OpenRun();
    void CloseRun();

    const size_t m_label;
    const uint64_t m_bytes_in;
    const std::span<const uint8_t> m_input;
    const bool m_repeatable;
    bool m_enabled{false};
    bool m_open{false};
    unsigned m_runs{0};
    uint64_t m_out{0};
    bool m_disconnect{false};
    bool m_connected{false};
    std::array<std::pair<std::string, uint64_t>, MAX_REPLY_TYPES> m_out_by_type{};
    size_t m_n_reply_types{0};
    Sample m_best{};
    uint64_t m_log_at_start{0};
    uint64_t m_alloc_bytes_at_start{0};
    uint64_t m_alloc_count_at_start{0};
    int64_t m_live_at_start{0};
    uint64_t m_ticks_at_start{0};
    uint64_t m_rchar_at_start{0};
    uint64_t m_wchar_at_start{0};
};

//! True when the meter is compiled in and enabled at run time.
bool Enabled();

} // namespace fuzz_cost


#endif // BITCOIN_TEST_FUZZ_UTIL_COST_H
