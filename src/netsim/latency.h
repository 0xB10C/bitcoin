// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETSIM_LATENCY_H
#define BITCOIN_NETSIM_LATENCY_H

#include <netsim/clock.h>
#include <random.h>

#include <cstddef>
#include <cstdint>

namespace netsim {

/** One-way delay for a chunk of bytes travelling between two simulated nodes. */
class LatencyModel
{
public:
    virtual ~LatencyModel() = default;

    /** `bytes` is passed even by models that ignore it, so a bandwidth-aware
     *  model can be dropped in without touching the call sites. */
    virtual SimTime Delay(uint32_t from, uint32_t to, size_t bytes, FastRandomContext& rng) const = 0;
};

/** Region-based delay.
 *
 * Each node belongs to a region. The one-way delay is a base value chosen by
 * whether the endpoints share a region, plus bounded jitter, plus an optional
 * serialisation delay from a per-link bandwidth.
 *
 * This is deliberately crude. It exists so that latency is a first-class part
 * of the simulation from the start, and so that measured per-prefix delays can
 * replace it later behind the same interface.
 */
class RegionLatency final : public LatencyModel
{
public:
    struct Options {
        unsigned num_regions{6};
        SimTime intra_region{std::chrono::milliseconds{12}};
        SimTime inter_region{std::chrono::milliseconds{90}};
        /** Jitter is uniform over plus or minus this fraction of the base delay. */
        double jitter_fraction{0.25};
        /** Zero means unlimited, so message size does not affect the delay. */
        uint64_t bandwidth_bytes_per_second{0};
    };

    explicit RegionLatency(Options opts) : m_opts{opts} {}

    SimTime Delay(uint32_t from, uint32_t to, size_t bytes, FastRandomContext& rng) const override;

    /** Which region a node belongs to. Derived from the id by hashing, so that
     *  region membership does not correlate with address assignment order. */
    unsigned Region(uint32_t node) const;

private:
    const Options m_opts;
};

} // namespace netsim

#endif // BITCOIN_NETSIM_LATENCY_H
