// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netsim/latency.h>

#include <util/check.h>

#include <algorithm>
#include <cstdint>

namespace netsim {

unsigned RegionLatency::Region(uint32_t node) const
{
    Assert(m_opts.num_regions > 0);
    // splitmix32, so that consecutive node ids do not land in consecutive
    // regions. Node ids map to addresses in order, and a correlation between
    // address and region would quietly bias every path-length measurement.
    uint32_t x{node + 0x9e3779b9u};
    x ^= x >> 16;
    x *= 0x21f0aaadu;
    x ^= x >> 15;
    x *= 0x735a2d97u;
    x ^= x >> 15;
    return x % m_opts.num_regions;
}

SimTime RegionLatency::Delay(uint32_t from, uint32_t to, size_t bytes, FastRandomContext& rng) const
{
    SimTime delay{Region(from) == Region(to) ? m_opts.intra_region : m_opts.inter_region};

    if (m_opts.jitter_fraction > 0.0) {
        const auto span{static_cast<int64_t>(static_cast<double>(delay.count()) * m_opts.jitter_fraction)};
        if (span > 0) {
            const auto draw{static_cast<int64_t>(rng.randrange(static_cast<uint64_t>(2 * span + 1)))};
            delay += SimTime{draw - span};
        }
    }

    if (m_opts.bandwidth_bytes_per_second > 0 && bytes > 0) {
        delay += SimTime{(static_cast<int64_t>(bytes) * 1'000'000) /
                         static_cast<int64_t>(m_opts.bandwidth_bytes_per_second)};
    }

    // A zero delay would let a message arrive at the instant it was sent,
    // which makes causality harder to reason about for no benefit.
    return std::max(delay, SimTime{1});
}

} // namespace netsim
