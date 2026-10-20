// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETSIM_METRICS_H
#define BITCOIN_NETSIM_METRICS_H

#include <cstdint>
#include <optional>

namespace netsim {

/** Current resident set size of this process, in bytes.
 *
 * Memory is the binding constraint on how large a simulation can be, so the
 * simulator measures its own footprint rather than leaving it to be guessed
 * from type sizes. Take a reading before building the population and another
 * after the run: the difference is what the simulation itself cost, with the
 * host process and its shared chainstate excluded.
 *
 * Returns std::nullopt where the platform does not expose it.
 */
std::optional<uint64_t> ResidentSetBytes();

/** High-water mark of the resident set size, in bytes.
 *
 * Unlike ResidentSetBytes() this never falls back, so it answers "how much did
 * this run need at its worst", which is the figure that decides whether the
 * next rung of the scale ladder fits on a given machine.
 */
std::optional<uint64_t> PeakResidentSetBytes();

} // namespace netsim

#endif // BITCOIN_NETSIM_METRICS_H
