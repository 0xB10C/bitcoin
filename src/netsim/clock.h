// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETSIM_CLOCK_H
#define BITCOIN_NETSIM_CLOCK_H

#include <chrono>

namespace netsim {

/** Simulated time. Microsecond resolution, counted from an arbitrary epoch. */
using SimTime = std::chrono::microseconds;

/** The simulation's single clock.
 *
 * It deliberately carries two resolutions.
 *
 * Events are ordered at microsecond resolution, so link latency is modelled
 * exactly and a 90 ms hop really does arrive after a 12 ms one.
 *
 * Mock time, which is all a simulated node can observe, moves in whole
 * seconds. That is not a choice: SetMockTime() stores std::chrono::seconds and
 * NodeClock::now() reads it directly, so even the microsecond accessors in
 * net_processing see second-quantised values.
 *
 * The coarse belief is harmless for what this simulator measures, because
 * every timer involved sits well above a second: a 30 s average address
 * broadcast, a 24 h self-announcement, a 2 min ping, a rate limiter refilling
 * at 0.1 addresses per second. Two consequences are worth remembering. A timer
 * armed for a fractional offset fires at the next second boundary, and several
 * messages arriving within one simulated second see a zero time delta in the
 * address rate limiter, so it does not refill between them.
 */
class SimClock
{
public:
    /** `start` must be positive, because mock time treats zero as "not mocked". */
    explicit SimClock(SimTime start);
    ~SimClock();

    SimClock(const SimClock&) = delete;
    SimClock& operator=(const SimClock&) = delete;

    SimTime Now() const { return m_now; }

    /** Move to `when`, which must not be in the past, and republish mock time. */
    void AdvanceTo(SimTime when);

private:
    SimTime m_now;
    std::chrono::seconds m_published{};
};

} // namespace netsim

#endif // BITCOIN_NETSIM_CLOCK_H
