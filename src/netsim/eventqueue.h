// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETSIM_EVENTQUEUE_H
#define BITCOIN_NETSIM_EVENTQUEUE_H

#include <netsim/clock.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

namespace netsim {

/** Work to be run at one simulated instant. */
using Event = std::function<void()>;

/** A time-ordered queue of pending work, and the engine of the simulation.
 *
 * Events posted for the same instant run in the order they were posted, so a
 * run with a fixed seed is reproducible. Posting from inside a running event
 * is expected: that is how the simulation keeps itself alive.
 */
class EventQueue
{
public:
    void Post(SimTime when, Event event);

    bool Empty() const { return m_heap.empty(); }
    size_t Size() const { return m_heap.size(); }

    /** Time of the earliest pending event. Must not be called when empty. */
    SimTime NextTime() const;

    /** Advance `clock` to the earliest event and run it. Must not be called when empty. */
    void RunOne(SimClock& clock);

    /** Run every event up to and including `until`, then leave the clock at
     *  `until`. Returns how many events ran. */
    size_t RunUntil(SimClock& clock, SimTime until);

private:
    struct Entry {
        SimTime when;
        uint64_t seq;
        Event event;
    };

    /** Comparator for a std::*_heap min-heap on (when, seq).
     *
     * The standard heap helpers build a max-heap, so this is inverted: the
     * "greatest" entry under this ordering is the earliest one, which is what
     * we want at the top. */
    struct MinHeapOrder {
        bool operator()(const Entry& a, const Entry& b) const
        {
            if (a.when != b.when) return a.when > b.when;
            return a.seq > b.seq;
        }
    };

    std::vector<Entry> m_heap;
    uint64_t m_next_seq{0};
};

} // namespace netsim

#endif // BITCOIN_NETSIM_EVENTQUEUE_H
