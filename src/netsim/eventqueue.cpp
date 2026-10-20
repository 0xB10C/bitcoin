// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netsim/eventqueue.h>

#include <netsim/clock.h>
#include <util/check.h>

#include <algorithm>
#include <utility>

namespace netsim {

void EventQueue::Post(SimTime when, Event event)
{
    m_heap.push_back(Entry{when, m_next_seq++, std::move(event)});
    std::push_heap(m_heap.begin(), m_heap.end(), MinHeapOrder{});
}

SimTime EventQueue::NextTime() const
{
    Assert(!m_heap.empty());
    return m_heap.front().when;
}

void EventQueue::RunOne(SimClock& clock)
{
    Assert(!m_heap.empty());
    std::pop_heap(m_heap.begin(), m_heap.end(), MinHeapOrder{});
    Entry entry{std::move(m_heap.back())};
    m_heap.pop_back();

    clock.AdvanceTo(entry.when);
    // The event may post more work, including work for this same instant.
    entry.event();
}

size_t EventQueue::RunUntil(SimClock& clock, SimTime until)
{
    size_t ran{0};
    while (!Empty() && NextTime() <= until) {
        RunOne(clock);
        ++ran;
    }
    if (clock.Now() < until) clock.AdvanceTo(until);
    return ran;
}

} // namespace netsim
