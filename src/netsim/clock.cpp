// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netsim/clock.h>

#include <util/check.h>
#include <util/time.h>

#include <chrono>

namespace netsim {

SimClock::SimClock(SimTime start)
    : m_now{start}
{
    Assert(start > SimTime::zero());
    m_published = std::chrono::duration_cast<std::chrono::seconds>(m_now);
    SetMockTime(m_published);
}

SimClock::~SimClock()
{
    // Hand the process back its real clock, so a simulation cannot leak mock
    // time into whatever runs next.
    SetMockTime(std::chrono::seconds{0});
}

void SimClock::AdvanceTo(SimTime when)
{
    Assert(when >= m_now);
    m_now = when;

    const auto whole_seconds{std::chrono::duration_cast<std::chrono::seconds>(m_now)};
    if (whole_seconds != m_published) {
        m_published = whole_seconds;
        SetMockTime(whole_seconds);
    }
}

} // namespace netsim
