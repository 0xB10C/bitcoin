// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netsim/setup.h>

namespace netsim {

TestOpts SimTestOpts()
{
    TestOpts opts;
    // Every node builds its own CConnman and PeerManager, so the fixture's
    // single set would just be dead weight.
    opts.setup_net = false;
    // Otherwise ValidationCache eagerly allocates and touches 32.25 MiB, which
    // would sit inside every memory figure the simulator reports.
    opts.min_validation_cache = true;
    return opts;
}

} // namespace netsim
