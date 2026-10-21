// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETSIM_SETUP_H
#define BITCOIN_NETSIM_SETUP_H

#include <test/util/setup_common.h>

namespace netsim {

/** What a simulation wants from TestingSetup, as opposed to what a test wants.
 *
 * Shared by the standalone driver and the regression tests so the two measure
 * the same thing.
 */
TestOpts SimTestOpts();

} // namespace netsim

#endif // BITCOIN_NETSIM_SETUP_H
