# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# In-process network simulator. Built as a library so that the same code backs
# both the standalone simulator binary and the regression tests in
# test/netsim_tests.cpp.
add_library(bitcoin_netsim STATIC EXCLUDE_FROM_ALL
  addresses.cpp
  clock.cpp
  eventqueue.cpp
  latency.cpp
  node.cpp
  pump.cpp
)

# test_util is a deliberate dependency, not an accident. It carries
# ConnmanTestMsg, which exposes exactly the CConnman internals a socketless
# driver needs, and TestingSetup, which wires up the shared ChainstateManager.
# Neither pulls in Boost.Test: that lives only in the test_bitcoin executable.
target_link_libraries(bitcoin_netsim
  PRIVATE
    core_interface
  PUBLIC
    test_util
)
