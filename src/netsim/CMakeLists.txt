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
)

target_link_libraries(bitcoin_netsim
  PRIVATE
    core_interface
)
