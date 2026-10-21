# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# In-process network simulator. Built as a library so that the same code backs
# both the standalone simulator binary and the regression tests in
# test/netsim_tests.cpp.
add_library(bitcoin_netsim STATIC EXCLUDE_FROM_ALL
  addresses.cpp
  chain.cpp
  clock.cpp
  eventqueue.cpp
  export.cpp
  latency.cpp
  metrics.cpp
  network.cpp
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

# Standalone driver. EXCLUDE_FROM_ALL because it links the whole node and a
# normal build does not need it; build it with
#   cmake --build build --target bitcoin-netsim
add_executable(bitcoin-netsim EXCLUDE_FROM_ALL
  main.cpp
)

target_link_libraries(bitcoin-netsim
  core_interface
  bitcoin_netsim
  test_util
  bitcoin_node
  bitcoin_common
  bitcoin_util
  bitcoin_consensus
  minisketch
  leveldb
  univalue
  secp256k1
  Boost::headers
)
