# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_executable(bench_bitcoin
  bench_bitcoin.cpp
  bench.cpp
  nanobench.cpp
# Benchmarks:
  addrman.cpp
  base58.cpp
  bech32.cpp
  bip324_ecdh.cpp
  block_assemble.cpp
  blockencodings.cpp
  ccoins_caching.cpp
  chacha20.cpp
  checkblock.cpp
  checkblockindex.cpp
  checkqueue.cpp
  cluster_linearize.cpp
  connectblock.cpp
  crypto_hash.cpp
  descriptors.cpp
  disconnected_transactions.cpp
  duplicate_inputs.cpp
  ellswift.cpp
  examples.cpp
  gcs_filter.cpp
  hashpadding.cpp
  index_blockfilter.cpp
  load_external.cpp
  lockedpool.cpp
  logging.cpp
  mempool_ephemeral_spends.cpp
  mempool_eviction.cpp
  mempool_stress.cpp
  merkle_root.cpp
  obfuscation.cpp
  parse_hex.cpp
  peer_eviction.cpp
  poly1305.cpp
  pool.cpp
  prevector.cpp
  random.cpp
  readwriteblock.cpp
  rollingbloom.cpp
  rpc_blockchain.cpp
  rpc_mempool.cpp
  sign_transaction.cpp
  streams_findbyte.cpp
  strencodings.cpp
  txgraph.cpp
  txorphanage.cpp
  uint256_blob.cpp
  util_time.cpp
  verify_script.cpp
)

add_windows_application_manifest(bench_bitcoin)

include(TargetDataSources)
target_raw_data_sources(bench_bitcoin NAMESPACE benchmark::data
  data/block413567.raw
)

target_link_libraries(bench_bitcoin
  core_interface
  test_util
  bitcoin_node
  Boost::headers
)

if(WITH_EMBEDDED_ASMAP)
  target_sources(bench_bitcoin PRIVATE asmap.cpp)
endif()

if(ENABLE_WALLET)
  target_sources(bench_bitcoin
    PRIVATE
      coin_selection.cpp
      wallet_balance.cpp
      wallet_create.cpp
      wallet_create_tx.cpp
      wallet_encrypt.cpp
      wallet_loading.cpp
      wallet_ismine.cpp
      wallet_migration.cpp
  )
  target_link_libraries(bench_bitcoin bitcoin_wallet)
endif()

install_binary_component(bench_bitcoin INTERNAL)

# Standalone benchmark that measures CBlock deserialization for every block in a
# node's blocks/ directory. Not part of bench_bitcoin: it has its own main() and
# is driven by a real block store instead of running for a fixed duration.
add_executable(bench_blocks
  bench_blocks.cpp
)
add_windows_application_manifest(bench_blocks)
target_link_libraries(bench_blocks
  core_interface
  bitcoin_common
  bitcoin_util
  univalue
)
install_binary_component(bench_blocks INTERNAL)
