// Copyright (c) 2016-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <key.h>
#include <random.h>

#include <array>

static void EllSwiftEncode(benchmark::Bench& bench)
{
    ECC_Start();

    std::array<uint8_t, 32> rnd32;
    GetRandBytes(rnd32);

    CKey key;
    key.MakeNewKey(true);

    bench.batch(1).unit("pubkey").run([&] {
        key.EllSwiftEncode(rnd32);
    });
    ECC_Stop();
}

BENCHMARK(EllSwiftEncode);
