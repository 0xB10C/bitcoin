// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <netbase.h>
#include <netgroup.h>
#include <random.h>
#include <util/check.h>

#include <algorithm>
#include <array>
#include <span>
#include <string>

static void BenchGetGroup(benchmark::Bench& bench, std::span<const CNetAddr> addrs)

    auto netgroupman{NetGroupManager::NoAsmap()};

    bench.batch(addrs.size()).run([&] {
        for (const CNetAddr& addr : addrs) {
            netgroupman.GetGroup(addr);
        }
    });
}

static CNetAddr LookupAddr(const std::string& address) { return LookupHost(address, /*fAllowLookup=*/false).value(); }

static void NetGroupGetGroupMulti(benchmark::Bench& bench)
{
    // A list of 25 IPv4 and 25 IPv6 addresses randomly sampled across
    // 50 ASNs to have a mix of different lookup times. These have been
    // masked to /24 and /64 respectively. Some of these could become
    // unmapped when updating the embedded ASMap file, which will cause
    // the benchmarks to assert and the IPs will need to be changed out.
    std::array addrs{
        LookupAddr("5.8.10.1"),
        LookupAddr("14.53.20.1"),
        LookupAddr("34.86.160.1"),
        LookupAddr("67.68.205.1"),
        LookupAddr("68.163.58.1"),
        LookupAddr("69.138.189.1"),
        LookupAddr("72.211.58.1"),
        LookupAddr("73.124.158.1"),
        LookupAddr("77.179.43.1"),
        LookupAddr("80.79.125.1"),
        LookupAddr("81.217.170.1"),
        LookupAddr("82.216.149.1"),
        LookupAddr("84.52.201.1"),
        LookupAddr("87.184.174.1"),
        LookupAddr("90.221.151.1"),
        LookupAddr("95.31.136.1"),
        LookupAddr("99.234.174.1"),
        LookupAddr("105.98.199.1"),
        LookupAddr("146.190.174.1"),
        LookupAddr("154.16.157.1"),
        LookupAddr("172.81.183.1"),
        LookupAddr("173.24.74.1"),
        LookupAddr("195.99.226.1"),
        LookupAddr("213.197.14.1"),
        LookupAddr("220.255.248.1"),

        LookupAddr("2001:16a2:c0b0:58b7::1"),
        LookupAddr("2001:67c:e60:c0c::1"),
        LookupAddr("2001:99a:213:27f0::1"),
        LookupAddr("2001:9e8:894b:be00::1"),
        LookupAddr("2406:2d40:1ebc:3508::1"),
        LookupAddr("2600:1015:a020:1e00::1"),
        LookupAddr("2600:1700:4228:a800::1"),
        LookupAddr("2601:603:5000:3309::1"),
        LookupAddr("2601:cd:ce01:9610::1"),
        LookupAddr("2603:800c:25f0:8350::1"),
        LookupAddr("2604:3d09:f89:d100::1"),
        LookupAddr("2607:fb90:236f:821f::1"),
        LookupAddr("2800:2331:5440:ba3::1"),
        LookupAddr("2a00:16e0:1012:c108::1"),
        LookupAddr("2a00:23c6:9d44:7801::1"),
        LookupAddr("2a00:79c0:609:4900::1"),
        LookupAddr("2a01:4f8:13a:1f8d::1"),
        LookupAddr("2a01:e0a:8a3:ab90::1"),
        LookupAddr("2a02:810b:449e:c900::1"),
        LookupAddr("2a02:8308:20d:e800::1"),
        LookupAddr("2a0a:ef40:331:4401::1"),
        LookupAddr("2a0c:5a86:a002:e700::1"),
        LookupAddr("2a10:3781:1d7:1::1"),
        LookupAddr("2a12:26c0:3303:a100::1"),
        LookupAddr("2a12:a800:2:1::1"),
    };

    FastRandomContext rng{/*fDeterministic=*/true};
    std::ranges::shuffle(addrs, rng);

    BenchGetGroup(bench, addrs);
}

BENCHMARK(NetGroupGetGroupMulti);
