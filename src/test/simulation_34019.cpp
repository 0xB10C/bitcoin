// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addrdb.h>
#include <addrman.h>
#include <addrman_impl.h>
#include <boost/test/unit_test.hpp>
#include <node/data/ip_asn.dat.h>
#include <test/util/setup_common.h>
#include <test/util/net.h>
#include <util/fs_helpers.h>

using namespace std::literals;
using node::NodeContext;
using util::ToString;

static const uint SIMULATION_ITERATIONS = 1'000'000;
// Rate at which our outbound connections to non-bitprojects IPs succeed.
// The 25% are based on https://bnoc.xyz/t/outbound-connection-success-rates-of-a-bitcoin-node/142/4
static const int CONNECTION_SUCCESS_RATE = 25;  // %

struct PeersDatFile {
    fs::path path;
    // whether the node should use the embedded asmap file.
    // this is useful when the node was using asmap before
    // to retain (most of) the bucketing of the addrman entries.
    bool asmap;
    // size of the new table
    uint new_;
    // size of the tried table
    uint tried;
    // number of ipv4 entries
    uint ipv4;
    // number of ipv6 entries
    uint ipv6;
    // number of onion entries
    uint onion;
    // number of i2p entries
    uint i2p;

    int64_t oldest_new;
    int64_t youngest_new;
    int64_t oldest_tried;
    int64_t youngest_tried;

    // number of Bitprojects IPs in new table
    uint bitprojects_new;
    // number of Bitprojects IPs in tried table
    uint bitprojects_tried;

    std::unique_ptr<AddrMan> load(NetGroupManager& netgroupmanager) const
    {
        auto addrman = LoadAddrmanFromPath(path, netgroupmanager);
        uint32_t bitprojects_addr_in_new = 0;
        uint32_t bitprojects_addr_in_tried = 0;
        int64_t oldest_new_ = std::numeric_limits<int64_t>::max();
        int64_t youngest_new_ = 0;
        int64_t oldest_tried_ = std::numeric_limits<int64_t>::max();
        int64_t youngest_tried_ = 0;
        for (const auto& e : addrman->GetEntries(/*tried=*/false)) {
            AddrInfo info = e.first;
            oldest_new_ = std::min(oldest_new_, static_cast<int64_t>(TicksSinceEpoch<std::chrono::seconds>(info.nTime)));
            youngest_new_ = std::max(youngest_new_, static_cast<int64_t>(TicksSinceEpoch<std::chrono::seconds>(info.nTime)));
            if (info.IsBitprojects()) {
                bitprojects_addr_in_new++;
            };
        }
        for (const auto& e : addrman->GetEntries(/*tried=*/true)) {
            const AddrInfo& info = e.first;
            oldest_tried_ = std::min(oldest_tried_, static_cast<int64_t>(TicksSinceEpoch<std::chrono::seconds>(info.nTime)));
            youngest_tried_ = std::max(youngest_tried_, static_cast<int64_t>(TicksSinceEpoch<std::chrono::seconds>(info.nTime)));
            if (info.IsBitprojects()) {
                bitprojects_addr_in_tried++;
            };
        }

        BOOST_CHECK_EQUAL(addrman->Size(/*net=*/std::nullopt, /*in_new=*/true), new_);
        BOOST_CHECK_EQUAL(addrman->Size(/*net=*/std::nullopt, /*in_new=*/false), tried);
        BOOST_CHECK_EQUAL(addrman->Size(/*net=*/NET_IPV4, /*in_new=*/std::nullopt), ipv4);
        BOOST_CHECK_EQUAL(addrman->Size(/*net=*/NET_IPV6, /*in_new=*/std::nullopt), ipv6);
        BOOST_CHECK_EQUAL(addrman->Size(/*net=*/NET_ONION, /*in_new=*/std::nullopt), onion);
        BOOST_CHECK_EQUAL(addrman->Size(/*net=*/NET_I2P, /*in_new=*/std::nullopt), i2p);
        BOOST_CHECK_EQUAL(youngest_new, youngest_new_);
        BOOST_CHECK_EQUAL(oldest_new, oldest_new_);
        BOOST_CHECK_EQUAL(youngest_tried, youngest_tried_);
        BOOST_CHECK_EQUAL(oldest_tried, oldest_tried_);
        BOOST_CHECK_EQUAL(bitprojects_addr_in_new, bitprojects_new);
        BOOST_CHECK_EQUAL(bitprojects_addr_in_tried, bitprojects_tried);

        return addrman;
    }
};

static uint32_t simulate(ConnmanTestMsg *conman, NetGroupManager& netgroupmanager, FastRandomContext& rng) {
    std::set<std::vector<unsigned char>> outbound_ipv46_peer_netgroups{};
    uint32_t outbounds = 0;
    uint32_t bitprojects = 0;

    while (true) {
        std::optional<CAddress> address_opt = conman->TryPickOutboundAddress(
            /*anchor=*/false,
            // For the simulation, the connection type is not relevant. We only care who
            // we are connected to. While we pass conn_type to TryPickOutboundAddress, this
            // is only used for logging, not for making a decision on who to connect to.
            ConnectionType::OUTBOUND_FULL_RELAY,
            /*feeler=*/false,
            outbound_ipv46_peer_netgroups,
            // The preferred_net is not used in our "cold-start" simulations.
            // The node only uses it to replace a connection if we aren't
            // connected to a network after EXTRA_NETWORK_PEER_INTERVAL (5min).
            /*preferred_net=*/std::nullopt
        );

        // No suitable address was found within TryPickOutboundAddress' internal
        // attempt limit. In production ThreadOpenConnections would loop around
        // (sleep, re-add seeds, ...) and try again, so for the simulation we
        // just retry until we have filled all our outbound slots.
        if (!address_opt) {
            continue;
        }
        const CAddress& address{*address_opt};

        if (address.IsIPv4() || address.IsIPv6()) {
            outbound_ipv46_peer_netgroups.insert(netgroupmanager.GetGroup(address));
        }

        // We consider all connections to Bitprojects as successful, as that's what was
        // observed in the real world:
        // https://bnoc.xyz/t/outbound-connection-success-rates-of-a-bitcoin-node/142/5
        if(!address.IsBitprojects()) {
            // We fail some of the non-Bitprojects connections based on a CONNECTION_SUCCESS_RATE.
            if (rng.randrange(100) >= CONNECTION_SUCCESS_RATE) {
                continue;
            }
        }

        if(address.IsBitprojects()) {
            bitprojects++;
        }

        outbounds++;

        if (outbounds >= MAX_BLOCK_RELAY_ONLY_CONNECTIONS + MAX_OUTBOUND_FULL_RELAY_CONNECTIONS) {
            // simulation done
            break;
        }
    }

    return bitprojects;
}

static void run(node::NodeContext& node, const PeersDatFile& file) {
    NetGroupManager netgroupmanager{
        file.asmap ? NetGroupManager::WithEmbeddedAsmap(node::data::ip_asn) : NetGroupManager::NoAsmap()
    };

    auto addrman = file.load(netgroupmanager);

    auto connman = std::make_unique<ConnmanTestMsg>(0x1337, 0x1337, *addrman, netgroupmanager, Params());
    CConnman::Options options;
    options.m_msgproc = node.peerman.get();
    connman->Init(options);

    // Deterministic RNG so the simulation results are reproducible.
    FastRandomContext rng{/*fDeterministic=*/true};

    std::vector<int> counts(11, 0);
    for(uint i = 0; i < SIMULATION_ITERATIONS; i++) {
        if (i > 0 && i % (SIMULATION_ITERATIONS/10) == 0) {
            LogInfo("done %d/%d iterations", i, SIMULATION_ITERATIONS);
        }

        uint32_t bitprojects_connections = simulate(connman.get(), netgroupmanager, rng);
        counts[bitprojects_connections]++;
    }

    fs::path input_path{file.path};
    fs::path output_path =
        input_path.parent_path() /
        (input_path.stem().string() + "_results.txt");
    auto out = fsbridge::fopen(output_path, "w");

    std::string peers_dat_filename = fs::PathToString(file.path);
    fputs((peers_dat_filename + "\n").c_str(), out);
    for (size_t i = 0; i < counts.size(); ++i) {
        if (counts[i] > 0) {
            float percentage = counts[i] * 100.0 / SIMULATION_ITERATIONS;
            fprintf(out, "count %2zu: % 9d \t %.2f%%\n", i, counts[i], percentage);
        }
    }
}

BOOST_FIXTURE_TEST_SUITE(simulation_34019_20260312_hal, TestingSetup)

BOOST_AUTO_TEST_CASE(sim_20260312_hal)
{
    PeersDatFile file {
        .path = "../../../simulation_data/2026-03-12-hal-peers.dat",
        .asmap = true,
        .new_ = 62183,
        .tried = 9413,
        .ipv4 = 43901,
        .ipv6 = 5754,
        .onion = 18576,
        .i2p = 3365,
        .oldest_new = 1762413512,   // Thursday, November 6, 2025 at 07:18:32 UTC
        .youngest_new = 1773318441, // Thursday, March 12, 2026 at 12:27:21 UTC
        .oldest_tried = 1759921515, // Wednesday, October 8, 2025 at 11:05:15 UTC
        .youngest_tried = 1773315622, // Thursday, March 12, 2026 at 11:40:22 UTC
        .bitprojects_new = 396,
        .bitprojects_tried = 371,
    };

    run(m_node, file);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(simulation_34019_20250815_dea, TestingSetup)
BOOST_AUTO_TEST_CASE(sim_20250815_dea)
{
    PeersDatFile file {
        .path = "../../../simulation_data/2025-08-15-dea-peers.dat",
        .asmap = false,
        .new_ = 64612,
        .tried = 3915,
        .ipv4 = 57572,
        .ipv6 = 10955,
        .onion = 0,
        .i2p = 0,
        .oldest_new = 1743088338,   // Thursday, March 27, 2025 at 15:12:18 UTC
        .youngest_new = 1755227248, // Friday, August 15, 2025 at 03:07:28 UTC
        .oldest_tried = 1732086452, // Wednesday, November 20, 2024 at 07:07:32 UTC
        .youngest_tried = 1755227636, // Friday, August 15, 2025 at 03:13:56 UTC
        .bitprojects_new = 610,
        .bitprojects_tried = 424,
    };

    run(m_node, file);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(simulation_34019_20260114_dar, TestingSetup)
BOOST_AUTO_TEST_CASE(sim_20260114_dar)
{
    PeersDatFile file {
        .path = "../../../simulation_data/2026-01-14-dar-peers.dat",
        .asmap = false,
        .new_ = 26808,
        .tried = 167,
        .ipv4 = 23906,
        .ipv6 = 3069,
        .onion = 0,
        .i2p = 0,
        .oldest_new = 1765639029,   // Saturday, December 13, 2025 at 15:17:09 UTC
        .youngest_new = 1768407499, // Wednesday, January 14, 2026 at 16:18:19 UTC
        .oldest_tried = 1765920912, // Tuesday, December 16, 2025 at 21:35:12 UTC
        .youngest_tried = 1768412669, // Wednesday, January 14, 2026 at 17:44:29 UTC
        .bitprojects_new = 884,
        .bitprojects_tried = 41,
    };

    run(m_node, file);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(simulation_34019_20260210_dan, TestingSetup)
BOOST_AUTO_TEST_CASE(sim_20260210_dan)
{
    PeersDatFile file {
        .path = "../../../simulation_data/2026-02-10-dan-peers.dat",
        .asmap = false,
        .new_ = 46304,
        .tried = 83,
        .ipv4 = 40953,
        .ipv6 = 5434,
        .onion = 0,
        .i2p = 0,
        .oldest_new = 1745815456,   // Monday, April 28, 2025 at 04:44:16 UTC
        .youngest_new = 1770727464, // Tuesday, February 10, 2026 at 12:44:24 UTC
        .oldest_tried = 1765475690, // Thursday, December 11, 2025 at 17:54:50 UTC
        .youngest_tried = 1770734972, // Tuesday, February 10, 2026 at 14:49:32 UTC
        .bitprojects_new = 1717,
        .bitprojects_tried = 19,
    };

    run(m_node, file);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(simulation_34019_20260315_dea, TestingSetup)
BOOST_AUTO_TEST_CASE(sim_20260315_dea)
{
    PeersDatFile file {
        .path = "../../../simulation_data/2026-03-15-dea-peers.dat",
        .asmap = false,
        .new_ = 63778,
        .tried = 8361,
        .ipv4 = 61926,
        .ipv6 = 10213,
        .onion = 0,
        .i2p = 0,
        .oldest_new = 1736909159,   // Wednesday, January 15, 2025 at 02:45:59 UTC
        .youngest_new = 1773508175, // Saturday, March 14, 2026 at 17:09:35 UTC
        .oldest_tried = 1743272734, // Saturday, March 29, 2025 at 18:25:34 UTC
        .youngest_tried = 1773507875, // Saturday, March 14, 2026 at 17:04:35 UTC
        .bitprojects_new = 1291,
        .bitprojects_tried = 1124,
    };

    run(m_node, file);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(simulation_34019_20260326_wil, TestingSetup)
BOOST_AUTO_TEST_CASE(sim_20260326_wil)
{
    PeersDatFile file {
        .path = "../../../simulation_data/2026-03-26-wil-peers.dat",
        .asmap = false,
        .new_ = 63267,
        .tried = 7902,
        .ipv4 = 49088,
        .ipv6 = 7390,
        .onion = 14492,
        .i2p = 199,
        .oldest_new = 1702010757,   // Friday, December 8, 2023 at 04:45:57 UTC
        .youngest_new = 1774526858, // Thursday, March 26, 2026 at 12:07:38 UTC
        .oldest_tried = 1687767621, // Monday, June 26, 2023 at 08:20:21 UTC
        .youngest_tried = 1774532931, // Thursday, March 26, 2026 at 13:48:51 UTC
        .bitprojects_new = 1419,
        .bitprojects_tried = 288,
    };

    run(m_node, file);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(simulation_34019_20260403_dar, TestingSetup)
BOOST_AUTO_TEST_CASE(sim_20260403_dar)
{
    PeersDatFile file {
        .path = "../../../simulation_data/2026-04-03-dar-peers.dat",
        .asmap = false,
        .new_ = 26176,
        .tried = 35,
        .ipv4 = 22830,
        .ipv6 = 3381,
        .onion = 0,
        .i2p = 0,
        .oldest_new = 1761926332,   // Friday, October 31, 2025 at 15:58:52 UTC
        .youngest_new = 1775219356, // Friday, April 3, 2026 at 12:29:16 UTC
        .oldest_tried = 1764012518, // Monday, November 24, 2025 at 19:28:38 UTC
        .youngest_tried = 1775227272, // Friday, April 3, 2026 at 14:41:12 UTC
        .bitprojects_new = 803,
        .bitprojects_tried = 1,
    };

    run(m_node, file);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(simulation_34019_20250424_dan, TestingSetup)
BOOST_AUTO_TEST_CASE(sim_20250424_dan)
{
    PeersDatFile file {
        .path = "../../../simulation_data/2025-04-24-dan-peers.dat",
        .asmap = false,
        .new_ = 49334,
        .tried = 199,
        .ipv4 = 35684,
        .ipv6 = 6718,
        .onion = 7055,
        .i2p = 76,
        .oldest_new = 1648720055,   // Thursday, March 31, 2022 at 09:47:35 UTC
        .youngest_new = 1745493722, // Thursday, April 24, 2025 at 11:22:02 UTC
        .oldest_tried = 1649527665, // Saturday, April 9, 2022 at 18:07:45 UTC
        .youngest_tried = 1745501514, // Thursday, April 24, 2025 at 13:31:54 UTC
        .bitprojects_new = 282,
        .bitprojects_tried = 3,
    };

    run(m_node, file);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(simulation_34019_20260624_cha, TestingSetup)
BOOST_AUTO_TEST_CASE(sim_20260624_cha)
{
    PeersDatFile file {
        .path = "../../../simulation_data/2026-06-24-cha-peers.dat",
        .asmap = false,
        .new_ = 65532,
        .tried = 9991,
        .ipv4 = 63520,
        .ipv6 = 12003,
        .onion = 0,
        .i2p = 0,
        .oldest_new = 1774752084,   // Thursday, March 31, 2022 at 09:47:35 UTC
        .youngest_new = 1782296956, // Thursday, April 24, 2025 at 11:22:02 UTC
        .oldest_tried = 1745608873, // Saturday, April 9, 2022 at 18:07:45 UTC
        .youngest_tried = 1782296499, // Thursday, April 24, 2025 at 13:31:54 UTC
        .bitprojects_new = 2,
        .bitprojects_tried = 1295,
    };

    run(m_node, file);
}
BOOST_AUTO_TEST_SUITE_END()
