// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETSIM_ADDRESSES_H
#define BITCOIN_NETSIM_ADDRESSES_H

#include <netaddress.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

namespace netsim {

/** A synthetic set of node addresses.
 *
 * Two things about a population's addresses change what Core does, and both
 * are configurable here.
 *
 * **Which networks they are on.** The ladder in `ThreadOpenConnections` treats
 * Tor and I2P peers differently from IPv4 and IPv6 ones: they are counted as
 * `privacy_network_peers` rather than joining the netgroup diversity set,
 * because `NetGroupManager::GetGroup` gives onion and I2P addresses only four
 * bits of group, so diversity there is meaningless. `MaybePickPreferredNetwork`
 * exists to put one outbound peer on every reachable network and can never
 * fire in a single-network population.
 *
 * **How they share netgroups.** An outbound connection is only opened to an
 * address whose netgroup differs from every existing outbound peer, and with no
 * asmap loaded that is a /16 for IPv4 and a /32 for IPv6. One node per netgroup
 * is the most favourable case Core will ever see; mainnet is not like that.
 *
 * Defaults stay IPv4-only with one node per /16, which is what every
 * measurement recorded so far used. `Options::mainnet_mix` and
 * `Options::mainnet_netgroups` switch to the measured shape.
 */
class AddressUniverse
{
public:
    /** The networks a simulated address can be on. */
    enum class Net : uint8_t {
        IPv4,
        IPv6,
        Onion,
        I2P,
    };
    static constexpr size_t NUM_NETS{4};

    struct Options {
        uint32_t num_nodes{100};
        /** Port every address carries. See Network::Options::port. */
        uint16_t port{0};

        /** Relative weight of each network, held as node counts rather than
         *  percentages so a measured snapshot pastes in directly. All-zero
         *  except IPv4 means an IPv4-only population. */
        uint32_t weight_ipv4{1};
        uint32_t weight_ipv6{0};
        uint32_t weight_onion{0};
        uint32_t weight_i2p{0};

        /** Draw /16 and /32 occupancy from the measured mainnet distribution
         *  instead of giving every node a netgroup of its own. */
        bool mainnet_netgroups{false};

        uint256 seed{uint256{1}};

        /** Set the four weights to the measured mainnet shares.
         *
         * From a btcnodes.io snapshot taken 2026-10-21 covering 25,636
         * reachable nodes: Tor 12,612, IPv4 7,514, I2P 4,288, IPv6 1,222. Tor
         * is half the reachable network and IPv4 under a third, which is the
         * opposite of what an IPv4-only simulation implies.
         */
        void UseMainnetMix();
    };

    explicit AddressUniverse(const Options& opts);
    /** IPv4-only, one node per /16. The historical behaviour. */
    AddressUniverse(uint32_t num_nodes, uint16_t port);

    uint32_t Size() const { return static_cast<uint32_t>(m_addrs.size()); }

    const CService& At(uint32_t node) const;
    /** Which network node `node` is on. */
    Net NetOf(uint32_t node) const;
    /** How many addresses landed on `net`. */
    uint32_t CountOn(Net net) const;

    static const char* NetName(Net net);

private:
    std::vector<CService> m_addrs;
    std::vector<Net> m_nets;
    uint32_t m_counts[NUM_NETS]{};
};

} // namespace netsim

#endif // BITCOIN_NETSIM_ADDRESSES_H
