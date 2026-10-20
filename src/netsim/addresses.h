// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETSIM_ADDRESSES_H
#define BITCOIN_NETSIM_ADDRESSES_H

#include <netaddress.h>

#include <cstdint>
#include <vector>

namespace netsim {

/** A synthetic set of node addresses.
 *
 * Every node gets a routable IPv4 address, and consecutive nodes land in
 * distinct /16s for as long as the space allows.
 *
 * The distinct-netgroup property is the point. An outbound connection is only
 * opened to an address whose netgroup differs from every existing outbound
 * peer, and with no asmap loaded NetGroupManager groups IPv4 by /16. A
 * population crowded into a handful of netgroups cannot fill its outbound
 * slots, and the topology you then measure is an artefact of the address
 * generator rather than a property of Bitcoin Core.
 *
 * There are only 65536 /16s in total, so a population larger than that reuses
 * prefixes with different host parts. That is realistic in any case, since
 * real networks carry many nodes per /16.
 */
class AddressUniverse
{
public:
    /** Generate `num_nodes` addresses, all bearing `port`. */
    AddressUniverse(uint32_t num_nodes, uint16_t port);

    uint32_t Size() const { return static_cast<uint32_t>(m_addrs.size()); }

    const CService& At(uint32_t node) const;

private:
    std::vector<CService> m_addrs;
};

} // namespace netsim

#endif // BITCOIN_NETSIM_ADDRESSES_H
