// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netsim/addresses.h>

#include <compat/compat.h>
#include <netaddress.h>
#include <util/check.h>

#include <cstring>

namespace netsim {

namespace {
//! First octets to walk. 224 and above is multicast or reserved.
constexpr unsigned FIRST_OCTET_MIN{1};
constexpr unsigned FIRST_OCTET_COUNT{223};
constexpr unsigned SECOND_OCTET_COUNT{256};
} // namespace

AddressUniverse::AddressUniverse(uint32_t num_nodes, uint16_t port)
{
    m_addrs.reserve(num_nodes);

    // Walk candidate a.b.1.h addresses and keep the ones Core itself considers
    // routable. Asking IsRoutable() is deliberate: reimplementing the list of
    // reserved ranges here would be one more thing to keep in sync.
    for (uint64_t i{0}; m_addrs.size() < num_nodes; ++i) {
        const auto a{static_cast<unsigned char>(FIRST_OCTET_MIN + (i / SECOND_OCTET_COUNT) % FIRST_OCTET_COUNT)};
        const auto b{static_cast<unsigned char>(i % SECOND_OCTET_COUNT)};
        const uint64_t prefix_cycle{i / (SECOND_OCTET_COUNT * FIRST_OCTET_COUNT)};
        Assert(prefix_cycle < 254);
        const auto host{static_cast<unsigned char>(1 + prefix_cycle)};

        // Network byte order is a.b.1.host, so write the octets directly
        // rather than going through htonl.
        const unsigned char octets[4]{a, b, 1, host};
        struct in_addr ip4{};
        std::memcpy(&ip4.s_addr, octets, sizeof(octets));

        const CService candidate{CNetAddr{ip4}, port};
        if (candidate.IsRoutable()) m_addrs.push_back(candidate);
    }
}

const CService& AddressUniverse::At(uint32_t node) const
{
    Assert(node < m_addrs.size());
    return m_addrs[node];
}

} // namespace netsim
