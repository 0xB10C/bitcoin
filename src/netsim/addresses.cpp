// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netsim/addresses.h>

#include <compat/compat.h>
#include <crypto/sha3.h>
#include <hash.h>
#include <netaddress.h>
#include <random.h>
#include <util/check.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <set>
#include <string>
#include <vector>

namespace netsim {

namespace {
//! First octets to walk for IPv4. 224 and above is multicast or reserved.
constexpr unsigned FIRST_OCTET_MIN{1};
constexpr unsigned FIRST_OCTET_COUNT{223};
constexpr unsigned SECOND_OCTET_COUNT{256};
//! Usable host values in an octet, excluding .0 and .255.
constexpr unsigned HOSTS_PER_OCTET{254};

//! Domain separators for the derived keys.
const std::string SEED_ONION{"netsim/addr/onion"};
const std::string SEED_I2P{"netsim/addr/i2p"};
const std::string SEED_GROUPS{"netsim/addr/groups"};

uint256 DeriveHash(const std::string& domain, const uint256& seed, uint32_t index = 0)
{
    HashWriter writer{};
    writer << domain << seed << index;
    return writer.GetHash();
}

std::span<const unsigned char> Bytes(const uint256& value)
{
    return {value.data(), value.size()};
}

/** How many nodes sit in each netgroup on mainnet, as a histogram.
 *
 * Measured from a btcnodes.io snapshot taken 2026-10-21: 7,514 IPv4 nodes in
 * 4,236 distinct /16s and 1,222 IPv6 nodes in 384 distinct /32s. Each entry is
 * (nodes in the group, how many groups had that many).
 *
 * The shape, not the scale, is what is reused: both distributions are a long
 * tail of singletons under a short, heavy head, and it is the head that
 * decides whether Core's outbound netgroup rule has anything to bite on. IPv4
 * is 72% singletons with a top group of 107; IPv6 is 70% singletons but three
 * times as concentrated overall, its top /32 holding 156 of 1,222 nodes.
 */
struct GroupSize {
    uint32_t nodes;
    uint32_t groups;
};

constexpr GroupSize MAINNET_IPV4_GROUPS[]{
    {1, 3030}, {2, 727}, {3, 242}, {4, 70}, {5, 39}, {6, 27}, {7, 26}, {8, 15},
    {9, 6}, {10, 9}, {11, 10}, {12, 6}, {13, 1}, {14, 1}, {15, 4}, {16, 2},
    {18, 3}, {19, 2}, {21, 3}, {22, 1}, {24, 1}, {28, 2}, {31, 1}, {33, 1},
    {71, 1}, {77, 1}, {78, 1}, {84, 1}, {90, 1}, {92, 1}, {107, 1},
};

constexpr GroupSize MAINNET_IPV6_GROUPS[]{
    {1, 269}, {2, 56}, {3, 21}, {4, 6}, {5, 7}, {6, 6}, {7, 3}, {10, 1},
    {11, 3}, {15, 1}, {18, 1}, {21, 1}, {22, 1}, {25, 1}, {32, 1}, {33, 1},
    {35, 1}, {62, 1}, {93, 1}, {107, 1}, {156, 1},
};

/** Occupancy for as many netgroups as it takes to hold `nodes` addresses.
 *
 * Group sizes are drawn independently from the empirical distribution — the
 * chance of drawing a group of `s` nodes is the share of mainnet groups that
 * held `s` nodes — until the population is placed. Drawing rather than
 * replaying the histogram in order is what makes this work at any scale: a
 * 200-node population is then a plausible random subsample of mainnet's
 * groups, usually all small ones, while a 20,000-node population picks up the
 * heavy head with about the frequency mainnet has it.
 *
 * With `real == false` every group holds one node, which is the historical
 * behaviour and the most favourable case Core's outbound diversity rule will
 * ever see.
 */
std::vector<uint32_t> GroupOccupancy(uint32_t nodes, std::span<const GroupSize> histogram,
                                     bool real, FastRandomContext& rng)
{
    std::vector<uint32_t> sizes;
    if (nodes == 0) return sizes;
    if (!real) {
        sizes.assign(nodes, 1);
        return sizes;
    }

    uint64_t total_groups{0};
    for (const GroupSize& entry : histogram) total_groups += entry.groups;
    Assert(total_groups > 0);

    uint32_t placed{0};
    while (placed < nodes) {
        uint64_t draw{rng.randrange(total_groups)};
        uint32_t size{1};
        for (const GroupSize& entry : histogram) {
            if (draw < entry.groups) {
                size = entry.nodes;
                break;
            }
            draw -= entry.groups;
        }
        // The last group is truncated rather than allowed to overshoot, so the
        // population is exactly the size that was asked for.
        sizes.push_back(std::min(size, nodes - placed));
        placed += sizes.back();
    }
    return sizes;
}

/** The first `count` routable /16 prefixes, as (first octet, second octet).
 *
 * Asking `IsRoutable()` rather than reimplementing the list of reserved ranges
 * is deliberate: that list is one more thing that would need keeping in sync.
 */
std::vector<std::pair<unsigned char, unsigned char>> RoutablePrefixes(size_t count)
{
    std::vector<std::pair<unsigned char, unsigned char>> out;
    out.reserve(count);
    for (uint64_t i{0}; out.size() < count; ++i) {
        const auto a{static_cast<unsigned char>(FIRST_OCTET_MIN + (i / SECOND_OCTET_COUNT) % FIRST_OCTET_COUNT)};
        const auto b{static_cast<unsigned char>(i % SECOND_OCTET_COUNT)};
        Assert(i < uint64_t{FIRST_OCTET_COUNT} * SECOND_OCTET_COUNT);

        const unsigned char octets[4]{a, b, 1, 1};
        struct in_addr probe{};
        std::memcpy(&probe.s_addr, octets, sizeof(octets));
        if (CNetAddr{probe}.IsRoutable()) out.emplace_back(a, b);
    }
    return out;
}

/** The `host`th address inside the /16 named by `prefix`. */
CService MakeIPv4(std::pair<unsigned char, unsigned char> prefix, uint32_t host, uint16_t port)
{
    const auto c{static_cast<unsigned char>(1 + host / HOSTS_PER_OCTET)};
    const auto d{static_cast<unsigned char>(1 + host % HOSTS_PER_OCTET)};
    // Network byte order is a.b.c.d, so write the octets directly rather than
    // going through htonl.
    const unsigned char octets[4]{prefix.first, prefix.second, c, d};
    struct in_addr ip4{};
    std::memcpy(&ip4.s_addr, octets, sizeof(octets));
    return CService{CNetAddr{ip4}, port};
}

/** The `host`th address inside the `group`th /32.
 *
 * Built inside 2a00::/8, which is real RIPE global unicast space. The choice
 * is not cosmetic: 2001:db8::/32 is documentation space and Core calls it
 * unroutable, 2001:470::/32 is he.net and gets /36 groups instead of /32, and
 * 2002::/16 and 2001::/32 are 6to4 and Teredo, which `GetGroup` unwraps to the
 * encapsulated IPv4 address.
 */
CService MakeIPv6(uint32_t group, uint32_t host, uint16_t port)
{
    Assert(group < 0x10000u * 0x100u);
    unsigned char bytes[16]{};
    bytes[0] = 0x2a;
    bytes[1] = static_cast<unsigned char>(group >> 16);
    bytes[2] = static_cast<unsigned char>(group >> 8);
    bytes[3] = static_cast<unsigned char>(group);
    // Host bits well inside the interface identifier, so the /32 is the group.
    bytes[12] = static_cast<unsigned char>(host >> 24);
    bytes[13] = static_cast<unsigned char>(host >> 16);
    bytes[14] = static_cast<unsigned char>(host >> 8);
    bytes[15] = static_cast<unsigned char>(host);
    // Never the all-zero interface identifier, which is the subnet-router
    // anycast address.
    if (host == 0) bytes[15] = 1;

    struct in6_addr ip6{};
    std::memcpy(&ip6, bytes, sizeof(bytes));
    return CService{CNetAddr{ip6}, port};
}

/** A base32 onion v3 address for `key`, as Core's parser accepts it. */
std::string OnionString(const uint256& key)
{
    // TORv3 address = base32(PUBKEY | CHECKSUM | VERSION) where
    // CHECKSUM = SHA3-256(".onion checksum" | PUBKEY | VERSION)[:2]. Nothing
    // here is a real Tor key, but the checksum has to be right or SetSpecial
    // rejects it, and going through SetSpecial is the point: the simulator
    // then holds whatever Core's own parser produced.
    static const std::array<unsigned char, 15> PREFIX{
        '.', 'o', 'n', 'i', 'o', 'n', ' ', 'c', 'h', 'e', 'c', 'k', 's', 'u', 'm'};
    static const std::array<unsigned char, 1> VERSION{3};

    SHA3_256 hasher;
    hasher.Write(PREFIX);
    hasher.Write(Bytes(key));
    hasher.Write(VERSION);
    std::array<unsigned char, SHA3_256::OUTPUT_SIZE> digest{};
    hasher.Finalize(digest);

    std::vector<unsigned char> payload;
    payload.reserve(35);
    payload.insert(payload.end(), key.begin(), key.end());
    payload.push_back(digest[0]);
    payload.push_back(digest[1]);
    payload.push_back(VERSION[0]);

    // 35 bytes is 56 base32 characters exactly, so no padding is produced.
    return EncodeBase32(payload) + ".onion";
}

/** A base32 I2P address for `key`. */
std::string I2PString(const uint256& key)
{
    // 32 bytes encode to 52 characters plus four '=' of padding, and Core's
    // parser wants the 52 without it.
    const std::string encoded{EncodeBase32(Bytes(key))};
    Assert(encoded.size() == 56);
    return encoded.substr(0, 52) + ".b32.i2p";
}
} // namespace

void AddressUniverse::Options::UseMainnetMix()
{
    weight_ipv4 = 7514;
    weight_ipv6 = 1222;
    weight_onion = 12612;
    weight_i2p = 4288;
}

const char* AddressUniverse::NetName(Net net)
{
    switch (net) {
    case Net::IPv4: return "ipv4";
    case Net::IPv6: return "ipv6";
    case Net::Onion: return "onion";
    case Net::I2P: return "i2p";
    }
    Assume(false);
    return "unknown";
}

AddressUniverse::AddressUniverse(uint32_t num_nodes, uint16_t port)
    : AddressUniverse{[&] {
          Options opts;
          opts.num_nodes = num_nodes;
          opts.port = port;
          return opts;
      }()}
{
}

AddressUniverse::AddressUniverse(const Options& opts)
{
    const uint32_t weights[NUM_NETS]{opts.weight_ipv4, opts.weight_ipv6,
                                     opts.weight_onion, opts.weight_i2p};
    uint64_t total_weight{0};
    for (const uint32_t w : weights) total_weight += w;
    Assert(total_weight > 0);

    // Assign a network to each node id by largest-remainder apportionment,
    // walked in id order. That interleaves the networks rather than laying
    // them end to end, which matters because the first ids are the listeners:
    // a block layout would make every listener IPv4.
    m_nets.reserve(opts.num_nodes);
    {
        // Signed: the winner's credit goes negative, which is what makes the
        // other networks catch up on the following steps.
        int64_t credit[NUM_NETS]{};
        for (uint32_t id{0}; id < opts.num_nodes; ++id) {
            size_t best{0};
            int64_t best_credit{std::numeric_limits<int64_t>::min()};
            for (size_t n{0}; n < NUM_NETS; ++n) {
                if (weights[n] == 0) continue;
                credit[n] += weights[n];
                if (credit[n] > best_credit) {
                    best_credit = credit[n];
                    best = n;
                }
            }
            credit[best] -= static_cast<int64_t>(total_weight);
            m_nets.push_back(static_cast<Net>(best));
            ++m_counts[best];
        }
    }

    FastRandomContext rng{DeriveHash(SEED_GROUPS, opts.seed)};
    const auto ipv4_groups{GroupOccupancy(m_counts[size_t(Net::IPv4)], MAINNET_IPV4_GROUPS,
                                          opts.mainnet_netgroups, rng)};
    const auto ipv6_groups{GroupOccupancy(m_counts[size_t(Net::IPv6)], MAINNET_IPV6_GROUPS,
                                          opts.mainnet_netgroups, rng)};

    const auto v4_prefixes{RoutablePrefixes(ipv4_groups.size())};

    // Walking position within each network's group list.
    size_t v4_group{0}, v6_group{0};
    uint32_t v4_in_group{0}, v6_in_group{0};
    uint32_t net_index[NUM_NETS]{};

    m_addrs.reserve(opts.num_nodes);
    for (uint32_t id{0}; id < opts.num_nodes; ++id) {
        const Net net{m_nets[id]};
        const uint32_t index{net_index[size_t(net)]++};

        switch (net) {
        case Net::IPv4: {
            if (v4_in_group >= ipv4_groups[v4_group]) {
                ++v4_group;
                v4_in_group = 0;
            }
            m_addrs.push_back(MakeIPv4(v4_prefixes[v4_group], v4_in_group, opts.port));
            ++v4_in_group;
            break;
        }
        case Net::IPv6: {
            if (v6_in_group >= ipv6_groups[v6_group]) {
                ++v6_group;
                v6_in_group = 0;
            }
            m_addrs.push_back(MakeIPv6(static_cast<uint32_t>(v6_group), v6_in_group, opts.port));
            ++v6_in_group;
            break;
        }
        case Net::Onion:
        case Net::I2P: {
            // No grouping to arrange: GetGroup gives these four bits taken
            // from the address itself, so the netgroup is whatever the derived
            // key happens to produce, exactly as on the real network.
            const uint256 key{DeriveHash(net == Net::Onion ? SEED_ONION : SEED_I2P, opts.seed, index)};
            CNetAddr addr;
            const bool ok{addr.SetSpecial(net == Net::Onion ? OnionString(key) : I2PString(key))};
            Assert(ok);
            m_addrs.emplace_back(addr, opts.port);
            break;
        }
        }
        Assert(m_addrs.back().IsRoutable());
    }
}

const CService& AddressUniverse::At(uint32_t node) const
{
    Assert(node < m_addrs.size());
    return m_addrs[node];
}

AddressUniverse::Net AddressUniverse::NetOf(uint32_t node) const
{
    Assert(node < m_nets.size());
    return m_nets[node];
}

uint32_t AddressUniverse::CountOn(Net net) const
{
    return m_counts[size_t(net)];
}

} // namespace netsim
