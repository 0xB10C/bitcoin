// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <holepunch.h>

#include <compat/compat.h>
#include <hash.h>
#include <logging.h>
#include <netbase.h>
#include <streams.h>

#include <algorithm>
#include <set>

namespace holepunch {

//! The address family of an IP address regardless of routability, NET_UNROUTABLE otherwise.
static Network Family(const CNetAddr& addr)
{
    if (addr.IsIPv4()) return NET_IPV4;
    if (addr.IsIPv6()) return NET_IPV6;
    return NET_UNROUTABLE;
}

std::string RoleName(Role role)
{
    return role == Role::INITIATOR ? "initiator" : "responder";
}

std::optional<PunchKey> PunchKey::FromAddress(const CAddress& addr, bool allow_local)
{
    if (!addr.IsPunchKey()) return std::nullopt;
    const std::vector<unsigned char> bytes{addr.GetAddrBytes()};
    if (bytes.size() != ADDR_PUNCHKEY_IPV4_SIZE && bytes.size() != ADDR_PUNCHKEY_IPV6_SIZE) return std::nullopt;
    const std::span<const unsigned char> address{bytes.data() + 1, bytes.size() - 1 - CPubKey::COMPRESSED_SIZE};
    const std::span<const unsigned char> pubkey_bytes{bytes.data() + bytes.size() - CPubKey::COMPRESSED_SIZE, CPubKey::COMPRESSED_SIZE};

    CNetAddr net_addr;
    if (bytes[0] == CNetAddr::BIP155Network::IPV4 && address.size() == ADDR_IPV4_SIZE) {
        in_addr ipv4;
        memcpy(&ipv4, address.data(), sizeof(ipv4));
        net_addr = CNetAddr{ipv4};
    } else if (bytes[0] == CNetAddr::BIP155Network::IPV6 && address.size() == ADDR_IPV6_SIZE) {
        in6_addr ipv6;
        memcpy(&ipv6, address.data(), sizeof(ipv6));
        net_addr = CNetAddr{ipv6};
        // An IPv4-mapped address is not an IPv6 endpoint (R-1.4).
        if (!net_addr.IsIPv6()) return std::nullopt;
    } else {
        return std::nullopt;
    }

    PunchKey key{.endpoint = CService{net_addr, addr.GetPort()}, .pubkey = CPubKey{pubkey_bytes}, .services = addr.nServices};
    if (!IsWellFormedEndpoint(key.endpoint)) return std::nullopt;
    if (!allow_local && !key.endpoint.IsRoutable()) return std::nullopt;
    if (!key.pubkey.IsCompressed() || !key.pubkey.IsFullyValid()) return std::nullopt;
    if (!(key.services & NODE_P2P_V2)) return std::nullopt;
    return key;
}

CAddress PunchKey::ToAddress(NodeSeconds time) const
{
    std::vector<uint8_t> bytes;
    if (endpoint.IsIPv4()) {
        in_addr ipv4;
        const bool ok{endpoint.GetInAddr(&ipv4)};
        assert(ok);
        bytes.push_back(CNetAddr::BIP155Network::IPV4);
        bytes.insert(bytes.end(), reinterpret_cast<const uint8_t*>(&ipv4), reinterpret_cast<const uint8_t*>(&ipv4) + sizeof(ipv4));
    } else {
        in6_addr ipv6;
        const bool ok{endpoint.GetIn6Addr(&ipv6)};
        assert(ok);
        bytes.push_back(CNetAddr::BIP155Network::IPV6);
        bytes.insert(bytes.end(), reinterpret_cast<const uint8_t*>(&ipv6), reinterpret_cast<const uint8_t*>(&ipv6) + sizeof(ipv6));
    }
    bytes.insert(bytes.end(), pubkey.begin(), pubkey.end());
    return CAddress{CService{CNetAddr::PunchKey(bytes), endpoint.GetPort()}, services, time};
}

std::vector<uint8_t> EncodeEndpoint(const CService& endpoint)
{
    DataStream ss;
    ss << CNetAddr::V2(endpoint);
    return {UCharCast(ss.data()), UCharCast(ss.data()) + ss.size()};
}

uint256 PairValue(const uint256& x, const uint256& block_hash, const CService& ep_a, const CService& ep_b)
{
    std::vector<uint8_t> first{EncodeEndpoint(ep_a)};
    std::vector<uint8_t> second{EncodeEndpoint(ep_b)};
    if (second < first) std::swap(first, second);
    HashWriter writer{TaggedHash("tcp-holepunch/pair")};
    writer << x << block_hash;
    writer.write(MakeByteSpan(first));
    writer.write(MakeByteSpan(second));
    return writer.GetSHA256();
}

Role RoleFor(const uint256& pair, const CPubKey& own, const CPubKey& other)
{
    const bool smaller_key_initiates{(pair.data()[31] & 1) == 0};
    const bool own_is_smaller{own < other};
    return own_is_smaller == smaller_key_initiates ? Role::INITIATOR : Role::RESPONDER;
}

//! Whether two endpoints name the same host: the same address, or with `by_endpoint` the same address and port.
static bool SameAddress(const CService& a, const CService& b, bool by_endpoint)
{
    return by_endpoint ? a == b : static_cast<const CNetAddr&>(a) == static_cast<const CNetAddr&>(b);
}

size_t Table::CountSource(const std::vector<unsigned char>& source) const
{
    return std::count_if(m_entries.begin(), m_entries.end(), [&](const Entry& e) { return e.source == source; });
}

template <typename Pred>
void Table::EvictOne(NodeClock::time_point now, Pred pred)
{
    std::vector<size_t> candidates;
    for (size_t i = 0; i < m_entries.size(); ++i) {
        if (!pred(m_entries[i])) continue;
        if (m_entries[i].Expired(now)) {
            m_entries.erase(m_entries.begin() + i);
            return;
        }
        candidates.push_back(i);
    }
    assert(!candidates.empty());
    m_entries.erase(m_entries.begin() + candidates[m_rng.randrange(candidates.size())]);
}

bool Table::Add(const std::vector<unsigned char>& source, const PunchKey& key, const uint256& secret, NodeClock::time_point now, bool allow_local)
{
    LOCK(m_mutex);
    for (Entry& entry : m_entries) {
        if (entry.key.endpoint == key.endpoint && entry.key.pubkey == key.pubkey) {
            // A refresh: last_seen moves, received_at stays (R-6.1).
            entry.key.services = key.services;
            entry.last_seen = now;
            return false;
        }
    }
    // The same board's entry for the same address under another key is replaced (R-6.1).
    std::erase_if(m_entries, [&](const Entry& e) { return e.source == source && SameAddress(e.key.endpoint, key.endpoint, allow_local); });

    if (CountSource(source) >= SOURCE_CAP) {
        EvictOne(now, [&](const Entry& e) { return e.source == source; });
    } else if (m_entries.size() >= TABLE_MAX) {
        std::map<std::vector<unsigned char>, size_t> sizes;
        for (const Entry& e : m_entries) ++sizes[e.source];
        const auto largest{std::max_element(sizes.begin(), sizes.end(), [](const auto& a, const auto& b) { return a.second < b.second; })->first};
        // An expired entry anywhere goes first, else a random one of the largest group.
        if (std::any_of(m_entries.begin(), m_entries.end(), [&](const Entry& e) { return e.Expired(now); })) {
            EvictOne(now, [](const Entry&) { return true; });
        } else {
            EvictOne(now, [&](const Entry& e) { return e.source == largest; });
        }
    }
    m_entries.push_back(Entry{.key = key, .secret = secret, .source = source, .received_at = now, .last_seen = now});
    return true;
}

std::vector<Entry> Table::Eligible(NodeClock::time_point now, NodeClock::time_point parent_time) const
{
    LOCK(m_mutex);
    std::vector<Entry> out;
    for (const Entry& e : m_entries) {
        if (!e.Expired(now) && e.received_at < parent_time) out.push_back(e);
    }
    return out;
}

void Table::Remove(const CService& endpoint, const CPubKey& pubkey)
{
    LOCK(m_mutex);
    std::erase_if(m_entries, [&](const Entry& e) { return e.key.endpoint == endpoint && e.key.pubkey == pubkey; });
}

void Table::Expire(NodeClock::time_point now)
{
    LOCK(m_mutex);
    std::erase_if(m_entries, [&](const Entry& e) { return e.Expired(now); });
}

size_t Table::Size() const
{
    LOCK(m_mutex);
    return m_entries.size();
}

std::map<std::vector<unsigned char>, size_t> Table::SizeBySource() const
{
    LOCK(m_mutex);
    std::map<std::vector<unsigned char>, size_t> sizes;
    for (const Entry& e : m_entries) ++sizes[e.source];
    return sizes;
}

std::optional<Board::Entry> Board::Store(NodeId visitor, const PunchKey& key, NodeClock::time_point now, bool allow_local)
{
    LOCK(m_mutex);
    // One entry per connection: a later element replaces it (R-5.6).
    std::erase_if(m_entries, [&](const Entry& e) { return e.visitor == visitor; });
    // One entry per address: a live one is never displaced, one in its grace period is (R-5.7).
    for (const Entry& e : m_entries) {
        if (SameAddress(e.key.endpoint, key.endpoint, allow_local) && e.Live()) return std::nullopt;
    }
    std::erase_if(m_entries, [&](const Entry& e) { return SameAddress(e.key.endpoint, key.endpoint, allow_local); });
    const Entry entry{.key = key, .time = std::chrono::time_point_cast<std::chrono::seconds>(now), .visitor = visitor, .closed_at = std::nullopt};
    m_entries.push_back(entry);
    return entry;
}

std::vector<Board::Entry> Board::LiveEntries() const
{
    LOCK(m_mutex);
    std::vector<Entry> live;
    for (const Entry& e : m_entries) {
        if (e.Live()) live.push_back(e);
    }
    return live;
}

void Board::Disconnected(NodeId visitor, NodeClock::time_point now)
{
    LOCK(m_mutex);
    for (Entry& e : m_entries) {
        if (e.visitor == visitor && e.Live()) e.closed_at = now;
    }
}

void Board::Expire(NodeClock::time_point now)
{
    LOCK(m_mutex);
    std::erase_if(m_entries, [&](const Entry& e) { return e.closed_at && now >= *e.closed_at + BOARD_GRACE; });
}

size_t Board::Size() const
{
    LOCK(m_mutex);
    return m_entries.size();
}

std::vector<std::string> FeatureFlagNames(uint32_t flags)
{
    std::vector<std::string> names;
    if (flags & FeatureData::FLAG_BOARD) names.push_back("BOARD");
    if (flags & FeatureData::FLAG_VISITOR) names.push_back("VISITOR");
    return names;
}

CService WildcardAddress(Network family, uint16_t port)
{
    if (family == NET_IPV4) {
        struct in_addr inaddr_any;
        inaddr_any.s_addr = htonl(INADDR_ANY);
        return CService{inaddr_any, port};
    }
    return CService{in6_addr(COMPAT_IN6ADDR_ANY_INIT), port};
}

//! Whether `port` can be bound on the wildcard address of every available family.
static bool PortIsFree(uint16_t port)
{
    for (const Network net : {NET_IPV4, NET_IPV6}) {
        // One socket at a time: a dual-stack [::] bind conflicts with a live 0.0.0.0 one.
        auto sock{CreateSock(net == NET_IPV4 ? AF_INET : AF_INET6, SOCK_STREAM, IPPROTO_TCP)};
        if (!sock) continue; // the family is not available here
        sockaddr_storage storage;
        socklen_t len{sizeof(storage)};
        if (!WildcardAddress(net, port).GetSockAddr(reinterpret_cast<sockaddr*>(&storage), &len)) return false;
        if (sock->Bind(reinterpret_cast<sockaddr*>(&storage), len) != 0) return false;
    }
    return true;
}

std::optional<uint16_t> PickRandomPunchPort(FastRandomContext& rng)
{
    for (int i = 0; i < 20; ++i) {
        const auto port{static_cast<uint16_t>(PUNCH_PORT_MIN + rng.randrange(PUNCH_PORT_MAX - PUNCH_PORT_MIN + 1))};
        if (IsBadPort(port)) continue;
        if (PortIsFree(port)) return port;
    }
    return std::nullopt;
}

bool IsWellFormedEndpoint(const CService& endpoint)
{
    // Unknown BIP 155 network ids and IPv4-mapped IPv6 addresses (R-1.4) both
    // deserialize as the unspecified address ::, which is never a usable endpoint.
    return (endpoint.IsIPv4() || endpoint.IsIPv6()) && !endpoint.IsBindAny() && endpoint.GetPort() != 0;
}

bool ExternalAddressTracker::AddReport(NodeId id, const std::vector<unsigned char>& group, const CService& reported, bool allow_local)
{
    if (Family(reported) == NET_UNROUTABLE) return false;
    if (reported.GetPort() == 0) return false;
    if (!allow_local && !reported.IsRoutable()) return false;

    Report report{group, reported};
    if (allow_local) {
        // Each peer counts as its own network group (R-2.5).
        report.group.clear();
        for (int i = 0; i < 8; ++i) report.group.push_back(static_cast<unsigned char>(id >> (8 * i)));
    }

    LOCK(m_mutex);
    m_reports[id] = std::move(report);
    LogDebug(BCLog::HOLEPUNCH, "peer=%d reports our address as %s\n", id, reported.ToStringAddrPort());
    return true;
}

void ExternalAddressTracker::RemovePeer(NodeId id)
{
    LOCK(m_mutex);
    m_reports.erase(id);
}

std::optional<CService> ExternalAddressTracker::Get(Network net) const
{
    return GetInfo(net).address;
}

ExternalAddressTracker::Info ExternalAddressTracker::GetInfo(Network net) const
{
    Info info;
    // For every reported address: the distinct groups reporting it and how many peers do.
    struct Agreement {
        std::set<std::vector<unsigned char>> groups;
        size_t reporters{0};
    };
    std::map<CService, Agreement> by_addr;
    {
        LOCK(m_mutex);
        for (const auto& [id, report] : m_reports) {
            if (Family(report.addr) != net) continue;
            auto& agreement = by_addr[report.addr];
            agreement.groups.insert(report.group);
            ++agreement.reporters;
            ++info.reports;
        }
    }
    // An address agreed on by two distinct groups is a candidate (R-2.2). One candidate
    // is the external address; two or more mean the mapping is not endpoint-independent
    // or there are several external addresses (R-2.3).
    for (const auto& [addr, agreement] : by_addr) {
        if (agreement.groups.size() < 2) continue;
        if (info.address) {
            info.conflicting = true;
            info.address.reset();
            info.reporters = 0;
            break;
        }
        info.address = addr;
        info.reporters = agreement.reporters;
    }
    return info;
}

} // namespace holepunch
