// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <holepunch.h>

#include <logging.h>
#include <serialize.h>
#include <util/log.h>

#include <set>

namespace holepunch {

//! The address family of an IP address regardless of routability, NET_UNROUTABLE otherwise.
static Network Family(const CNetAddr& addr)
{
    if (addr.IsIPv4()) return NET_IPV4;
    if (addr.IsIPv6()) return NET_IPV6;
    return NET_UNROUTABLE;
}

std::vector<std::string> CapNames(uint32_t caps)
{
    std::vector<std::string> names;
    if (caps & CAP_COORDINATOR) names.push_back("COORDINATOR");
    if (caps & CAP_ADVERTISED) names.push_back("ADVERTISED");
    if (caps & CAP_POOL_OK) names.push_back("POOL_OK");
    if (caps & CAP_HANDOFF_OK) names.push_back("HANDOFF_OK");
    if (caps & CAP_PUNCHPORT) names.push_back("PUNCHPORT");
    return names;
}

bool IsWellFormedEndpoint(const CService& endpoint)
{
    // Unknown BIP 155 network ids and IPv4-mapped IPv6 addresses (R-1.4) both
    // deserialize as the unspecified address ::, which is never a usable endpoint.
    return (endpoint.IsIPv4() || endpoint.IsIPv6()) && !endpoint.IsBindAny();
}

bool RendezvousMsg::IsWellFormed() const
{
    return IsWellFormedEndpoint(target) && IsWellFormedEndpoint(requester) && Family(target) == Family(requester);
}

bool PunchMsg::IsWellFormed() const
{
    return (role == static_cast<uint8_t>(Role::RESPONDER) || role == static_cast<uint8_t>(Role::INITIATOR)) && IsWellFormedEndpoint(peer);
}

bool ExternalAddressTracker::AddReport(NodeId id, const std::vector<unsigned char>& group, const CService& reported)
{
    if (Family(reported) == NET_UNROUTABLE) return false;
    if (reported.GetPort() == 0) return false;
    if (!m_allow_local && !reported.IsRoutable()) return false;

    Report report{group, reported};
    if (m_allow_local) {
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
