// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <holepunch.h>

#include <compat/compat.h>
#include <logging.h>
#include <netbase.h>
#include <serialize.h>
#include <tinyformat.h>
#include <util/log.h>
#include <util/thread.h>

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
        if (IsBadPort(port) || IsBadPort(port + 1)) continue;
        if (PortIsFree(port) && PortIsFree(port + 1)) return port;
    }
    return std::nullopt;
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

std::optional<Announcement> AnnouncementCache::Add(NodeId from, const CAddress& element, NodeClock::time_point now, bool allow_local)
{
    if (!element.IsHolePunch() || !element.IsValid()) return std::nullopt;
    const auto coordinator{element.HolePunchCoordinator()};
    const auto target{element.HolePunchTarget()};
    if (!coordinator || !target) return std::nullopt;
    if (!allow_local && !element.IsRoutable()) return std::nullopt;
    if (element.GetPort() == 0) return std::nullopt;
    // Same freshness window as address relay (R-6.3).
    const auto now_s{std::chrono::time_point_cast<std::chrono::seconds>(now)};
    if (element.nTime <= now_s - std::chrono::minutes{10} || element.nTime > now_s + std::chrono::minutes{10}) return std::nullopt;

    Announcement announcement{
        .coordinator = *coordinator,
        .target = CService{*target, element.GetPort()},
        .services = element.nServices,
        .time = element.nTime,
        .from = from,
    };
    LOCK(m_mutex);
    Expire(now);
    // A newer element for the same pair replaces the old one.
    std::erase_if(m_entries, [&](const Announcement& a) { return a.coordinator == announcement.coordinator && a.target == announcement.target; });
    const size_t from_peer{static_cast<size_t>(std::ranges::count_if(m_entries, [&](const Announcement& a) { return a.from == from; }))};
    if (from_peer >= CACHE_PER_PEER) return std::nullopt;
    if (m_entries.size() >= CACHE_MAX) m_entries.erase(m_entries.begin());
    m_entries.push_back(announcement);
    return announcement;
}

void AnnouncementCache::Expire(NodeClock::time_point now)
{
    const auto now_s{std::chrono::time_point_cast<std::chrono::seconds>(now)};
    std::erase_if(m_entries, [&](const Announcement& a) { return a.time + CACHE_TTL <= now_s; });
}

std::vector<Announcement> AnnouncementCache::Get(NodeClock::time_point now) const
{
    LOCK(m_mutex);
    const auto now_s{std::chrono::time_point_cast<std::chrono::seconds>(now)};
    std::vector<Announcement> live;
    for (const auto& a : m_entries) {
        if (a.time + CACHE_TTL > now_s) live.push_back(a);
    }
    return live;
}

std::optional<Announcement> AnnouncementCache::Take(NodeClock::time_point now, const std::function<bool(const Announcement&)>& eligible, FastRandomContext& rng)
{
    LOCK(m_mutex);
    Expire(now);
    std::vector<size_t> candidates;
    for (size_t i = 0; i < m_entries.size(); ++i) {
        if (eligible(m_entries[i])) candidates.push_back(i);
    }
    if (candidates.empty()) return std::nullopt;
    const size_t index{candidates[rng.randrange(candidates.size())]};
    Announcement taken{m_entries[index]};
    m_entries.erase(m_entries.begin() + index);
    return taken;
}

size_t AnnouncementCache::Size() const
{
    LOCK(m_mutex);
    return m_entries.size();
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

static const char* RoleName(Role role)
{
    return role == Role::INITIATOR ? "initiator" : "responder";
}

SessionManager::SessionManager(const Options& opts, ResultFn on_result)
    : m_opts{opts}, m_on_result{std::move(on_result)}
{
}

SessionManager::~SessionManager()
{
    Stop();
}

bool SessionManager::Start()
{
    for (const Network family : {NET_IPV4, NET_IPV6}) {
        const CService addr{WildcardAddress(family, m_opts.port)};
        auto sock{CreateSock(addr.GetSAFamily(), SOCK_STREAM, IPPROTO_TCP)};
        if (!sock) {
            LogDebug(BCLog::HOLEPUNCH, "cannot create punch listener socket for %s\n", addr.ToStringAddrPort());
            continue;
        }
#ifdef IPV6_V6ONLY
        if (family == NET_IPV6) {
            const int one{1};
            if (sock->SetSockOpt(IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) == SOCKET_ERROR) {
                LogDebug(BCLog::HOLEPUNCH, "cannot set IPV6_V6ONLY on punch listener: %s\n", NetworkErrorString(WSAGetLastError()));
            }
        }
#endif
        if (!BindToSharedPort(*sock, addr)) continue;
        if (sock->Listen(SOMAXCONN) == SOCKET_ERROR) {
            LogDebug(BCLog::HOLEPUNCH, "cannot listen on punch port %s: %s\n", addr.ToStringAddrPort(), NetworkErrorString(WSAGetLastError()));
            continue;
        }
        LogInfo("Hole punching: listening on %s", addr.ToStringAddrPort());
        m_listeners.push_back(std::move(sock));
    }
    if (m_listeners.empty()) {
        LogWarning("Hole punching: could not open a punch listener on port %d", m_opts.port);
        return false;
    }
    m_thread = std::thread(&util::TraceThread, "holepunch", [this] { ThreadLoop(); });
    return true;
}

void SessionManager::Stop()
{
    m_interrupt();
    if (m_thread.joinable()) m_thread.join();
    m_listeners.clear();
    LOCK(m_mutex);
    m_sessions.clear();
    m_held.clear();
}

CService SessionManager::AddrKey(const CService& peer) const
{
    // On test networks every node has the same address, so limit per endpoint there.
    return m_opts.allow_local ? peer : CService{peer, 0};
}

std::optional<std::string> SessionManager::Punch(Role role, const CService& peer)
{
    const auto now{NodeClock::now()};
    LOCK(m_mutex);
    if (m_sessions.contains(peer)) return "a session with this peer exists";
    if (m_sessions.size() >= MAX_ACTIVE_SESSIONS) return strprintf("%d sessions are active", m_sessions.size());
    while (!m_recent_starts.empty() && m_recent_starts.front() + std::chrono::minutes{1} <= now) m_recent_starts.pop_front();
    if (m_recent_starts.size() >= SESSIONS_PER_MIN) return strprintf("%d sessions were started in the last minute", m_recent_starts.size());
    if (const auto it{m_last_start.find(AddrKey(peer))}; it != m_last_start.end() && it->second + PER_ADDR_INTERVAL > now) {
        return "a session with this address was started recently";
    }
    // Pruning: forget addresses whose interval is over.
    std::erase_if(m_last_start, [&](const auto& entry) { return entry.second + PER_ADDR_INTERVAL <= now; });

    m_recent_starts.push_back(now);
    m_last_start[AddrKey(peer)] = now;
    m_sessions.emplace(peer, Session{.role = role, .peer = peer, .started = now, .deadline = now + WINDOW, .next_attempt = now, .attempt = nullptr, .attempts = 0, .wait_for_accept = false});
    LogDebug(BCLog::HOLEPUNCH, "session with %s started as %s\n", peer.ToStringAddrPort(), RoleName(role));
    return std::nullopt;
}

bool SessionManager::HasSession(const CService& peer) const
{
    LOCK(m_mutex);
    return m_sessions.contains(peer);
}

void SessionManager::Cancel(const CService& peer)
{
    LOCK(m_mutex);
    const auto it{m_sessions.find(peer)};
    if (it == m_sessions.end()) return;
    LogDebug(BCLog::HOLEPUNCH, "session with %s cancelled as %s after %d attempt(s)\n", peer.ToStringAddrPort(), RoleName(it->second.role), it->second.attempts);
    m_sessions.erase(it);
}

std::vector<SessionManager::SessionInfo> SessionManager::GetSessions() const
{
    std::vector<SessionInfo> infos;
    LOCK(m_mutex);
    for (const auto& [peer, session] : m_sessions) {
        infos.push_back({.peer = peer, .role = session.role, .started = session.started, .attempts = session.attempts});
    }
    return infos;
}

void SessionManager::Finish(const CService& peer, std::shared_ptr<Sock> sock, std::vector<Result>& results)
{
    const auto it{m_sessions.find(peer)};
    if (it == m_sessions.end()) return;
    Session& session{it->second};
    if (sock) {
        LogDebug(BCLog::HOLEPUNCH, "session with %s established as %s after %d attempt(s)\n", peer.ToStringAddrPort(), RoleName(session.role), session.attempts);
    } else {
        LogDebug(BCLog::HOLEPUNCH, "session with %s failed as %s after %d attempt(s)\n", peer.ToStringAddrPort(), RoleName(session.role), session.attempts);
    }
    results.push_back({.peer = peer, .role = session.role, .sock = std::move(sock), .deadline = session.deadline + GRACE});
    m_sessions.erase(it);
}

void SessionManager::StartAttempt(Session& session, NodeClock::time_point now)
{
    const CService& peer{session.peer};
    ++session.attempts;
    auto sock{CreateSock(peer.GetSAFamily(), SOCK_STREAM, IPPROTO_TCP)};
    if (!sock) {
        LogDebug(BCLog::HOLEPUNCH, "cannot create socket for attempt %d to %s\n", session.attempts, peer.ToStringAddrPort());
        session.next_attempt = now + RETRY;
        return;
    }
    const CService local{WildcardAddress(peer.IsIPv4() ? NET_IPV4 : NET_IPV6, m_opts.port)};
    if (!BindToSharedPort(*sock, local)) {
        session.next_attempt = now + RETRY;
        return;
    }
    sockaddr_storage storage;
    socklen_t len{sizeof(storage)};
    if (!peer.GetSockAddr(reinterpret_cast<sockaddr*>(&storage), &len)) {
        session.next_attempt = now + RETRY;
        return;
    }
    if (sock->Connect(reinterpret_cast<sockaddr*>(&storage), len) == SOCKET_ERROR) {
        const int err{WSAGetLastError()};
        if (err != WSAEINPROGRESS && err != WSAEWOULDBLOCK && err != WSAEINVAL) {
            if (err == WSAEADDRINUSE || err == WSAEADDRNOTAVAIL) {
                // The 4-tuple exists already: the listener accepted the peer's connection (R-5.6).
                LogDebug(BCLog::HOLEPUNCH, "attempt %d to %s: connection exists, waiting for the listener\n", session.attempts, peer.ToStringAddrPort());
                session.wait_for_accept = true;
            } else {
                LogDebug(BCLog::HOLEPUNCH, "attempt %d to %s failed: %s\n", session.attempts, peer.ToStringAddrPort(), NetworkErrorString(err));
                session.next_attempt = now + RETRY;
            }
            return;
        }
    }
    LogDebug(BCLog::HOLEPUNCH, "attempt %d to %s from port %d pending\n", session.attempts, peer.ToStringAddrPort(), m_opts.port);
    session.attempt = std::move(sock);
}

void SessionManager::OnAttemptDone(Session& session, NodeClock::time_point now, std::vector<Result>& results)
{
    int err{0};
    socklen_t err_len{sizeof(err)};
    if (session.attempt->GetSockOpt(SOL_SOCKET, SO_ERROR, &err, &err_len) == SOCKET_ERROR) {
        err = WSAGetLastError();
    }
    auto sock{std::move(session.attempt)};
    session.attempt.reset();
    if (err == 0) {
        Finish(session.peer, std::move(sock), results);
        return;
    }
    LogDebug(BCLog::HOLEPUNCH, "attempt %d to %s failed: %s\n", session.attempts, session.peer.ToStringAddrPort(), NetworkErrorString(err));
    session.next_attempt = now + RETRY;
}

void SessionManager::OnAccepted(std::shared_ptr<Sock> sock, const CService& peer, NodeClock::time_point now, std::vector<Result>& results)
{
    if (const auto it{m_sessions.find(peer)}; it != m_sessions.end()) {
        LogDebug(BCLog::HOLEPUNCH, "listener accepted the connection from %s\n", peer.ToStringAddrPort());
        it->second.attempt.reset(); // a pending attempt for the same 4-tuple cannot succeed anymore
        Finish(peer, std::move(sock), results);
        return;
    }
    // Not expected (yet): keep it briefly in case the punch for it is still on its way (R-5.7).
    LogDebug(BCLog::HOLEPUNCH, "listener accepted a connection from %s that matches no session, holding it for %ds\n", peer.ToStringAddrPort(), Ticks<std::chrono::seconds>(HOLD));
    m_held.push_back({.sock = std::move(sock), .peer = peer, .expires = now + HOLD});
}

void SessionManager::RunTimers(NodeClock::time_point now, std::vector<Result>& results)
{
    // A session may match a connection the listener accepted before the session existed.
    for (auto held{m_held.begin()}; held != m_held.end();) {
        if (m_sessions.contains(held->peer)) {
            LogDebug(BCLog::HOLEPUNCH, "using the held connection from %s\n", held->peer.ToStringAddrPort());
            Finish(held->peer, std::move(held->sock), results);
            held = m_held.erase(held);
        } else if (held->expires <= now) {
            LogDebug(BCLog::HOLEPUNCH, "closing the unmatched connection from %s\n", held->peer.ToStringAddrPort());
            held = m_held.erase(held);
        } else {
            ++held;
        }
    }
    for (auto it{m_sessions.begin()}; it != m_sessions.end();) {
        Session& session{it->second};
        const CService peer{it->first};
        if (now >= session.deadline + GRACE) {
            ++it;
            Finish(peer, nullptr, results);
            continue;
        }
        if (now >= session.deadline) {
            if (session.attempt) {
                LogDebug(BCLog::HOLEPUNCH, "window for %s is over, stopping attempts\n", peer.ToStringAddrPort());
                session.attempt.reset();
            }
        } else if (!session.attempt && !session.wait_for_accept && now >= session.next_attempt) {
            StartAttempt(session, now);
        }
        ++it;
    }
}

void SessionManager::ThreadLoop()
{
    while (!m_interrupt) {
        std::vector<Result> results;
        Sock::EventsPerSock events;
        {
            LOCK(m_mutex);
            RunTimers(NodeClock::now(), results);
            for (const auto& listener : m_listeners) events.emplace(listener, Sock::Events{Sock::RecvEvent});
            for (const auto& [peer, session] : m_sessions) {
                if (session.attempt) events.emplace(session.attempt, Sock::Events{Sock::SendEvent});
            }
        }
        for (auto& result : results) m_on_result(result.peer, result.role, std::move(result.sock), result.deadline);
        results.clear();

        if (events.empty() || !events.begin()->first->WaitMany(std::chrono::milliseconds{100}, events)) {
            m_interrupt.sleep_for(std::chrono::milliseconds{100});
            continue;
        }

        {
            LOCK(m_mutex);
            const auto now{NodeClock::now()};
            for (const auto& listener : m_listeners) {
                if (!(events.at(listener).occurred & Sock::RecvEvent)) continue;
                sockaddr_storage storage;
                socklen_t len{sizeof(storage)};
                auto sock{listener->Accept(reinterpret_cast<sockaddr*>(&storage), &len)};
                if (!sock) continue;
                CService peer;
                if (!peer.SetSockAddr(reinterpret_cast<sockaddr*>(&storage), len)) continue;
                OnAccepted(std::move(sock), peer, now, results);
            }
            // Collect first: finishing a session removes it from m_sessions.
            std::vector<CService> done;
            for (const auto& [peer, session] : m_sessions) {
                if (!session.attempt) continue;
                const auto it{events.find(session.attempt)};
                if (it != events.end() && it->second.occurred != 0) done.push_back(peer);
            }
            for (const CService& peer : done) OnAttemptDone(m_sessions.at(peer), now, results);
        }
        for (auto& result : results) m_on_result(result.peer, result.role, std::move(result.sock), result.deadline);
    }
}

} // namespace holepunch
