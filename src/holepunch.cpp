// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <holepunch.h>

#include <compat/compat.h>
#include <hash.h>
#include <logging.h>
#include <netbase.h>
#include <streams.h>
#include <tinyformat.h>
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

void SessionManager::PruneStarts(NodeClock::time_point now)
{
    for (auto it{m_group_starts.begin()}; it != m_group_starts.end();) {
        std::erase_if(it->second, [&](const auto& start) { return start + std::chrono::hours{1} <= now; });
        it = it->second.empty() ? m_group_starts.erase(it) : std::next(it);
    }
}

bool SessionManager::GroupBudgetFree(const std::vector<unsigned char>& group) const
{
    const auto now{NodeClock::now()};
    LOCK(m_mutex);
    const auto it{m_group_starts.find(group)};
    if (it == m_group_starts.end()) return true;
    const size_t recent{static_cast<size_t>(std::count_if(it->second.begin(), it->second.end(), [&](const auto& start) { return start + std::chrono::hours{1} > now; }))};
    return recent < GROUP_SESSIONS_PER_HOUR;
}

std::optional<std::string> SessionManager::Punch(Role role, const CService& peer, const std::vector<unsigned char>& group)
{
    const auto now{NodeClock::now()};
    LOCK(m_mutex);
    if (m_sessions.contains(peer)) return "a session with this peer exists";
    if (m_sessions.size() >= MAX_ACTIVE_SESSIONS) return strprintf("%d sessions are in progress", m_sessions.size());
    PruneStarts(now);
    if (m_group_starts[group].size() >= GROUP_SESSIONS_PER_HOUR) return "the network group's sessions for this hour are used up";

    m_group_starts[group].push_back(now);
    m_sessions.emplace(peer, Session{.role = role, .peer = peer, .started = now, .deadline = now + WINDOW, .next_attempt = now, .retry = RETRY, .attempt = nullptr, .attempts = 0, .wait_for_accept = false, .established = nullptr});
    ++m_stats.started[static_cast<size_t>(role)];
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

std::array<size_t, 2> SessionManager::SessionsByRole() const
{
    std::array<size_t, 2> counts{};
    LOCK(m_mutex);
    for (const auto& [peer, session] : m_sessions) ++counts[static_cast<size_t>(session.role)];
    return counts;
}

void SessionManager::Establish(Session& session, std::shared_ptr<Sock> sock, std::vector<Result>& results)
{
    session.attempt.reset();
    session.wait_for_accept = false;
    if (session.role == Role::INITIATOR) {
        Finish(session.peer, std::move(sock), results);
        return;
    }
    LogDebug(BCLog::HOLEPUNCH, "connected to %s as responder after %d attempt(s), waiting for the initiator's first bytes\n", session.peer.ToStringAddrPort(), session.attempts);
    session.established = std::move(sock);
}

void SessionManager::OnEstablishedReadable(Session& session, NodeClock::time_point now, std::vector<Result>& results)
{
    // Peek: the bytes stay in the socket for the transport that takes it over.
    char byte;
    const ssize_t got{session.established->Recv(&byte, 1, MSG_PEEK)};
    if (got > 0) {
        Finish(session.peer, std::move(session.established), results);
        return;
    }
    if (got < 0) {
        const int err{WSAGetLastError()};
        if (err == WSAEWOULDBLOCK || err == WSAEINTR || err == WSAEINPROGRESS) return;
    }
    // Closed, or broken, before a byte arrived: the peer did not expect us yet (R-8.5).
    LogDebug(BCLog::HOLEPUNCH, "%s closed the connection before sending anything, resuming attempts\n", session.peer.ToStringAddrPort());
    session.established.reset();
    ScheduleRetry(session, now);
}

void SessionManager::ScheduleRetry(Session& session, NodeClock::time_point now)
{
    session.next_attempt = now + session.retry;
    session.retry *= 2;
}

void SessionManager::Finish(const CService& peer, std::shared_ptr<Sock> sock, std::vector<Result>& results)
{
    const auto it{m_sessions.find(peer)};
    if (it == m_sessions.end()) return;
    Session& session{it->second};
    if (sock) {
        ++m_stats.established[static_cast<size_t>(session.role)];
        LogDebug(BCLog::HOLEPUNCH, "session with %s established as %s after %d attempt(s)\n", peer.ToStringAddrPort(), RoleName(session.role), session.attempts);
    } else {
        ++m_stats.failed[static_cast<size_t>(session.role)];
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
        ScheduleRetry(session, now);
        return;
    }
    const CService local{WildcardAddress(peer.IsIPv4() ? NET_IPV4 : NET_IPV6, m_opts.port)};
    if (!BindToSharedPort(*sock, local)) {
        ScheduleRetry(session, now);
        return;
    }
    sockaddr_storage storage;
    socklen_t len{sizeof(storage)};
    if (!peer.GetSockAddr(reinterpret_cast<sockaddr*>(&storage), &len)) {
        ScheduleRetry(session, now);
        return;
    }
    if (sock->Connect(reinterpret_cast<sockaddr*>(&storage), len) == SOCKET_ERROR) {
        const int err{WSAGetLastError()};
        if (err != WSAEINPROGRESS && err != WSAEWOULDBLOCK && err != WSAEINVAL) {
            if (err == WSAEADDRINUSE || err == WSAEADDRNOTAVAIL) {
                // The 4-tuple exists already: the listener has the peer's connection (R-8.3).
                LogDebug(BCLog::HOLEPUNCH, "attempt %d to %s: connection exists, waiting for the listener\n", session.attempts, peer.ToStringAddrPort());
                session.wait_for_accept = true;
            } else {
                LogDebug(BCLog::HOLEPUNCH, "attempt %d to %s failed: %s\n", session.attempts, peer.ToStringAddrPort(), NetworkErrorString(err));
                ScheduleRetry(session, now);
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
        Establish(session, std::move(sock), results);
        return;
    }
    LogDebug(BCLog::HOLEPUNCH, "attempt %d to %s failed: %s\n", session.attempts, session.peer.ToStringAddrPort(), NetworkErrorString(err));
    ScheduleRetry(session, now);
}

void SessionManager::OnAccepted(std::shared_ptr<Sock> sock, const CService& peer, NodeClock::time_point now, std::vector<Result>& results)
{
    if (const auto it{m_sessions.find(peer)}; it != m_sessions.end()) {
        LogDebug(BCLog::HOLEPUNCH, "listener accepted the connection from %s\n", peer.ToStringAddrPort());
        it->second.attempt.reset(); // a pending attempt for the same 4-tuple cannot succeed anymore
        Establish(it->second, std::move(sock), results);
        return;
    }
    // Not expected (yet): keep it, untouched, in case a session for it starts soon,
    // as it does when the peer's tip reached the block before ours (R-8.4).
    if (m_held.size() >= HELD_MAX) {
        LogDebug(BCLog::HOLEPUNCH, "closing the oldest held connection, from %s, to make room\n", m_held.front().peer.ToStringAddrPort());
        m_held.erase(m_held.begin());
    }
    LogDebug(BCLog::HOLEPUNCH, "listener accepted a connection from %s that matches no session, holding it for %ds\n", peer.ToStringAddrPort(), Ticks<std::chrono::seconds>(HOLD));
    m_held.push_back({.sock = std::move(sock), .peer = peer, .expires = now + HOLD});
}

void SessionManager::RunTimers(NodeClock::time_point now, std::vector<Result>& results)
{
    // A session may match a connection the listener accepted before the session existed.
    for (auto held{m_held.begin()}; held != m_held.end();) {
        if (const auto it{m_sessions.find(held->peer)}; it != m_sessions.end()) {
            LogDebug(BCLog::HOLEPUNCH, "using the held connection from %s\n", held->peer.ToStringAddrPort());
            it->second.attempt.reset();
            Establish(it->second, std::move(held->sock), results);
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
        } else if (!session.attempt && !session.established && !session.wait_for_accept && now >= session.next_attempt) {
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
                if (session.established) events.emplace(session.established, Sock::Events{Sock::RecvEvent});
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
            std::vector<CService> readable;
            for (const auto& [peer, session] : m_sessions) {
                if (session.attempt) {
                    const auto it{events.find(session.attempt)};
                    if (it != events.end() && it->second.occurred != 0) done.push_back(peer);
                }
                if (session.established) {
                    const auto it{events.find(session.established)};
                    if (it != events.end() && it->second.occurred != 0) readable.push_back(peer);
                }
            }
            for (const CService& peer : done) OnAttemptDone(m_sessions.at(peer), now, results);
            for (const CService& peer : readable) OnEstablishedReadable(m_sessions.at(peer), now, results);
        }
        for (auto& result : results) m_on_result(result.peer, result.role, std::move(result.sock), result.deadline);
    }
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
