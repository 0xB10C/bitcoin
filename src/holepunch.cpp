// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <holepunch.h>

#include <compat/compat.h>
#include <logging.h>
#include <netbase.h>
#include <tinyformat.h>

#include <algorithm>
#include <thread>

namespace holepunch {

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

//! A socket listening on the punch port of the peer's family, or null.
static std::shared_ptr<Sock> ListenOnPunchPort(const CService& peer, uint16_t punch_port)
{
    const Network family{peer.IsIPv4() ? NET_IPV4 : NET_IPV6};
    const CService addr{WildcardAddress(family, punch_port)};
    std::shared_ptr<Sock> sock{CreateSock(addr.GetSAFamily(), SOCK_STREAM, IPPROTO_TCP)};
    if (!sock) {
        LogDebug(BCLog::HOLEPUNCH, "cannot create a listening socket for %s\n", addr.ToStringAddrPort());
        return nullptr;
    }
#ifdef IPV6_V6ONLY
    if (family == NET_IPV6) {
        const int one{1};
        if (sock->SetSockOpt(IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) == SOCKET_ERROR) {
            LogDebug(BCLog::HOLEPUNCH, "cannot set IPV6_V6ONLY on the listening socket: %s\n", NetworkErrorString(WSAGetLastError()));
        }
    }
#endif
    if (!BindToSharedPort(*sock, addr)) return nullptr;
    if (sock->Listen(SOMAXCONN) == SOCKET_ERROR) {
        LogDebug(BCLog::HOLEPUNCH, "cannot listen on %s: %s\n", addr.ToStringAddrPort(), NetworkErrorString(WSAGetLastError()));
        return nullptr;
    }
    return sock;
}

/**
 * Start a non-blocking connection to `peer` from the punch port. Returns the
 * socket while the connection is pending or made, null if connect() failed.
 * @param[out] exists Set if the 4-tuple is in use already, which means that the
 * listener has accepted the peer's connection.
 */
static std::shared_ptr<Sock> StartAttempt(const CService& peer, uint16_t punch_port, int attempt, bool& exists)
{
    exists = false;
    std::shared_ptr<Sock> sock{CreateSock(peer.GetSAFamily(), SOCK_STREAM, IPPROTO_TCP)};
    if (!sock) {
        LogDebug(BCLog::HOLEPUNCH, "attempt %d to %s: cannot create a socket\n", attempt, peer.ToStringAddrPort());
        return nullptr;
    }
    if (!BindToSharedPort(*sock, WildcardAddress(peer.IsIPv4() ? NET_IPV4 : NET_IPV6, punch_port))) return nullptr;
    sockaddr_storage storage;
    socklen_t len{sizeof(storage)};
    if (!peer.GetSockAddr(reinterpret_cast<sockaddr*>(&storage), &len)) return nullptr;
    if (sock->Connect(reinterpret_cast<sockaddr*>(&storage), len) == SOCKET_ERROR) {
        const int err{WSAGetLastError()};
        if (err == WSAEINPROGRESS || err == WSAEWOULDBLOCK || err == WSAEINVAL) {
            LogDebug(BCLog::HOLEPUNCH, "attempt %d to %s from port %d pending\n", attempt, peer.ToStringAddrPort(), punch_port);
            return sock;
        }
        if (err == WSAEADDRINUSE || err == WSAEADDRNOTAVAIL) {
            LogDebug(BCLog::HOLEPUNCH, "attempt %d to %s: the connection exists, waiting for the listener\n", attempt, peer.ToStringAddrPort());
            exists = true;
        } else {
            LogDebug(BCLog::HOLEPUNCH, "attempt %d to %s failed: %s\n", attempt, peer.ToStringAddrPort(), NetworkErrorString(err));
        }
        return nullptr;
    }
    LogDebug(BCLog::HOLEPUNCH, "attempt %d to %s from port %d connected at once\n", attempt, peer.ToStringAddrPort(), punch_port);
    return sock;
}

PunchOutcome Punch(const CService& peer, uint16_t punch_port, std::chrono::milliseconds window, const std::function<bool()>& interrupted)
{
    using clock = std::chrono::steady_clock;
    PunchOutcome outcome;
    const auto started{clock::now()};
    const auto deadline{started + window};
    LogDebug(BCLog::HOLEPUNCH, "punching to %s from port %d for %d ms\n", peer.ToStringAddrPort(), punch_port, Ticks<std::chrono::milliseconds>(window));

    // The peer's SYN may arrive before our attempt exists: the listener takes it then.
    const auto listener{ListenOnPunchPort(peer, punch_port)};
    if (!listener) LogDebug(BCLog::HOLEPUNCH, "no listener on port %d, only our own attempts can succeed\n", punch_port);

    std::shared_ptr<Sock> attempt;
    auto next_attempt{started};
    while (!interrupted()) {
        auto now{clock::now()};
        if (now >= deadline) {
            outcome.error = strprintf("no connection within %d ms", Ticks<std::chrono::milliseconds>(window));
            break;
        }
        if (!attempt && now >= next_attempt) {
            bool exists{false};
            attempt = StartAttempt(peer, punch_port, ++outcome.attempts, exists);
            if (!attempt) next_attempt = now + RETRY;
        }

        Sock::EventsPerSock events;
        if (listener) events.emplace(listener, Sock::Events{Sock::RecvEvent});
        if (attempt) events.emplace(attempt, Sock::Events{Sock::SendEvent});
        const auto timeout{std::min<clock::duration>(std::chrono::milliseconds{100}, deadline - now)};
        if (events.empty()) {
            std::this_thread::sleep_for(timeout);
            continue;
        }
        if (!events.begin()->first->WaitMany(std::chrono::duration_cast<std::chrono::milliseconds>(timeout), events)) {
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
            continue;
        }
        now = clock::now();

        if (listener && (events.at(listener).occurred & Sock::RecvEvent)) {
            sockaddr_storage storage;
            socklen_t len{sizeof(storage)};
            std::shared_ptr<Sock> accepted{listener->Accept(reinterpret_cast<sockaddr*>(&storage), &len)};
            CService from;
            if (accepted && from.SetSockAddr(reinterpret_cast<sockaddr*>(&storage), len)) {
                if (static_cast<const CNetAddr&>(from) == static_cast<const CNetAddr&>(peer)) {
                    LogDebug(BCLog::HOLEPUNCH, "the listener accepted the connection from %s\n", from.ToStringAddrPort());
                    outcome.sock = std::move(accepted);
                    outcome.peer = from;
                    break;
                }
                LogDebug(BCLog::HOLEPUNCH, "closing a connection from %s, which is not the peer\n", from.ToStringAddrPort());
            }
        }

        if (attempt && events.at(attempt).occurred != 0) {
            int err{0};
            socklen_t err_len{sizeof(err)};
            if (attempt->GetSockOpt(SOL_SOCKET, SO_ERROR, &err, &err_len) == SOCKET_ERROR) err = WSAGetLastError();
            if (err == 0) {
                LogDebug(BCLog::HOLEPUNCH, "attempt %d to %s connected\n", outcome.attempts, peer.ToStringAddrPort());
                outcome.sock = std::move(attempt);
                outcome.peer = peer;
                break;
            }
            LogDebug(BCLog::HOLEPUNCH, "attempt %d to %s failed: %s\n", outcome.attempts, peer.ToStringAddrPort(), NetworkErrorString(err));
            attempt.reset();
            next_attempt = now + RETRY;
        }
    }
    if (!outcome.sock && outcome.error.empty()) outcome.error = "interrupted";
    LogDebug(BCLog::HOLEPUNCH, "punch to %s %s after %d attempt(s) and %d ms\n", peer.ToStringAddrPort(),
             outcome.sock ? "succeeded" : "failed: " + outcome.error, outcome.attempts, Ticks<std::chrono::milliseconds>(clock::now() - started));
    return outcome;
}

} // namespace holepunch
