// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <holepunch.h>

#include <compat/compat.h>
#include <netbase.h>

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

} // namespace holepunch
