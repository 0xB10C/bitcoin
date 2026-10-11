// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HOLEPUNCH_H
#define BITCOIN_HOLEPUNCH_H

#include <netaddress.h>
#include <serialize.h>
#include <sync.h>

#include <cstdint>
#include <map>
#include <optional>
#include <vector>

/**
 * TCP hole punching between nodes behind NATs (draft BIP "TCP Hole Punching
 * for Peer Connections"). Everything specific to hole punching that does not
 * need CConnman or PeerManager lives in this namespace, so that it can be
 * unit tested on its own. Rule numbers (R-x.y) refer to the draft.
 */
namespace holepunch {

typedef int64_t NodeId;

/** Role of a node in a session, as carried in `punch`. The initiator sends the
 * first bytes (it is the BIP 324 initiator and sends `version` first). */
enum class Role : uint8_t {
    RESPONDER = 0,
    INITIATOR = 1,
};

/**
 * Whether an endpoint received in a message is well formed (R-4.2): an IPv4 or
 * IPv6 address that is not an IPv4-mapped IPv6 address (R-1.4). Validity for
 * use (routable, port, own address) is checked separately.
 */
bool IsWellFormedEndpoint(const CService& endpoint);

/**
 * `rendezvous`: connector to coordinator. Endpoints are serialized as BIP 155
 * address elements without time and services, which is the V2 form of CService.
 */
struct RendezvousMsg {
    /** The advertiser's endpoint, from its announcement. */
    CService target;
    /** The connector's own external address, in the same address family. */
    CService requester;

    SERIALIZE_METHODS(RendezvousMsg, obj)
    {
        READWRITE(CNetAddr::V2(obj.target), CNetAddr::V2(obj.requester));
    }

    /** Both endpoints well formed and of the same family (R-4.2, R-4.3). */
    bool IsWellFormed() const;
};

/** `punch`: coordinator to a party. */
struct PunchMsg {
    uint8_t role{0};
    /** The other party's endpoint. */
    CService peer;

    SERIALIZE_METHODS(PunchMsg, obj)
    {
        READWRITE(obj.role, CNetAddr::V2(obj.peer));
    }

    /** Known role and well formed endpoint (R-4.2). */
    bool IsWellFormed() const;
};

/** Settings, filled in from the command line options. */
struct Options {
    /** Whether hole punching is enabled at all. */
    bool enabled{false};
    /** The punch port: the local port used for all clearnet outbound
     * connections and for the punch listener, in both address families. */
    uint16_t port{0};
    /** On test networks: accept non-routable addresses and count each peer
     * as its own network group (R-2.5). */
    bool allow_local{false};
};

/**
 * Derives our external address and port per address family from what peers
 * report in `version.addr_recv` (R-2.1 to R-2.4).
 *
 * Only reports from peers that we reached from the punch port without a proxy
 * are meaningful; the caller makes that selection. A report is accepted when
 * its address is routable (or anything on test networks) and its port is not
 * zero. The external address of a family is the reported address that at
 * least two peers in distinct network groups agree on. If two such agreeing
 * sets disagree with each other, the family has no external address.
 */
class ExternalAddressTracker
{
public:
    explicit ExternalAddressTracker(bool allow_local) : m_allow_local{allow_local} {}

    /**
     * Record what peer `id` reports as our address.
     * @param[in] group The peer's network group, as used for outbound diversity.
     * @return true if the report was recorded, false if it is unusable (R-2.1).
     */
    bool AddReport(NodeId id, const std::vector<unsigned char>& group, const CService& reported)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Forget the report of a peer that disconnected. */
    void RemovePeer(NodeId id) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** The external address for `net` (NET_IPV4 or NET_IPV6), if any (R-2.2, R-2.3). */
    std::optional<CService> Get(Network net) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    struct Info {
        /** Same as Get(). */
        std::optional<CService> address;
        /** Number of peers that report `address` (0 if none). */
        size_t reporters{0};
        /** Whether two agreeing sets of peers report different addresses (R-2.3). */
        bool conflicting{false};
        /** Number of reports recorded for this family. */
        size_t reports{0};
    };

    /** Details for logging and RPC. */
    Info GetInfo(Network net) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    struct Report {
        std::vector<unsigned char> group;
        CService addr;
    };

    const bool m_allow_local;
    mutable Mutex m_mutex;
    std::map<NodeId, Report> m_reports GUARDED_BY(m_mutex);
};

} // namespace holepunch

#endif // BITCOIN_HOLEPUNCH_H
