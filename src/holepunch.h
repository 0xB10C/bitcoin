// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HOLEPUNCH_H
#define BITCOIN_HOLEPUNCH_H

#include <netaddress.h>
#include <random.h>
#include <serialize.h>
#include <sync.h>

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

/**
 * TCP hole punching between nodes behind NATs (draft BIP "Coordinator-less
 * TCP Hole Punching for Peer Connections"). Everything specific to hole
 * punching that does not need CConnman or PeerManager lives in this
 * namespace, so that it can be unit tested on its own. Rule numbers (R-x.y)
 * and limit names refer to the draft.
 */
namespace holepunch {

typedef int64_t NodeId;

/** The range the punch port is chosen from: the dynamic port range. */
inline constexpr uint16_t PUNCH_PORT_MIN{49152};
inline constexpr uint16_t PUNCH_PORT_MAX{65535};

// Limits of the board pool (section 5 of the draft, R-5.5).
/** Visitors a board holds at most. */
inline constexpr size_t BOARD_VISITORS_MAX{32};
/** Visitors from one network group a board holds at most. */
inline constexpr size_t BOARD_PER_GROUP{4};
/** Visitors from one address a board holds at most. */
inline constexpr size_t BOARD_IP_CAP{1};

/** Settings, filled in from the command line options. */
struct Options {
    /** Whether the node visits boards and punches. */
    bool enabled{false};
    /** The punch port: the local port of every board connection, every punch
     * attempt and the punch listener, in both address families. */
    uint16_t port{0};
    /** Whether the node acts as a board for others. */
    bool board{false};
    /** On test networks: accept non-routable addresses, count each peer as
     * its own network group, and compare endpoints where the draft compares
     * addresses (R-2.5). */
    bool allow_local{false};
};

/** Payload of the BIP 434 feature message for hole punching (R-3.1). */
struct FeatureData {
    /** The sender acts as a board. */
    static constexpr uint32_t FLAG_BOARD{1 << 0};
    /** The sender opened this connection as a board connection and will announce on it. */
    static constexpr uint32_t FLAG_VISITOR{1 << 1};

    /** The highest version the sender supports; the lower of the two is used (R-3.2). */
    uint8_t version{0};
    /** Flags; unknown bits are ignored. */
    uint32_t flags{0};

    SERIALIZE_METHODS(FeatureData, obj)
    {
        READWRITE(obj.version, obj.flags);
    }
};

/** Names of the set feature flags, for logs and RPC. */
std::vector<std::string> FeatureFlagNames(uint32_t flags);

/** The wildcard address of `family` (NET_IPV4 or NET_IPV6) with `port`. */
CService WildcardAddress(Network family, uint16_t port);

/**
 * Pick a punch port at random from the dynamic range: one that is not a bad
 * port and that can be bound. Nothing on the wire depends on the number; a
 * fixed well-known port would mark the node's connections behind a
 * port-preserving NAT and collide with other nodes behind the same NAT.
 * Returns nullopt if no such port was found in a few tries.
 */
std::optional<uint16_t> PickRandomPunchPort(FastRandomContext& rng);

/**
 * Whether an endpoint is an IPv4 or IPv6 address with a port, and not an
 * IPv4-mapped IPv6 address (R-1.4). Routability and the port's use are
 * checked separately.
 */
bool IsWellFormedEndpoint(const CService& endpoint);

/**
 * What peers report as this node's address and port in `version.addr_recv`
 * on connections made from the punch port (section 2 of the draft).
 *
 * Only reports from peers that saw this node from its punch port are
 * meaningful; the caller makes that selection. A report is accepted when its
 * address is routable (or anything on test networks) and its port is not
 * zero. The external address of a family is the reported endpoint that at
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
