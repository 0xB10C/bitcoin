// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HOLEPUNCH_H
#define BITCOIN_HOLEPUNCH_H

#include <key.h>
#include <netaddress.h>
#include <protocol.h>
#include <pubkey.h>
#include <random.h>
#include <serialize.h>
#include <sync.h>
#include <uint256.h>
#include <util/time.h>

#include <chrono>
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

// Limits of board connections (section 5 of the draft, R-5.2).
/** Board connections a visitor keeps per announced address family. */
inline constexpr size_t BOARDS{2};
/** A board connection is replaced about this long after it was opened, at a time not aligned across nodes. */
inline constexpr auto BOARD_ROTATE{std::chrono::hours{6}};
/** How far from BOARD_ROTATE a connection's lifetime may lie, either way. */
inline constexpr auto BOARD_ROTATE_SPREAD{std::chrono::hours{1}};
/** After this many replacements in a row without a result for one family, the visitor pauses. */
inline constexpr int BOARD_FAIL_MAX{4};
/** How long it pauses. */
inline constexpr auto BOARD_BACKOFF{std::chrono::hours{1}};

/** How long a visitor waits for the board's answer to its element (R-5.3). */
inline constexpr auto BOARD_ACK{std::chrono::seconds{60}};
/** Elements processed from one peer per hour at most (R-5.10). */
inline constexpr uint32_t PUNCHKEY_PER_HOUR{240};

/** An entry at a board lives this long after its connection closed (R-5.7). */
inline constexpr auto BOARD_GRACE{std::chrono::minutes{10}};
/** A board sends every live entry to every visitor again this often (R-5.8). */
inline constexpr auto BOARD_REFRESH{std::chrono::minutes{30}};

// Limits of the board pool (section 5 of the draft, R-5.5).
/** Visitors a board holds at most. */
inline constexpr size_t BOARD_VISITORS_MAX{32};
/** Visitors from one network group a board holds at most. */
inline constexpr size_t BOARD_PER_GROUP{4};
/** Visitors from one address a board holds at most. */
inline constexpr size_t BOARD_IP_CAP{1};

// Limits of the table (section 6 of the draft).
/** Entries kept per source group at most (R-6.2). */
inline constexpr size_t SOURCE_CAP{64};
/** Entries kept in total at most (R-6.3). */
inline constexpr size_t TABLE_MAX{1024};
/** An entry expires this long after it was last seen (R-6.4). */
inline constexpr auto ENTRY_TTL{std::chrono::hours{1}};
/** A family's key is replaced at least this often (R-4.3). */
inline constexpr auto KEY_ROTATE{std::chrono::hours{24}};

/** Role of a node in a session (R-4.7). The initiator sends the first bytes. */
enum class Role : uint8_t {
    RESPONDER = 0,
    INITIATOR = 1,
};
std::string RoleName(Role role);

/** The content of a PUNCHKEY element (section 5 of the draft). */
struct PunchKey {
    /** The announcer's external address and port. */
    CService endpoint;
    /** The announcer's current key for the endpoint's family. */
    CPubKey pubkey;
    /** The announcer's services. */
    ServiceFlags services{NODE_NONE};

    /**
     * Parse an element, applying R-5.1: an IPv4 or IPv6 endpoint that is
     * routable (or anything with `allow_local`) with a port, a valid
     * compressed key, and services with NODE_P2P_V2. Nullopt if rejected.
     */
    static std::optional<PunchKey> FromAddress(const CAddress& addr, bool allow_local);
    /** The element to send. `time` carries no meaning for receivers (R-5.3). */
    CAddress ToAddress(NodeSeconds time) const;
};

/**
 * The encoding of an endpoint in the pair value (Terminology): a BIP 155
 * element without time and services.
 */
std::vector<uint8_t> EncodeEndpoint(const CService& endpoint);

/**
 * The pair value (R-4.5) of two nodes with the shared secret `x` for the
 * block with `block_hash`; the same from both sides, since the endpoints
 * are sorted. Ranked as 256-bit integers, lower first (R-4.6).
 */
uint256 PairValue(const uint256& x, const uint256& block_hash, const CService& ep_a, const CService& ep_b);

/** The role of the node with key `own` towards the node with key `other` for a pair value (R-4.7). */
Role RoleFor(const uint256& pair, const CPubKey& own, const CPubKey& other);

/** A stored announcement (section 6 of the draft). */
struct Entry {
    PunchKey key;
    /** The shared secret with the announcer (R-4.4), computed once when stored. */
    uint256 secret;
    /** The network group of the board that served the entry (R-5.4). */
    std::vector<unsigned char> source;
    /** When the entry was first received; a refresh keeps it (R-6.1). */
    NodeClock::time_point received_at;
    /** When an element for the entry was last received (R-6.4). */
    NodeClock::time_point last_seen;

    bool Expired(NodeClock::time_point now) const { return now >= last_seen + ENTRY_TTL; }
};

/**
 * The entries a node has learned from its boards, keyed by (endpoint,
 * pubkey) and organised by the board they came from (section 6).
 */
class Table
{
public:
    /**
     * Store an element from the board in source group `source`, or refresh
     * the entry it matches, or replace the same board's entry for the same
     * address with another key (R-6.1), evicting within the limits (R-6.2,
     * R-6.3). With `allow_local`, addresses are compared with their port.
     * @return true if a new entry was stored.
     */
    bool Add(const std::vector<unsigned char>& source, const PunchKey& key, const uint256& secret, NodeClock::time_point now, bool allow_local)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** The unexpired entries that take part in a round whose parent the tip reached at `parent_time` (R-7.2). */
    std::vector<Entry> Eligible(NodeClock::time_point now, NodeClock::time_point parent_time) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Remove an entry, as a pick does (R-6.5). */
    void Remove(const CService& endpoint, const CPubKey& pubkey) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Drop expired entries (R-6.4). */
    void Expire(NodeClock::time_point now) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    size_t Size() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Entries per source group, for RPC. */
    std::map<std::vector<unsigned char>, size_t> SizeBySource() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    mutable Mutex m_mutex;
    std::vector<Entry> m_entries GUARDED_BY(m_mutex);
    FastRandomContext m_rng GUARDED_BY(m_mutex);

    size_t CountSource(const std::vector<unsigned char>& source) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    /** Evict an expired entry among those with `pred`, else a random one. */
    template <typename Pred>
    void EvictOne(NodeClock::time_point now, Pred pred) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
};

/**
 * The entries a board holds for its visitors (R-5.6 to R-5.8): one per
 * board connection, verified by the caller against the connection's remote
 * endpoint, kept for BOARD_GRACE after the connection closes.
 */
class Board
{
public:
    struct Entry {
        PunchKey key;
        /** When the board received the element; sent as the element's time. */
        NodeSeconds time;
        /** The visitor's connection. */
        NodeId visitor;
        /** When that connection closed, if it did: the entry is in its grace period. */
        std::optional<NodeClock::time_point> closed_at;

        bool Live() const { return !closed_at; }
    };

    /**
     * Store a verified element from `visitor`, replacing that visitor's
     * earlier entry (R-5.6) or an entry for the same address in its grace
     * period (R-5.7). Nothing is stored while another open connection holds
     * an entry for the address. With `allow_local`, addresses are compared
     * with their port.
     * @return the stored entry, to be sent to the other visitors (R-5.8).
     */
    std::optional<Entry> Store(NodeId visitor, const PunchKey& key, NodeClock::time_point now, bool allow_local) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** The entries whose connection is open (R-5.8). */
    std::vector<Entry> LiveEntries() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** The visitor's connection closed: its entry enters the grace period (R-5.7). */
    void Disconnected(NodeId visitor, NodeClock::time_point now) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Drop entries whose grace period is over. */
    void Expire(NodeClock::time_point now) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Entries in total, live and in their grace period. */
    size_t Size() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    mutable Mutex m_mutex;
    std::vector<Entry> m_entries GUARDED_BY(m_mutex);
};

/** Settings, filled in from the command line options. */
struct Options {
    /** Whether the node visits boards and punches. */
    bool enabled{false};
    /** The punch port: the local port of every board connection, every punch
     * attempt and the punch listener, in both address families. */
    uint16_t port{0};
    /** Whether the node acts as a board for others. */
    bool board{false};
    /** Boards to connect to besides those found in the address manager (-holepunchboardseed, for tests). */
    std::vector<CService> board_seeds;
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
    /**
     * Record what peer `id` reports as our address.
     * @param[in] group The peer's network group, as used for outbound diversity.
     * @param[in] allow_local On test networks: accept non-routable addresses and
     * count the peer as its own network group (R-2.5).
     * @return true if the report was recorded, false if it is unusable (R-2.1).
     */
    bool AddReport(NodeId id, const std::vector<unsigned char>& group, const CService& reported, bool allow_local)
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

    mutable Mutex m_mutex;
    std::map<NodeId, Report> m_reports GUARDED_BY(m_mutex);
};

} // namespace holepunch

#endif // BITCOIN_HOLEPUNCH_H
