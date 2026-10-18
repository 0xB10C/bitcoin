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
#include <util/sock.h>
#include <util/threadinterrupt.h>
#include <util/time.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <thread>
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

// Limits of punching (section 8 of the draft) and slots (section 9).
/** Attempts are made for this long after the session start (R-8.1). */
inline constexpr auto WINDOW{std::chrono::seconds{120}};
/** The wait after a failed attempt, doubled after each failure (R-8.2). */
inline constexpr auto RETRY{std::chrono::seconds{1}};
/** How long after the window the session may still succeed (R-8.7). */
inline constexpr auto GRACE{std::chrono::seconds{5}};
/** How long an accepted connection that matches no session is held (R-8.4). */
inline constexpr auto HOLD{std::chrono::seconds{10}};
/** At most this many such connections are held (R-8.4). */
inline constexpr size_t HELD_MAX{8};
/** Sessions started per round at most (R-7.4). */
inline constexpr size_t PICKS_PER_ROUND{3};
/** Of them, from entries of one source group at most (R-7.4). */
inline constexpr size_t PICKS_PER_SOURCE{2};
/** Sessions in progress at most (R-7.4). */
inline constexpr size_t MAX_ACTIVE_SESSIONS{6};
/** Sessions started per network group per hour at most (R-7.3). */
inline constexpr size_t GROUP_SESSIONS_PER_HOUR{4};
/** Hole-punch outbound connections a node holds at most (R-9.1). */
inline constexpr int HP_OUTBOUND_MAX{1};

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

    /**
     * Recompute the shared secret of every entry of `family` with `key`, which
     * the node MUST do when it replaces that family's key (R-4.3): the entry's
     * peer will compute with the new public key as soon as the announcement
     * reaches it, and a secret left over from the old key would make the two
     * sides disagree on every pair value. An entry whose product is the point
     * at infinity is dropped (R-4.4). `received_at` is kept.
     */
    void Rekey(Network family, const CKey& key) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

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

/**
 * Runs punch sessions (section 8 of the draft): listens on the punch port of
 * each family and, per session, connects to the peer's endpoint from the punch
 * port, again after each failure with a doubling wait, until a connection with
 * exactly that remote endpoint exists, from our connect() or from the
 * listener. A session is keyed by the peer's endpoint. It ends in success
 * with the connection, or in failure WINDOW + GRACE after it started.
 */
class SessionManager
{
public:
    /**
     * Called when a session ends: with the connection on success, with nullptr
     * on failure. `deadline` is the session's end (R-8.7): the handshake on the
     * connection has to be complete by then too.
     */
    using ResultFn = std::function<void(const CService& peer, Role role, std::shared_ptr<Sock> sock, NodeClock::time_point deadline)>;

    SessionManager(const Options& opts, ResultFn on_result);
    ~SessionManager() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Open the punch listeners and start the thread. False if no listener could be opened. */
    bool Start() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Stop the thread and close everything; pending sessions end without a callback. */
    void Stop() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Start a session with `peer` in `role`; `group` is the peer's network
     * group for GROUP_SESSIONS_PER_HOUR (R-7.3).
     * @return the reason if the session was not started: a session with the
     * peer exists, MAX_ACTIVE_SESSIONS are in progress, or the group's hourly
     * budget is used up.
     */
    std::optional<std::string> Punch(Role role, const CService& peer, const std::vector<unsigned char>& group) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    bool HasSession(const CService& peer) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Drop the session with `peer`, closing its sockets. Nothing is reported for it. */
    void Cancel(const CService& peer) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    struct SessionInfo {
        CService peer;
        Role role;
        NodeClock::time_point started;
        int attempts;
    };
    std::vector<SessionInfo> GetSessions() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Sessions in progress per role (index Role), which reserve the slot their role needs (R-7.3). */
    std::array<size_t, 2> SessionsByRole() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Whether a session to an address in `group` may start now (R-7.3). */
    bool GroupBudgetFree(const std::vector<unsigned char>& group) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** What happened so far, per role (index Role). Every field only ever grows. */
    struct Stats {
        std::atomic<uint64_t> started[2]{};
        std::atomic<uint64_t> established[2]{};
        std::atomic<uint64_t> failed[2]{};
    };
    const Stats& GetStats() const { return m_stats; }

private:
    struct Session {
        Role role;
        CService peer;
        NodeClock::time_point started;
        /** No new attempts after this (started + WINDOW). */
        NodeClock::time_point deadline;
        /** When to make the next attempt; none while `attempt` is pending. */
        NodeClock::time_point next_attempt;
        /** The wait before the next attempt, doubled after each failure (R-8.2). */
        std::chrono::seconds retry{RETRY};
        /** The pending connect(), if any. */
        std::shared_ptr<Sock> attempt;
        int attempts{0};
        /** Set when connect() refused the 4-tuple: the listener has the connection (R-8.3). */
        bool wait_for_accept{false};
        /**
         * Responder only: the session's connection, kept here until the initiator's
         * first bytes arrive. A peer that closes it before sending anything was not
         * expecting it yet, and the attempts resume (R-8.5).
         */
        std::shared_ptr<Sock> established;
    };
    /** An accepted connection that matched no session when it arrived (R-8.4). */
    struct Held {
        std::shared_ptr<Sock> sock;
        CService peer;
        NodeClock::time_point expires;
    };
    struct Result {
        CService peer;
        Role role;
        std::shared_ptr<Sock> sock;
        NodeClock::time_point deadline;
    };

    void ThreadLoop() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Timers: start attempts, stop attempts at the deadline, fail sessions after the grace period, expire held connections. */
    void RunTimers(NodeClock::time_point now, std::vector<Result>& results) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void StartAttempt(Session& session, NodeClock::time_point now) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    /** The listener accepted a connection from `peer`. */
    void OnAccepted(std::shared_ptr<Sock> sock, const CService& peer, NodeClock::time_point now, std::vector<Result>& results) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    /** The pending connect() of a session finished, successfully or not. */
    void OnAttemptDone(Session& session, NodeClock::time_point now, std::vector<Result>& results) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void Finish(const CService& peer, std::shared_ptr<Sock> sock, std::vector<Result>& results) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    /** The session's connection is `sock`: hand it over (initiator) or wait for the first bytes on it (responder). */
    void Establish(Session& session, std::shared_ptr<Sock> sock, std::vector<Result>& results) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    /** The responder's connection became readable: first bytes, or a close. */
    void OnEstablishedReadable(Session& session, NodeClock::time_point now, std::vector<Result>& results) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    /** Forget session starts older than an hour. */
    void PruneStarts(NodeClock::time_point now) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    /** An attempt failed: the next one waits, twice as long as the last wait (R-8.2). */
    static void ScheduleRetry(Session& session, NodeClock::time_point now);

    const Options m_opts;
    const ResultFn m_on_result;
    Stats m_stats;
    std::vector<std::shared_ptr<Sock>> m_listeners;
    mutable Mutex m_mutex;
    std::map<CService, Session> m_sessions GUARDED_BY(m_mutex);
    std::vector<Held> m_held GUARDED_BY(m_mutex);
    /** Session starts in the last hour per network group, for GROUP_SESSIONS_PER_HOUR. */
    std::map<std::vector<unsigned char>, std::vector<NodeClock::time_point>> m_group_starts GUARDED_BY(m_mutex);
    CThreadInterrupt m_interrupt;
    std::thread m_thread;
};

} // namespace holepunch

#endif // BITCOIN_HOLEPUNCH_H
