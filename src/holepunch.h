// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HOLEPUNCH_H
#define BITCOIN_HOLEPUNCH_H

#include <netaddress.h>
#include <protocol.h>
#include <random.h>
#include <serialize.h>
#include <sync.h>
#include <util/sock.h>
#include <util/threadinterrupt.h>
#include <util/time.h>

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <thread>
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
 * The range the default punch port is chosen from: the dynamic port range, with
 * room for the coordination bind at the next port.
 */
inline constexpr uint16_t PUNCH_PORT_MIN{49152};
inline constexpr uint16_t PUNCH_PORT_MAX{65534};

/**
 * Pick a punch port at random from the dynamic range: one that is not a bad port
 * and that can be bound, as can the next port. Nothing on the wire depends on
 * the number; a fixed well-known port would mark the node's connections behind
 * a port-preserving NAT and collide with other nodes behind the same NAT.
 * Returns nullopt if no such port was found in a few tries.
 */
std::optional<uint16_t> PickRandomPunchPort(FastRandomContext& rng);

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

/** Version of the protocol carried in the feature data (R-3.1, R-3.2). */
inline constexpr uint8_t FEATURE_DATA_VERSION{0};

/** Capability bits in the feature data (R-3.1). Unknown bits are ignored. */
enum Caps : uint32_t {
    /** The sender acts as coordinator (Profile A). */
    CAP_COORDINATOR = 1 << 0,
    /** The sender is advertised through the receiver and accepts `punch` as responder. */
    CAP_ADVERTISED = 1 << 1,
    /** The sender may be paired with another pool member by the receiver. */
    CAP_POOL_OK = 1 << 2,
    /** The sender accepts a handoff instead of eviction on this connection. */
    CAP_HANDOFF_OK = 1 << 3,
    /** This connection is from the sender's punch port: the endpoint the receiver observes is the sender's external address. */
    CAP_PUNCHPORT = 1 << 4,
};

/** Names of the set capability bits, for logs and RPC. */
std::vector<std::string> CapNames(uint32_t caps);

/** Payload of the BIP 434 feature message for hole punching. */
struct FeatureData {
    /** The highest version the sender supports; the lower of the two is used (R-3.2). */
    uint8_t version{FEATURE_DATA_VERSION};
    uint32_t caps{0};

    SERIALIZE_METHODS(FeatureData, obj)
    {
        READWRITE(obj.version, obj.caps);
    }
};

/** Settings, filled in from the command line options. */
struct Options {
    /** Whether hole punching is enabled at all. */
    bool enabled{false};
    /** The punch port: the local port used for all clearnet outbound
     * connections and for the punch listener, in both address families. */
    uint16_t port{0};
    /** On test networks: accept non-routable addresses, count each peer as
     * its own network group (R-2.5) and rate limit sessions per endpoint
     * rather than per address. */
    bool allow_local{false};
    /** Where coordination connections are accepted (R-12.1); the target of
     * the coordination onion service. */
    std::optional<CService> coordination_bind;
    /**
     * Regtest only: addresses that stand in for the onion services Tor would
     * create, used in order as the identity is replaced (-holepunchcoordonion).
     */
    std::vector<CService> coordination_services;
};

/** The wildcard address of `family` (NET_IPV4 or NET_IPV6) with `port`. */
CService WildcardAddress(Network family, uint16_t port);

// Limits of the punch procedure (draft section 10).
/** Attempts are made for this long after `punch` was received (R-5.4). */
inline constexpr auto WINDOW{std::chrono::seconds{15}};
/** Pause between attempts after an immediate failure (R-5.5). */
inline constexpr auto RETRY{std::chrono::seconds{1}};
/** How long the peer's connection may still arrive after the window (R-5.11). */
inline constexpr auto GRACE{std::chrono::seconds{2}};
/** How long an accepted connection that matches no session is kept, in case
 * the `punch` for it is still on its way. */
inline constexpr auto HOLD{std::chrono::seconds{2}};
inline constexpr size_t MAX_ACTIVE_SESSIONS{2};
inline constexpr size_t SESSIONS_PER_MIN{4};
inline constexpr auto PER_ADDR_INTERVAL{std::chrono::minutes{10}};
/** Hole-punched outbound connections a node holds at most (R-8.1). */
inline constexpr int HP_OUTBOUND_MAX{1};
/** How long a connector waits for the answer to a rendezvous (R-4.4, R-7.3). */
inline constexpr auto COORD_TIMEOUT{std::chrono::seconds{10}};
/** Coordination connections an advertiser accepts at once (R-12.2). */
inline constexpr size_t COORD_INBOUND_MAX{8};

/** Cache limits for announcements (R-6.2). */
inline constexpr size_t CACHE_MAX{32};
inline constexpr size_t CACHE_PER_PEER{4};
inline constexpr auto CACHE_TTL{std::chrono::minutes{10}};
/** An advertiser announces at most this often per peer (R-6.5). */
inline constexpr auto ANNOUNCE_INTERVAL{std::chrono::minutes{10}};
/** The longest a coordination onion identity is announced (R-12.1); the actual lifetime is drawn below this, so that nodes do not all rotate at once. */
inline constexpr auto ONION_MAX_LIFETIME{std::chrono::hours{24}};
/** How long a replaced coordination onion identity stays reachable: the cache lifetime plus the clock skew allowance of R-6.2 (R-12.1). */
inline constexpr auto ONION_RETIRE{CACHE_TTL + std::chrono::minutes{10}};
/** A connector starts at most one coordination attempt per this interval (R-7.2). */
inline constexpr auto HP_ATTEMPT_INTERVAL{std::chrono::minutes{5}};

/** A hole punching announcement received from a peer: a HOLEPUNCH address element taken apart. */
struct Announcement {
    /** The coordinator through which the node can be reached. */
    CService coordinator;
    /** The announced node's endpoint. */
    CService target;
    ServiceFlags services;
    NodeSeconds time;
    /** The peer the element came from. */
    NodeId from;
};

/**
 * Short-lived store of announcements (R-6.2): at most CACHE_MAX entries,
 * CACHE_PER_PEER from one peer, each expiring CACHE_TTL after its time. Nothing
 * here is ever persisted or handed to the address manager.
 */
class AnnouncementCache
{
public:
    /**
     * Add an element. Rejected if it is not a well formed HOLEPUNCH address, its
     * time is outside the relay window, or the peer's share is used up. A
     * newer element for the same coordinator and target replaces the old one.
     * @param[in] allow_local Accept non-routable targets (test networks).
     * @return the announcement if it was added.
     */
    std::optional<Announcement> Add(NodeId from, const CAddress& element, NodeClock::time_point now, bool allow_local)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** All announcements that have not expired, oldest first. */
    std::vector<Announcement> Get(NodeClock::time_point now) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Remove and return a random announcement among those `eligible` (R-7.1, R-7.2). */
    std::optional<Announcement> Take(NodeClock::time_point now, const std::function<bool(const Announcement&)>& eligible, FastRandomContext& rng)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    size_t Size() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    void Expire(NodeClock::time_point now) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    mutable Mutex m_mutex;
    /** Insertion order, oldest first. */
    std::vector<Announcement> m_entries GUARDED_BY(m_mutex);
};

/**
 * Runs the punch procedure (draft section 5): listens on the punch port, makes
 * the connect attempts of each session from the punch port, and hands over the
 * connection that comes out of it. Everything happens on its own thread; the
 * result callback runs there too.
 *
 * A session is keyed by the peer's endpoint. It ends in success, when a
 * connection with exactly that remote endpoint exists (from our connect() or
 * from the listener), or in failure after WINDOW + GRACE.
 */
class SessionManager
{
public:
    /**
     * Called when a session ends: with the connection on success, with nullptr on failure.
     * `deadline` is the session's deadline (R-5.11): the connection's handshake must be
     * complete by then too.
     */
    using ResultFn = std::function<void(const CService& peer, Role role, std::shared_ptr<Sock> sock, NodeClock::time_point deadline)>;

    SessionManager(const Options& opts, ResultFn on_result);
    ~SessionManager() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Open the punch listeners and start the thread. False if no listener could be opened. */
    bool Start() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Stop the thread and close everything; pending sessions fail without a callback. */
    void Stop() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Start a session with `peer` in `role`. Applies the limits of R-5.1 that
     * concern sessions (duplicate, concurrent, per minute, per address).
     * @return the reason if the session was not started.
     */
    std::optional<std::string> Punch(Role role, const CService& peer) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

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

private:
    struct Session {
        Role role;
        CService peer;
        NodeClock::time_point started;
        /** No new attempts after this (started + WINDOW). */
        NodeClock::time_point deadline;
        /** When to make the next attempt; none while `attempt` is pending. */
        NodeClock::time_point next_attempt;
        /** The pending connect(), if any. */
        std::shared_ptr<Sock> attempt;
        int attempts{0};
        /** Set when connect() refused the 4-tuple: the listener has the connection (R-5.6). */
        bool wait_for_accept{false};
    };
    /** An accepted connection that matched no session when it arrived. */
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
    /** The key for the per-address rate limit (R-5.1). */
    CService AddrKey(const CService& peer) const;

    const Options m_opts;
    const ResultFn m_on_result;
    std::vector<std::shared_ptr<Sock>> m_listeners;
    mutable Mutex m_mutex;
    std::map<CService, Session> m_sessions GUARDED_BY(m_mutex);
    std::vector<Held> m_held GUARDED_BY(m_mutex);
    /** Start times of recent sessions, for SESSIONS_PER_MIN. */
    std::deque<NodeClock::time_point> m_recent_starts GUARDED_BY(m_mutex);
    /** Last session start per address, for PER_ADDR_INTERVAL. */
    std::map<CService, NodeClock::time_point> m_last_start GUARDED_BY(m_mutex);
    CThreadInterrupt m_interrupt;
    std::thread m_thread;
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
