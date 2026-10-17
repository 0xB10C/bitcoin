// Copyright (c) 2015-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Functionality for communicating with Tor.
 */
#ifndef BITCOIN_TORCONTROL_H
#define BITCOIN_TORCONTROL_H

#include <netaddress.h>
#include <util/fs.h>
#include <util/sock.h>
#include <util/threadinterrupt.h>

#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <chrono>
#include <optional>
#include <string>
#include <util/time.h>
#include <thread>
#include <vector>

inline constexpr uint16_t DEFAULT_TOR_SOCKS_PORT{9050};
inline constexpr int DEFAULT_TOR_CONTROL_PORT = 9051;
extern const std::string DEFAULT_TOR_CONTROL;
inline constexpr bool DEFAULT_LISTEN_ONION = true;

/** Tor control reply code. Ref: https://spec.torproject.org/control-spec/replies.html */
inline constexpr int TOR_REPLY_OK{250};
inline constexpr int TOR_REPLY_UNRECOGNIZED{510};
inline constexpr int TOR_REPLY_SYNTAX_ERROR{512}; //!< Syntax error in command argument

CService DefaultOnionServiceTarget(uint16_t port);

/** Reply from Tor, can be single or multi-line */
class TorControlReply
{
public:
    TorControlReply() { Clear(); }

    int code;
    std::vector<std::string> lines;

    void Clear()
    {
        code = 0;
        lines.clear();
    }
};

/** Low-level handling for Tor control connection.
 * Speaks the SMTP-like protocol as defined in torspec/control-spec.txt
 */
class TorControlConnection
{
public:
    typedef std::function<void(TorControlConnection &,const TorControlReply &)> ReplyHandlerCB;
    /** Handler for asynchronous notifications (reply codes 600 and up), as enabled with SETEVENTS. */
    using AsyncHandlerCB = std::function<void(TorControlConnection&, const TorControlReply&)>;

    /** Create a new TorControlConnection.
     */
    explicit TorControlConnection(CThreadInterrupt& interrupt);
    ~TorControlConnection();

    /**
     * Connect to a Tor control port.
     * tor_control_center is address of the form host:port.
     * Return true on success.
     */
    bool Connect(const std::string& tor_control_center);

    /**
     * Disconnect from Tor control port.
     */
    void Disconnect();

    /** Send a command, register a handler for the reply.
     * A trailing CRLF is automatically added.
     * Return true on success.
     */
    bool Command(const std::string &cmd, const ReplyHandlerCB& reply_handler);
    /** Receive asynchronous notifications. */
    void SetAsyncHandler(AsyncHandlerCB handler) { m_async_handler = std::move(handler); }

    /**
     * Check if the connection is established.
     */
    bool IsConnected() const;

    /**
     * Wait for data to be available on the socket.
     * @param[in] timeout Maximum time to wait
     * @return true if data is available, false on timeout or error
     */
    bool WaitForData(std::chrono::milliseconds timeout);

    /**
     * Read available data from socket and process complete replies.
     * Dispatches to registered reply handlers.
     * @return true if connection is still open, false if connection was closed
     */
    bool ReceiveAndProcess();

private:
    /** Reference to interrupt object for clean shutdown */
    CThreadInterrupt& m_interrupt;
    /** Socket for the connection */
    std::unique_ptr<Sock> m_sock;
    /** Message being received */
    TorControlReply m_message;
    /** Response handlers */
    std::deque<ReplyHandlerCB> m_reply_handlers;
    /** Handler for asynchronous notifications, if any. */
    AsyncHandlerCB m_async_handler;
    /** Buffer for incoming data */
    std::string m_recv_buffer;
    /** Process complete lines from the receive buffer */
    bool ProcessBuffer();
};

/****** Bitcoin specific TorController implementation ********/

/** How a TorController runs its onion service. */
struct TorServiceOptions {
    /** Generate a fresh key every time and keep nothing on disk. */
    bool ephemeral{false};
    /** Add the service to the local addresses advertised to peers. */
    bool advertise{true};
    /**
     * Only report the service once Tor says its descriptor is uploaded, so that
     * others can reach it by the time they are told about it. Needs Tor's HS_DESC
     * events, which the controller subscribes to.
     */
    bool wait_for_descriptor{false};
    /** How long a service replaced by Rotate() stays up before it is deleted. */
    std::chrono::seconds keep_previous{0};
    /** Called with the service address once it is up, and with an invalid one when it is gone. */
    std::function<void(const CService&)> on_service;
};

/**
 * The onion address of an HS_DESC UPLOADED notification line (without the
 * leading reply code), or nullopt for any other line.
 */
std::optional<std::string> ParseHsDescUploaded(const std::string& line);

/** Controller that connects to Tor control socket, authenticate, then create
 * and maintain an ephemeral onion service.
 */
class TorController
{
public:
    TorController(const std::string& tor_control_center, const CService& target, TorServiceOptions options = {});
    TorController() : m_conn(m_interrupt) {
        // Used for testing only.
    }
    ~TorController();

    /**
     * Replace the service by one with a fresh key. The old one stays up for
     * `keep_previous`, then is deleted. The new one is reported through
     * `on_service` like the first. May be called from any thread.
     */
    void Rotate() { m_rotate_requested = true; }

    /** Get name of file to store private key in */
    fs::path GetPrivateKeyFile();

    /** Interrupt the controller thread */
    void Interrupt();

    /** Wait for the controller thread to exit */
    void Join();
private:
    CThreadInterrupt m_interrupt;
    std::thread m_thread;
    const std::string m_tor_control_center;
    TorControlConnection m_conn;
    std::string m_private_key;
    std::string m_service_id;
    /** Whether `on_service` has been called for the current service. */
    bool m_service_reported{false};
    std::atomic<bool> m_rotate_requested{false};
    /** Replaced services, with the time to delete them. Control thread only. */
    std::vector<std::pair<std::string, NodeClock::time_point>> m_retiring;
    std::atomic<bool> m_reconnect;
    std::chrono::duration<double> m_reconnect_timeout;
    CService m_service;
    const CService m_target;
    const TorServiceOptions m_options;
    /** Cookie for SAFECOOKIE auth */
    std::vector<uint8_t> m_cookie;
    /** ClientNonce for SAFECOOKIE auth */
    std::vector<uint8_t> m_client_nonce;

    /// \anchor torcontrol
    void ThreadControl();
    /** Periodic work on the control thread: rotation requests and retiring services. */
    void Tick();
    /** Issue ADD_ONION for a fresh key. */
    void RequestOnion(const std::string& private_key);
    /** Report the current service through `on_service`, once. */
    void ReportService();
    void async_cb(TorControlConnection& conn, const TorControlReply& reply);

public:
    /** Callback for GETINFO net/listeners/socks result */
    void get_socks_cb(TorControlConnection& conn, const TorControlReply& reply);
    /** Callback for ADD_ONION result */
    void add_onion_cb(TorControlConnection& conn, const TorControlReply& reply, bool pow_was_enabled);
    /** Callback for AUTHENTICATE result */
    void auth_cb(TorControlConnection& conn, const TorControlReply& reply);
    /** Callback for AUTHCHALLENGE result */
    void authchallenge_cb(TorControlConnection& conn, const TorControlReply& reply);
    /** Callback for PROTOCOLINFO result */
    void protocolinfo_cb(TorControlConnection& conn, const TorControlReply& reply);
    /** Callback after successful connection */
    void connected_cb(TorControlConnection& conn);
    /** Callback after connection lost or failed connection attempt */
    void disconnected_cb(TorControlConnection& conn);
};

#endif // BITCOIN_TORCONTROL_H
