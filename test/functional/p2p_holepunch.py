#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test TCP hole punching (-holepunch)."""

import socket
import threading

from test_framework.messages import (
    CAddress,
    NODE_NETWORK,
    NODE_P2P_V2,
    msg_addrv2,
    msg_feature,
    msg_getaddr,
    msg_punch,
    msg_rendezvous,
    msg_verack,
)
from test_framework.p2p import (
    EncryptedP2PState,
    P2PInterface,
)
from test_framework.socks5 import start_socks5_server
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    MAX_NODES,
    assert_equal,
    assert_raises_rpc_error,
    holepunch_coord_port,
    holepunch_port,
    p2p_port,
    tor_port,
)

import time


HOLEPUNCH_FEATURE_ID = "https://delvingbitcoin.org/t/2497"
ONION = "kpgvmsfpi2usww3uw74pnpj3xbxf3gvxprpq4a5fwq5bws5662wbv3ad.onion"
CAP_COORDINATOR = 1 << 0
CAP_ADVERTISED = 1 << 1
CAP_PUNCHPORT = 1 << 4


def feature_data(caps, version=0):
    return version.to_bytes(1, "little") + caps.to_bytes(4, "little")


def endpoint(ip, port):
    addr = CAddress()
    addr.net = CAddress.NET_IPV6 if ":" in ip else CAddress.NET_IPV4
    addr.ip = ip
    addr.port = port
    return addr


def onion_endpoint(onion, port):
    addr = CAddress()
    addr.net = CAddress.NET_TORV3
    addr.ip = onion
    addr.port = port
    return addr


def endpoint_from_str(addr_port):
    ip, port = addr_port.rsplit(":", 1)
    return endpoint(ip, int(port))


def addrv2(addrs):
    msg = msg_addrv2()
    msg.addrs = addrs
    return msg


def announcement(coordinator, target, timestamp=None):
    """A HOLEPUNCH addrv2 element: `coordinator` and `target` are CAddress endpoints."""
    addr = CAddress()
    addr.net = CAddress.NET_HOLEPUNCH
    addr.coordinator = coordinator
    addr.ip = target.ip
    addr.port = target.port
    addr.nServices = NODE_NETWORK | NODE_P2P_V2
    addr.time = int(time.time()) if timestamp is None else timestamp
    return addr


class ReportingPeer(P2PInterface):
    """A test peer that reports the node's address in version.addr_recv.

    By default it reports what it sees on the socket, which is what a real
    peer does. A different report can be given to play a lying peer."""

    def __init__(self, report=None, **kwargs):
        super().__init__(**kwargs)
        self.report = report

    def connection_made(self, transport):
        # The version message is prepared before the socket exists; fill in the
        # node's address as seen from this side before it is sent.
        them = transport.get_extra_info("socket").getpeername()
        ip, port = self.report or (them[0], them[1])
        if self.on_connection_send_msg is not None:
            self.on_connection_send_msg.addrTo.ip = ip
            self.on_connection_send_msg.addrTo.port = port
        super().connection_made(transport)


class HolePunchPeer(ReportingPeer):
    """A test peer that announces hole punching capabilities and records the node's
    feature, announcements and rendezvous requests."""

    def __init__(self, caps=None, raw_feature_data=None, report=None, support_addrv2=False):
        super().__init__(report=report)
        self.support_addrv2 = support_addrv2
        self.caps = caps
        self.raw_feature_data = raw_feature_data
        self.holepunch_feature = None
        self.announcements = []
        self.rendezvous = []

    def on_addrv2(self, message):
        self.announcements += [a for a in message.addrs if a.net == CAddress.NET_HOLEPUNCH]

    def on_rendezvous(self, message):
        self.rendezvous.append(message)

    def on_version(self, message):
        # The feature has to go out after our version and before our verack, which
        # super().on_version() sends.
        if not self.p2p_connected_to_node:
            self.send_version()
        if self.raw_feature_data is not None:
            self.send_without_ping(msg_feature(HOLEPUNCH_FEATURE_ID, self.raw_feature_data))
        elif self.caps is not None:
            self.send_without_ping(msg_feature(HOLEPUNCH_FEATURE_ID, feature_data(self.caps)))
        super().on_version(message)

    def on_feature(self, message):
        if message.feature_id == HOLEPUNCH_FEATURE_ID:
            self.holepunch_feature = message.feature_data


class CoordinationPeer(HolePunchPeer):
    """A test peer on a coordination connection: it negotiates the feature and
    sends nothing else, in particular no getaddr after verack."""

    def on_version(self, message):
        if not self.p2p_connected_to_node:
            self.send_version()
        self.send_without_ping(msg_feature(HOLEPUNCH_FEATURE_ID, feature_data(self.caps)))
        self.send_without_ping(msg_verack())
        self.nServices = message.nServices


class PunchInitiatorPeer(HolePunchPeer):
    """A test peer at the other end of a punched connection, in the initiator
    role: it accepts the node's TCP connection but speaks first, as the BIP 324
    initiator, and sends version first."""

    def peer_accept_connection(self, *args, net, **kwargs):
        create = super().peer_accept_connection(*args, net=net, **kwargs)
        if self.v2_state is not None:
            self.v2_state = EncryptedP2PState(initiating=True, net=net)
        self.p2p_connected_to_node = True
        return create


class HolePunchTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[
            "-v2transport=1",
            "-holepunch=1",
            f"-holepunchport={holepunch_port(0)}",
            f"-holepunchcoordbind=127.0.0.1:{holepunch_coord_port(0)}",
            f"-holepunchcoordonion={ONION}",  # as if Tor had created the coordination service
            f"-bind=127.0.0.1:{tor_port(0)}=onion",  # the config file's bind= suppresses the default onion bind
            "-whitelist=addr@127.0.0.1",  # no address rate limit for inbound test peers
        ]]

    def setup_nodes(self):
        # A fake Tor proxy: connections to an onion address are redirected to
        # whatever self.proxy_destinations maps it to.
        self.proxy_destinations = {}

        def destinations_factory(requested_to_addr, requested_to_port, proxy_client):
            dest = self.proxy_destinations.get(requested_to_addr)
            if dest is None:
                return None
            return {"actual_to_addr": dest[0], "actual_to_port": dest[1]}

        self.socks5_server = start_socks5_server(destinations_factory)
        self.extra_args[0].append(f"-onion={self.socks5_server.conf.addr[0]}:{self.socks5_server.conf.addr[1]}")
        super().setup_nodes()

    def listen(self, peer, idx):
        """Make `peer` listen for a connection from the node. Returns its port."""
        listening = threading.Event()
        peer.peer_accept_connection(
            connect_cb=lambda address, port: listening.set(), connect_id=idx, net=self.chain,
            timeout_factor=self.options.timeout_factor, supports_v2_p2p=True, reconnect=False)()
        assert listening.wait(timeout=10 * self.options.timeout_factor)
        return p2p_port(MAX_NODES - idx)

    def test_outbound_from_punch_port(self):
        node = self.nodes[0]
        punch_port = holepunch_port(0)

        # For a connection accepted by a test peer, dstport is the node's source port as
        # the peer sees it: the port that version.addr_recv will report back.
        self.log.info("Outbound connections are made from the punch port")
        peer1 = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=0)
        assert_equal(peer1.dstport, punch_port)
        outbound = [p for p in node.getpeerinfo() if not p["inbound"]]
        assert_equal(len(outbound), 1)
        assert_equal(outbound[0]["addrbind"], f"127.0.0.1:{punch_port}")

        self.log.info("Several outbound connections share the punch port")
        peer2 = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=1)
        assert_equal(peer2.dstport, punch_port)

        self.log.info("Inbound connections are not affected")
        node.add_p2p_connection(P2PInterface())
        inbound = [p for p in node.getpeerinfo() if p["inbound"]]
        assert_equal(len(inbound), 1)
        assert inbound[0]["addrbind"] != f"127.0.0.1:{punch_port}"

        node.disconnect_p2ps()

    def external(self, node, network="ipv4"):
        return next(e for e in node.getholepunchinfo()["external"] if e["network"] == network)

    def test_external_address(self):
        node = self.nodes[0]
        punch_port = holepunch_port(0)
        info = node.getholepunchinfo()
        assert_equal(info["enabled"], True)
        assert_equal(info["port"], punch_port)
        assert_equal(self.external(node)["reports"], 0)
        assert "address" not in self.external(node)

        self.log.info("One peer reporting our address is not enough")
        node.add_outbound_p2p_connection(ReportingPeer(), p2p_idx=0)
        assert_equal(self.external(node)["reports"], 1)
        assert "address" not in self.external(node)

        self.log.info("Two peers agreeing on our address yield the external address")
        node.add_outbound_p2p_connection(ReportingPeer(), p2p_idx=1)
        assert_equal(self.external(node)["address"], f"127.0.0.1:{punch_port}")
        assert_equal(self.external(node)["reporters"], 2)

        self.log.info("A single peer reporting a different port is ignored")
        liar1 = node.add_outbound_p2p_connection(ReportingPeer(report=("127.0.0.1", 40001)), p2p_idx=2)
        assert_equal(self.external(node)["address"], f"127.0.0.1:{punch_port}")
        assert_equal(self.external(node)["reports"], 3)
        assert_equal(self.external(node)["conflicting"], False)

        self.log.info("Two peers agreeing on a different port rule out an external address")
        liar2 = node.add_outbound_p2p_connection(ReportingPeer(report=("127.0.0.1", 40001)), p2p_idx=3)
        assert "address" not in self.external(node)
        assert_equal(self.external(node)["conflicting"], True)

        self.log.info("Reports of disconnected peers are dropped")
        liar1.peer_disconnect()
        liar2.peer_disconnect()
        self.wait_until(lambda: self.external(node)["reports"] == 2)
        assert_equal(self.external(node)["address"], f"127.0.0.1:{punch_port}")

        self.log.info("Reports from inbound peers do not count")
        node.add_p2p_connection(ReportingPeer(report=("127.0.0.1", 40001)))
        assert_equal(self.external(node)["reports"], 2)

        node.disconnect_p2ps()
        self.wait_until(lambda: self.external(node)["reports"] == 0)

    def test_coordination_connection(self):
        node = self.nodes[0]
        self.log.info("A coordination connection is made from the punch port and negotiates only the feature")
        peer = node.add_outbound_p2p_connection(CoordinationPeer(caps=CAP_COORDINATOR), p2p_idx=0, connection_type="holepunch-coordination")
        assert_equal(peer.dstport, holepunch_port(0))
        # The connection is not kept, so the node does not offer to be advertised through it.
        assert_equal(peer.holepunch_feature, feature_data(CAP_PUNCHPORT))
        info = next(p for p in node.getpeerinfo() if p["connection_type"] == "holepunch-coordination")
        assert_equal(info["inbound"], False)
        assert_equal(info["holepunch_caps"], ["COORDINATOR"])
        assert set(peer.message_count) <= {"version", "feature", "verack", "pong"}, peer.message_count
        self.log.info("It takes no outbound slot")
        assert_equal(node.getnetworkinfo()["connections_out"], 0)

        self.log.info("Whatever else a clearnet coordinator sends is ignored: it is an ordinary node")
        with node.assert_debug_log(["ignoring getaddr on the coordination connection"], timeout=5):
            peer.send_without_ping(msg_getaddr())
        peer.sync_with_ping()

        self.log.info("It is closed when nothing came of it within COORD_TIMEOUT")
        with node.assert_debug_log(["coordination timed out"], timeout=5):
            node.setmocktime(int(time.time()) + 11)
            peer.wait_for_disconnect()
        node.setmocktime(0)
        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

    def test_coordination_bind(self):
        node = self.nodes[0]
        coord_port = holepunch_coord_port(0)
        self.log.info("getholepunchinfo shows the coordination bind and the onion service")
        assert_equal(node.getholepunchinfo()["coordination"], {"bind": f"127.0.0.1:{coord_port}", "onion": f"{ONION}:18444"})
        self.log.info("A connection to the coordination bind is a coordination connection reached through Tor")
        peer = node.add_p2p_connection(CoordinationPeer(caps=0), dstport=coord_port)
        info = next(p for p in node.getpeerinfo() if p["connection_type"] == "holepunch-coordination")
        assert_equal(info["inbound"], True)
        assert_equal(info["network"], "onion")
        # On the accepting side the node answers rendezvous, and it observes nothing about the peer.
        assert_equal(peer.holepunch_feature, feature_data(CAP_COORDINATOR))
        assert set(peer.message_count) <= {"version", "feature", "verack", "pong"}, peer.message_count
        self.log.info("It takes no inbound slot")
        assert_equal(node.getnetworkinfo()["connections_in"], 0)

        self.log.info("At most COORD_INBOUND_MAX coordination connections are held")
        for _ in range(7):
            node.add_p2p_connection(CoordinationPeer(caps=0), dstport=coord_port)
        with node.assert_debug_log(["coordination connection dropped: 8 are open already"], timeout=5):
            node.add_p2p_connection(CoordinationPeer(caps=0), dstport=coord_port, send_version=False, wait_for_verack=False, expect_success=False)
        assert_equal(len([p for p in node.getpeerinfo() if p["connection_type"] == "holepunch-coordination"]), 8)

        self.log.info("Any message other than ping, pong, rendezvous and punch closes it")
        with node.assert_debug_log(["getaddr on a coordination connection"], timeout=5):
            peer.send_without_ping(msg_getaddr())
            peer.wait_for_disconnect()
        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

    def test_feature_negotiation(self):
        node = self.nodes[0]

        self.log.info("The node announces COORDINATOR to inbound peers")
        peer = node.add_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR))
        assert_equal(peer.holepunch_feature, feature_data(CAP_COORDINATOR))
        self.log.info("A peer's capabilities show up in getpeerinfo")
        assert_equal(node.getpeerinfo()[-1]["holepunch_caps"], ["COORDINATOR"])

        self.log.info("The node announces COORDINATOR, ADVERTISED and PUNCHPORT on outbound connections from the punch port")
        peer = node.add_outbound_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR | CAP_PUNCHPORT), p2p_idx=0)
        assert_equal(peer.holepunch_feature, feature_data(CAP_COORDINATOR | CAP_ADVERTISED | CAP_PUNCHPORT))
        outbound = [p for p in node.getpeerinfo() if not p["inbound"]]
        assert_equal(outbound[0]["holepunch_caps"], ["COORDINATOR", "PUNCHPORT"])

        self.log.info("Unknown capability bits are ignored")
        node.add_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR | (1 << 31)))
        assert_equal(node.getpeerinfo()[-1]["holepunch_caps"], ["COORDINATOR"])

        self.log.info("Bytes after the known fields are ignored (future versions)")
        node.add_p2p_connection(HolePunchPeer(raw_feature_data=feature_data(CAP_COORDINATOR) + b"\x00\x01"))
        assert_equal(node.getpeerinfo()[-1]["holepunch_caps"], ["COORDINATOR"])

        self.log.info("A peer on a higher version negotiates the lower one, ours")
        with node.assert_debug_log(["supports hole punching up to version 3, negotiated 0"], timeout=5):
            node.add_p2p_connection(HolePunchPeer(raw_feature_data=feature_data(CAP_COORDINATOR, version=3)))
        assert_equal(node.getpeerinfo()[-1]["holepunch_caps"], ["COORDINATOR"])

        self.log.info("No feature is sent on feelers and address fetches")
        feeler = node.add_outbound_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR), p2p_idx=2, connection_type="feeler", wait_for_verack=False)
        feeler.wait_for_disconnect()
        assert "version" in feeler.message_count
        assert_equal(feeler.holepunch_feature, None)
        fetch = node.add_outbound_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR), p2p_idx=3, connection_type="addr-fetch")
        fetch.sync_with_ping()
        assert_equal(fetch.holepunch_feature, None)
        fetch.peer_disconnect()

        self.log.info("A peer without the feature has no holepunch_caps")
        node.add_p2p_connection(P2PInterface())
        assert "holepunch_caps" not in node.getpeerinfo()[-1]

        self.log.info("Truncated feature data disconnects the peer")
        with node.assert_debug_log(["invalid hole punching feature data"], timeout=5):
            peer = node.add_p2p_connection(HolePunchPeer(raw_feature_data=b"\x00\x01"), wait_for_verack=False)
            peer.wait_for_disconnect()

        node.disconnect_p2ps()

    def listen_for_punch(self, idx, v2=True):
        """Start a PunchInitiatorPeer listening where the node will punch to. Returns it and its port."""
        peer = PunchInitiatorPeer()
        listening = threading.Event()
        peer.peer_accept_connection(
            connect_cb=lambda address, port: listening.set(), connect_id=idx, net=self.chain,
            timeout_factor=self.options.timeout_factor, supports_v2_p2p=v2, reconnect=False)()
        assert listening.wait(timeout=10 * self.options.timeout_factor)
        return peer, p2p_port(MAX_NODES - idx)

    def wait_for_punched_connection(self, peer):
        peer.wait_for_connect()
        peer.wait_until(lambda: peer.v2_state.tried_v2_handshake)
        peer.wait_for_verack()
        peer.sync_with_ping()

    def test_punch_as_responder(self):
        node = self.nodes[0]
        punch_port = holepunch_port(0)
        # On this connection the node announced ADVERTISED, so it accepts punch requests.
        coordinator = node.add_outbound_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR), p2p_idx=0)
        # A second reporting peer, so that the node knows its external address.
        node.add_outbound_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR), p2p_idx=1)
        assert_equal(self.external(node)["address"], f"127.0.0.1:{punch_port}")
        listener, port = self.listen_for_punch(idx=5)

        self.log.info("A punch as responder starts a session; the node connects from its punch port")
        with node.assert_debug_log([f"session with 127.0.0.1:{port} started as responder"], timeout=5):
            coordinator.send_without_ping(msg_punch(msg_punch.ROLE_RESPONDER, endpoint("127.0.0.1", port)))
        self.wait_for_punched_connection(listener)
        assert_equal(listener.dstport, punch_port)
        punched = [p for p in node.getpeerinfo() if p["hole_punched"]]
        assert_equal(len(punched), 1)
        assert_equal(punched[0]["inbound"], True)
        assert_equal(punched[0]["addr"], f"127.0.0.1:{port}")
        assert_equal(punched[0]["transport_protocol_type"], "v2")
        self.log.info("The punched peer negotiates the feature like any other")
        assert_equal(listener.holepunch_feature, feature_data(CAP_COORDINATOR))

        self.log.info("A punched peer that speaks the v1 transport is disconnected")
        v1_listener, v1_port = self.listen_for_punch(idx=7, v2=False)
        with node.assert_debug_log(["punched connection uses the v1 transport"], timeout=10):
            coordinator.send_without_ping(msg_punch(msg_punch.ROLE_RESPONDER, endpoint("127.0.0.1", v1_port)))
            v1_listener.wait_for_connect()
            v1_listener.wait_for_disconnect()
        assert_equal(len([p for p in node.getpeerinfo() if p["hole_punched"]]), 1)

        self.log.info("Punch requests that fail validation are ignored")
        for punch, reason in [
            (msg_punch(msg_punch.ROLE_INITIATOR, endpoint("127.0.0.1", 40000)), "unsolicited punch with initiator role"),
            (msg_punch(msg_punch.ROLE_RESPONDER, endpoint("127.0.0.1", 0)), "peer has port 0"),
            (msg_punch(msg_punch.ROLE_RESPONDER, endpoint("127.0.0.1", 6667)), "peer has a bad port"),
            (msg_punch(msg_punch.ROLE_RESPONDER, endpoint("127.0.0.1", punch_port)), "peer is our own external address"),
        ]:
            with node.assert_debug_log(["ignoring punch from peer=", reason], timeout=5):
                coordinator.send_and_ping(punch)

        self.log.info("A punch as responder on a connection without ADVERTISED is ignored")
        inbound = node.add_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR))
        with node.assert_debug_log(["unsolicited punch without ADVERTISED"], timeout=5):
            inbound.send_and_ping(msg_punch(msg_punch.ROLE_RESPONDER, endpoint("127.0.0.1", 40000)))

        self.log.info("A malformed punch disconnects the peer")
        with node.assert_debug_log(["malformed punch"], timeout=5):
            inbound.send_without_ping(msg_punch(5, endpoint("127.0.0.1", 40000)))
            inbound.wait_for_disconnect()

        self.log.info("A punch without negotiated feature disconnects the peer")
        plain = node.add_p2p_connection(P2PInterface())
        with node.assert_debug_log(["punch without negotiated feature"], timeout=5):
            plain.send_without_ping(msg_punch(msg_punch.ROLE_RESPONDER, endpoint("127.0.0.1", 40000)))
            plain.wait_for_disconnect()

        listener.peer_disconnect()
        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

    def test_own_coordinator(self):
        node = self.nodes[0]
        coord_port = holepunch_coord_port(0)
        # Two reporting peers, so that the node knows its external address.
        node.add_outbound_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR), p2p_idx=0)
        node.add_outbound_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR), p2p_idx=1)
        external = endpoint_from_str(self.external(node)["address"])
        listener, port = self.listen_for_punch(idx=9)

        self.log.info("A rendezvous on the coordination bind is answered by the node itself")
        requester = node.add_p2p_connection(CoordinationPeer(caps=0), dstport=coord_port)
        with node.assert_debug_log([f"session with 127.0.0.1:{port} started as responder", "punch sent, disconnecting"], timeout=5):
            requester.send_without_ping(msg_rendezvous(external, endpoint("127.0.0.1", port)))
            requester.wait_for_disconnect()
        punch = requester.last_message["punch"]
        assert_equal(punch.role, msg_punch.ROLE_INITIATOR)
        assert_equal((punch.peer.ip, punch.peer.port), (external.ip, external.port))
        self.wait_for_punched_connection(listener)
        punched = [p for p in node.getpeerinfo() if p["hole_punched"]]
        assert_equal(len(punched), 1)
        assert_equal(punched[0]["inbound"], True)
        assert_equal(punched[0]["addr"], f"127.0.0.1:{port}")

        self.log.info("Rendezvous that fail validation are ignored")
        for target, who, reason in [
            (endpoint("127.0.0.1", 40000), endpoint("127.0.0.1", 40001), "target 127.0.0.1:40000 is not our external address"),
            (external, endpoint("127.0.0.1", 0), "peer has port 0"),
            (external, external, "peer is our own external address"),
            (external, endpoint("127.0.0.1", port), "a session with this address was started recently"),
        ]:
            requester = node.add_p2p_connection(CoordinationPeer(caps=0), dstport=coord_port)
            with node.assert_debug_log(["ignoring rendezvous from peer=", reason], timeout=5):
                requester.send_and_ping(msg_rendezvous(target, who))
            requester.peer_disconnect()
        listener.peer_disconnect()
        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

    def test_coordinator(self):
        node = self.nodes[0]

        def connect(caps):
            peer = node.add_p2p_connection(HolePunchPeer(caps=caps))
            return peer, node.getpeerinfo()[-1]["addr"]

        advertised, advertised_addr = connect(CAP_ADVERTISED | CAP_PUNCHPORT)
        connector, connector_addr = connect(CAP_PUNCHPORT)

        self.log.info("A rendezvous naming an advertised peer makes the coordinator punch both")
        with node.assert_debug_log(["punch sent to it as initiator"], timeout=5):
            connector.send_and_ping(msg_rendezvous(endpoint_from_str(advertised_addr), endpoint_from_str(connector_addr)))
        advertised.wait_until(lambda: "punch" in advertised.last_message)
        connector.wait_until(lambda: "punch" in connector.last_message)
        assert_equal(advertised.last_message["punch"].role, msg_punch.ROLE_RESPONDER)
        assert_equal(advertised.last_message["punch"].peer, endpoint_from_str(connector_addr))
        assert_equal(connector.last_message["punch"].role, msg_punch.ROLE_INITIATOR)
        assert_equal(connector.last_message["punch"].peer, endpoint_from_str(advertised_addr))

        self.log.info("Rendezvous requests that fail validation are ignored")
        other, other_addr = connect(CAP_PUNCHPORT)
        without_punchport, without_punchport_addr = connect(CAP_COORDINATOR)
        for peer, msg, reason in [
            (other, msg_rendezvous(endpoint("127.0.0.1", 40000), endpoint_from_str(other_addr)), "no advertised peer with that endpoint"),
            (other, msg_rendezvous(endpoint_from_str(connector_addr), endpoint_from_str(other_addr)), "no advertised peer with that endpoint"),
            (other, msg_rendezvous(endpoint_from_str(advertised_addr), endpoint("127.0.0.1", 1)), "differs from the observed endpoint"),
            (other, msg_rendezvous(endpoint_from_str(advertised_addr), endpoint_from_str(other_addr)), "a punch was sent to the target recently"),
            (connector, msg_rendezvous(endpoint_from_str(advertised_addr), endpoint_from_str(connector_addr)), "a punch was sent to the requester recently"),
            (without_punchport, msg_rendezvous(endpoint_from_str(advertised_addr), endpoint_from_str(without_punchport_addr)), "requester did not announce PUNCHPORT"),
        ]:
            with node.assert_debug_log(["ignoring rendezvous from peer=", reason], timeout=5):
                peer.send_and_ping(msg)

        self.log.info("A malformed rendezvous disconnects the peer")
        with node.assert_debug_log(["malformed rendezvous"], timeout=5):
            other.send_without_ping(msg_rendezvous(endpoint_from_str(advertised_addr), endpoint("::1", 1)))
            other.wait_for_disconnect()

        self.log.info("A rendezvous without negotiated feature disconnects the peer")
        plain = node.add_p2p_connection(P2PInterface())
        with node.assert_debug_log(["rendezvous without negotiated feature"], timeout=5):
            plain.send_without_ping(msg_rendezvous(endpoint_from_str(advertised_addr), endpoint("127.0.0.1", 1)))
            plain.wait_for_disconnect()

        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

    def announcements(self, node):
        return node.getholepunchinfo()["announcements"]

    def test_handshake_deadline(self):
        node = self.nodes[0]
        coord_port = holepunch_coord_port(0)
        node.add_outbound_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR), p2p_idx=0)
        node.add_outbound_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR), p2p_idx=1)
        external = endpoint_from_str(self.external(node)["address"])
        # A base far past any session the earlier mocktime-driven tests left behind.
        mocktime = int(time.time()) + 1000
        node.setmocktime(mocktime)

        self.log.info("A punched connection that never completes the handshake is closed at the session deadline")
        # A target that accepts the TCP connection but never speaks the v2 transport.
        silent = socket.socket()
        silent.bind(("127.0.0.1", 0))
        silent.listen(1)
        silent_port = silent.getsockname()[1]
        requester = node.add_p2p_connection(CoordinationPeer(caps=0), dstport=coord_port)
        with node.assert_debug_log([f"session with 127.0.0.1:{silent_port} started as responder"], timeout=10):
            requester.send_without_ping(msg_rendezvous(external, endpoint("127.0.0.1", silent_port)))
            conn, _ = silent.accept()
        self.wait_until(lambda: len([p for p in node.getpeerinfo() if p["hole_punched"]]) == 1)
        with node.assert_debug_log(["punched connection did not complete the handshake in time"], timeout=10):
            node.setmocktime(mocktime + 20)
            self.wait_until(lambda: not [p for p in node.getpeerinfo() if p["hole_punched"]])
        conn.close()
        silent.close()
        node.setmocktime(0)
        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

    def test_announcement_cache(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR))
        coordinator = endpoint("1.2.3.4", 8333)

        self.log.info("A HOLEPUNCH element from addrv2 goes into the announcement cache, not into addrman")
        peer.send_and_ping(addrv2([announcement(coordinator, endpoint("5.6.7.8", 8335))]))
        assert_equal(len(self.announcements(node)), 1)
        assert_equal(self.announcements(node)[0]["target"], "5.6.7.8:8335")
        assert_equal(self.announcements(node)[0]["coordinator"], "1.2.3.4:8333")
        assert_equal(node.getnodeaddresses(0), [])

        self.log.info("Stale, future and port-0 elements are ignored")
        peer.send_and_ping(addrv2([
            announcement(coordinator, endpoint("5.6.7.9", 8335), timestamp=int(time.time()) - 700),
            announcement(coordinator, endpoint("5.6.7.10", 8335), timestamp=int(time.time()) + 700),
            announcement(coordinator, endpoint("5.6.7.11", 0)),
        ]))
        assert_equal(len(self.announcements(node)), 1)

        self.log.info("At most four announcements from one peer are kept")
        peer.send_and_ping(addrv2([announcement(coordinator, endpoint(f"5.6.8.{i}", 8335)) for i in range(5)]))
        assert_equal(len(self.announcements(node)), 4)

        self.log.info("An announcement can be added by hand for testing")
        node.holepunchaddannouncement("192.0.2.3:8333", "203.0.113.1:8335")
        assert_equal(len(self.announcements(node)), 5)
        assert_equal(self.announcements(node)[-1]["from"], -1)
        assert_equal(self.announcements(node)[-1]["coordinator"], "192.0.2.3:8333")

        node.disconnect_p2ps()

    def test_relay(self):
        node = self.nodes[0]
        self.log.info("A fresh announcement is relayed to addrv2 peers and never stored")
        receivers = [node.add_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR, support_addrv2=True)) for _ in range(2)]
        legacy = node.add_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR, support_addrv2=False))
        source = node.add_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR))
        element = announcement(endpoint("1.2.3.4", 8333), endpoint("5.6.7.8", 8335))
        source.send_and_ping(addrv2([element]))
        self.wait_until(lambda: any(len(r.announcements) > 0 for r in receivers))
        relayed = next(r.announcements[0] for r in receivers if r.announcements)
        assert_equal(relayed.ip, "5.6.7.8")
        assert_equal(relayed.port, 8335)
        assert_equal(relayed.coordinator, endpoint("1.2.3.4", 8333))
        for receiver in receivers:
            receiver.sync_with_ping()
        legacy.sync_with_ping()
        assert_equal(legacy.announcements, [])
        assert_equal(node.getnodeaddresses(0), [])

        self.log.info("An element with an onion coordinator is relayed to clearnet peers only")
        onion_peer = node.add_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR, support_addrv2=True), dstport=tor_port(0))
        source.send_and_ping(addrv2([announcement(onion_endpoint(ONION, 18444), endpoint("5.6.7.9", 8335))]))
        self.wait_until(lambda: any(a.coordinator.net == CAddress.NET_TORV3 for r in receivers for a in r.announcements))
        onion_peer.sync_with_ping()
        assert_equal([a for a in onion_peer.announcements if a.coordinator.net == CAddress.NET_TORV3], [])
        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

    def test_bad_external_port(self):
        node = self.nodes[0]
        self.log.info("An external address with a bad port is not announced: nobody would punch to it")
        node.add_outbound_p2p_connection(ReportingPeer(report=("127.0.0.1", 6667), support_addrv2=True), p2p_idx=0)
        with node.assert_debug_log(["not announcing 127.0.0.1:6667 to peer="], timeout=10):
            node.add_outbound_p2p_connection(ReportingPeer(report=("127.0.0.1", 6667), support_addrv2=True), p2p_idx=1)
        assert_equal(self.external(node)["address"], "127.0.0.1:6667")
        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

    def test_advertiser(self):
        node = self.nodes[0]
        punch_port = holepunch_port(0)
        self.log.info("With an external address, a coordinator and a free inbound slot, the node announces itself")
        coordinator = node.add_outbound_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR, support_addrv2=True), p2p_idx=0)
        # A second reporting peer without capabilities, so that only one coordinator exists.
        node.add_outbound_p2p_connection(HolePunchPeer(caps=0, support_addrv2=True), p2p_idx=1)
        assert_equal(self.external(node)["address"], f"127.0.0.1:{punch_port}")
        coordinator.wait_until(lambda: len(coordinator.announcements) > 1)
        self.log.info("One element names the coordinator, one the node's own onion service")
        assert_equal(len(coordinator.announcements), 2)
        for element in coordinator.announcements:
            assert_equal(element.ip, "127.0.0.1")
            assert_equal(element.port, punch_port)
            assert_equal(element.nServices & NODE_P2P_V2, NODE_P2P_V2)
        by_net = {e.coordinator.net: e.coordinator for e in coordinator.announcements}
        assert_equal(by_net[CAddress.NET_IPV4].port, p2p_port(MAX_NODES - 1))  # the listening port of a p2p_idx=0 peer
        assert_equal(by_net[CAddress.NET_TORV3].ip, ONION)
        assert_equal(by_net[CAddress.NET_TORV3].port, 18444)

        self.log.info("A peer connected through Tor never learns the onion service")
        onion_peer = node.add_p2p_connection(HolePunchPeer(caps=0, support_addrv2=True), dstport=tor_port(0))
        onion_peer.wait_until(lambda: len(onion_peer.announcements) > 0)
        onion_peer.sync_with_ping()
        assert_equal([e.coordinator.net for e in onion_peer.announcements], [CAddress.NET_IPV4])
        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

    def test_connector(self):
        node = self.nodes[0]
        punch_port = holepunch_port(0)
        coordinator = node.add_outbound_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR, support_addrv2=True), p2p_idx=0)
        node.add_outbound_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR, support_addrv2=True), p2p_idx=1)
        assert_equal(self.external(node)["address"], f"127.0.0.1:{punch_port}")
        coordinator_endpoint = endpoint("127.0.0.1", p2p_port(MAX_NODES - 1))

        self.log.info("The connector asks the coordinator named in a cached announcement for a rendezvous")
        # The target: a test peer listening where the node will punch to, as responder.
        target = P2PInterface()
        listening = threading.Event()
        target.peer_accept_connection(
            connect_cb=lambda address, port: listening.set(), connect_id=6, net=self.chain,
            timeout_factor=self.options.timeout_factor, supports_v2_p2p=True, reconnect=False)()
        assert listening.wait(timeout=10 * self.options.timeout_factor)
        target_endpoint = endpoint("127.0.0.1", p2p_port(MAX_NODES - 6))
        source = node.add_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR))
        source.send_and_ping(addrv2([announcement(coordinator_endpoint, target_endpoint)]))
        coordinator.wait_until(lambda: len(coordinator.rendezvous) > 0, timeout=30)
        request = coordinator.rendezvous[0]
        assert_equal(request.target, target_endpoint)
        assert_equal(request.requester, endpoint("127.0.0.1", punch_port))
        self.log.info("A used announcement leaves the cache; ones without a connected coordinator stay")
        assert target_endpoint.port not in [int(a["target"].rsplit(":", 1)[1]) for a in self.announcements(node)]
        assert all(a["coordinator"] != f"127.0.0.1:{coordinator_endpoint.port}" for a in self.announcements(node))

        self.log.info("Answers that fail validation leave the request outstanding")
        coordinator_id = next(p["id"] for p in node.getpeerinfo() if p["addr"] == f"127.0.0.1:{coordinator_endpoint.port}")
        for punch, reason in [
            (msg_punch(msg_punch.ROLE_RESPONDER, target_endpoint), "the answer to our rendezvous names us responder"),
            (msg_punch(msg_punch.ROLE_INITIATOR, endpoint("127.0.0.1", 40000)), "not the target"),
        ]:
            with node.assert_debug_log(["ignoring punch from peer=", reason], timeout=5):
                coordinator.send_and_ping(punch)
        assert_raises_rpc_error(-1, "a rendezvous is outstanding on this connection", node.holepunchrendezvous, coordinator_id, f"127.0.0.1:{target_endpoint.port}")

        self.log.info("The coordinator's punch makes the node connect to the target as initiator")
        with node.assert_debug_log(["answers our rendezvous"], timeout=5):
            coordinator.send_and_ping(msg_punch(msg_punch.ROLE_INITIATOR, target_endpoint))
        target.wait_for_connect()
        target.wait_for_verack()
        punched = [p for p in node.getpeerinfo() if p["hole_punched"]]
        assert_equal(len(punched), 1)
        assert_equal(punched[0]["inbound"], False)
        assert_equal(punched[0]["addr"], f"127.0.0.1:{p2p_port(MAX_NODES - 6)}")
        assert_equal(punched[0]["addrbind"], f"127.0.0.1:{punch_port}")
        assert_equal(punched[0]["transport_protocol_type"], "v2")

        target.peer_disconnect()
        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

    def test_coordination_connect(self):
        node = self.nodes[0]
        punch_port = holepunch_port(0)
        # Reporting peers only, none of them a coordinator.
        node.add_outbound_p2p_connection(HolePunchPeer(caps=0), p2p_idx=0)
        node.add_outbound_p2p_connection(HolePunchPeer(caps=0), p2p_idx=1)
        assert_equal(self.external(node)["address"], f"127.0.0.1:{punch_port}")
        mocktime = int(time.time())

        self.log.info("A rendezvous is only asked of a peer that coordinates")
        assert_raises_rpc_error(-1, "the peer does not coordinate", node.holepunchrendezvous, node.getpeerinfo()[0]["id"], "127.0.0.1:40000")

        def run(coordinator_addr, coordinator_idx, target_idx, expected_caps, kept):
            nonlocal mocktime
            coordinator = CoordinationPeer(caps=CAP_COORDINATOR)
            coordinator_port = self.listen(coordinator, coordinator_idx)
            self.proxy_destinations[ONION] = ("127.0.0.1", coordinator_port)
            target = P2PInterface()
            target_endpoint = endpoint("127.0.0.1", self.listen(target, target_idx))
            # Past HP_ATTEMPT_INTERVAL since the last attempt.
            mocktime += 310
            node.setmocktime(mocktime)
            coordinator_str = f"{coordinator_addr}:{coordinator_port}"
            with node.assert_debug_log([f"opening a coordination connection to {coordinator_str}", "asked peer="], timeout=30):
                node.holepunchaddannouncement(coordinator_str, f"127.0.0.1:{target_endpoint.port}")
                coordinator.wait_until(lambda: len(coordinator.rendezvous) > 0, timeout=30, check_connected=False)
            assert_equal(coordinator.rendezvous[0].target, target_endpoint)
            assert_equal(coordinator.rendezvous[0].requester, endpoint("127.0.0.1", punch_port))
            assert_equal(coordinator.holepunch_feature, feature_data(expected_caps))
            info = next(p for p in node.getpeerinfo() if p["connection_type"] == "holepunch-coordination")
            assert_equal(info["inbound"], False)
            assert_equal(info["addr"], coordinator_str)
            self.log.info("The coordinator's punch makes the node connect to the target")
            with node.assert_debug_log(["coordination finished"], timeout=5):
                coordinator.send_without_ping(msg_punch(msg_punch.ROLE_INITIATOR, target_endpoint))
                if not kept:
                    coordinator.wait_for_disconnect()
            target.wait_for_connect()
            target.wait_for_verack()
            punched = [p for p in node.getpeerinfo() if p["hole_punched"]]
            assert_equal(len(punched), 1)
            assert_equal(punched[0]["inbound"], False)
            assert_equal(punched[0]["addr"], f"127.0.0.1:{target_endpoint.port}")
            if kept:
                self.log.info("A coordination connection to a clearnet coordinator stays open through the punch window")
                coordinator.sync_with_ping()
                assert_equal(info["id"], next(p["id"] for p in node.getpeerinfo() if p["connection_type"] == "holepunch-coordination"))
                mocktime += 20
                with node.assert_debug_log(["punch window over"], timeout=5):
                    node.setmocktime(mocktime)
                    coordinator.wait_for_disconnect()
            target.peer_disconnect()
            self.wait_until(lambda: not [p for p in node.getpeerinfo() if p["hole_punched"]])
            return info

        self.log.info("Without a connection to a clearnet coordinator, the connector opens one from the punch port")
        info = run("127.0.0.1", coordinator_idx=10, target_idx=11, expected_caps=CAP_PUNCHPORT, kept=True)
        assert_equal(info["addrbind"], f"127.0.0.1:{punch_port}")

        self.log.info("An onion coordinator is reached through the Tor proxy")
        info = run(ONION, coordinator_idx=8, target_idx=4, expected_caps=0, kept=False)
        assert_equal(info["network"], "onion")

        node.setmocktime(0)
        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

    def test_options(self):
        node = self.nodes[0]
        self.log.info("-holepunch needs -v2transport")
        self.stop_node(0)
        node.assert_start_raises_init_error(
            ["-holepunch=1", "-v2transport=0"], "Error: -holepunch requires -v2transport")
        node.assert_start_raises_init_error(
            ["-holepunch=1", "-v2transport=1", "-holepunchport=70000"],
            "Error: Invalid port specified in -holepunchport: '70000'")
        node.assert_start_raises_init_error(
            ["-holepunch=1", "-v2transport=1", "-holepunchport=6667"],
            "Error: Port 6667 in -holepunchport is one other nodes refuse to connect to, choose another")
        self.log.info("-holepunchcoordonion sets the coordination service by hand")
        node.assert_start_raises_init_error(
            ["-holepunch=1", "-v2transport=1", "-holepunchcoordonion=1.2.3.4"],
            "Error: -holepunchcoordonion must be an onion address")
        with node.assert_debug_log([f"Hole punch coordination service is {ONION}:18444 (-holepunchcoordonion)"]):
            self.start_node(0, extra_args=self.extra_args[0])
        self.stop_node(0)
        self.log.info("Without -holepunchport, a random port from the dynamic range is used for the run")
        self.start_node(0, extra_args=["-holepunch=1", "-v2transport=1"])
        port = node.getholepunchinfo()["port"]
        assert 49152 <= port <= 65534, port
        assert_equal(node.getholepunchinfo()["coordination"]["bind"], f"127.0.0.1:{port + 1}")
        peer = node.add_outbound_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR), p2p_idx=0)
        assert_equal(peer.dstport, port)
        node.disconnect_p2ps()
        self.stop_node(0)
        self.log.info("Without -holepunch, outbound connections use an ephemeral port and no feature is sent")
        self.start_node(0, extra_args=["-v2transport=1"])
        peer = node.add_outbound_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR), p2p_idx=0)
        assert peer.dstport != holepunch_port(0)
        assert_equal(peer.holepunch_feature, None)
        self.log.info("A peer's feature is still recorded")
        assert_equal(node.getpeerinfo()[-1]["holepunch_caps"], ["COORDINATOR"])

    def run_test(self):
        self.test_outbound_from_punch_port()
        self.test_external_address()
        self.test_coordination_connection()
        self.test_coordination_bind()
        self.test_feature_negotiation()
        self.test_punch_as_responder()
        self.test_own_coordinator()
        self.test_coordinator()
        # The connector tests run while the announcement cache is empty: entries
        # left by the cache tests would be attempted as soon as the node has an
        # external address, and would use up the attempt interval.
        self.test_bad_external_port()
        self.test_advertiser()
        self.test_connector()
        self.test_coordination_connect()
        self.test_handshake_deadline()
        self.test_announcement_cache()
        self.test_relay()
        self.test_options()
        self.socks5_server.stop()


if __name__ == '__main__':
    HolePunchTest(__file__).main()
