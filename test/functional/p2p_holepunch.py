#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test TCP hole punching (-holepunch)."""

import threading

from test_framework.messages import (
    CAddress,
    NODE_NETWORK,
    NODE_P2P_V2,
    msg_addrv2,
    msg_feature,
    msg_punch,
    msg_rendezvous,
)
from test_framework.p2p import (
    EncryptedP2PState,
    P2PInterface,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    MAX_NODES,
    assert_equal,
    holepunch_port,
    p2p_port,
)

import time


HOLEPUNCH_FEATURE_ID = "https://delvingbitcoin.org/t/2497"
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

    def __init__(self, report=None):
        super().__init__()
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


class PunchInitiatorPeer(HolePunchPeer):
    """A test peer at the other end of a punched connection, in the initiator
    role: it accepts the node's TCP connection but speaks first, as the BIP 324
    initiator, and sends version first."""

    def peer_accept_connection(self, *args, net, **kwargs):
        create = super().peer_accept_connection(*args, net=net, **kwargs)
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
            "-whitelist=addr@127.0.0.1",  # no address rate limit for inbound test peers
        ]]

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

        self.log.info("A peer without the feature has no holepunch_caps")
        node.add_p2p_connection(P2PInterface())
        assert "holepunch_caps" not in node.getpeerinfo()[-1]

        self.log.info("Truncated feature data disconnects the peer")
        with node.assert_debug_log(["invalid hole punching feature data"], timeout=5):
            peer = node.add_p2p_connection(HolePunchPeer(raw_feature_data=b"\x00\x01"), wait_for_verack=False)
            peer.wait_for_disconnect()

        node.disconnect_p2ps()

    def listen_for_punch(self, idx):
        """Start a PunchInitiatorPeer listening where the node will punch to. Returns it and its port."""
        peer = PunchInitiatorPeer()
        listening = threading.Event()
        peer.peer_accept_connection(
            connect_cb=lambda address, port: listening.set(), connect_id=idx, net=self.chain,
            timeout_factor=self.options.timeout_factor, supports_v2_p2p=True, reconnect=False)()
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

        node.disconnect_p2ps()

    def test_advertiser(self):
        node = self.nodes[0]
        punch_port = holepunch_port(0)
        self.log.info("With an external address, a coordinator and a free inbound slot, the node announces itself")
        coordinator = node.add_outbound_p2p_connection(HolePunchPeer(caps=CAP_COORDINATOR, support_addrv2=True), p2p_idx=0)
        # A second reporting peer without capabilities, so that only one coordinator exists.
        node.add_outbound_p2p_connection(HolePunchPeer(caps=0, support_addrv2=True), p2p_idx=1)
        assert_equal(self.external(node)["address"], f"127.0.0.1:{punch_port}")
        coordinator.wait_until(lambda: len(coordinator.announcements) > 0)
        element = coordinator.announcements[0]
        assert_equal(element.ip, "127.0.0.1")
        assert_equal(element.port, punch_port)
        assert_equal(element.coordinator.port, p2p_port(MAX_NODES - 1))  # the listening port of a p2p_idx=0 peer
        assert_equal(element.nServices & NODE_P2P_V2, NODE_P2P_V2)
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
        assert all(a["coordinator"] == "1.2.3.4:8333" for a in self.announcements(node))

        self.log.info("The coordinator's punch makes the node connect to the target as initiator")
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

    def test_options(self):
        node = self.nodes[0]
        self.log.info("-holepunch needs -v2transport")
        self.stop_node(0)
        node.assert_start_raises_init_error(
            ["-holepunch=1", "-v2transport=0"], "Error: -holepunch requires -v2transport")
        node.assert_start_raises_init_error(
            ["-holepunch=1", "-v2transport=1", "-holepunchport=70000"],
            "Error: Invalid port specified in -holepunchport: '70000'")
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
        self.test_feature_negotiation()
        self.test_punch_as_responder()
        self.test_coordinator()
        self.test_announcement_cache()
        self.test_advertiser()
        self.test_connector()
        self.test_options()


if __name__ == '__main__':
    HolePunchTest(__file__).main()
