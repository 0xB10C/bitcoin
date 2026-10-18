#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test TCP hole punching through boards: options, board connections, the feature exchange,
the external address, announcing to boards, acting as a board, and punched connections."""

import hashlib
import socket
import time

from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.crypto.secp256k1 import GE
from test_framework.key import ECKey
from test_framework.messages import (
    CAddress,
    NODE_HOLEPUNCH_BOARD,
    NODE_NETWORK,
    NODE_P2P_V2,
    NODE_WITNESS,
    msg_addrv2,
    msg_feature,
    msg_getaddr,
    msg_inv,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    MAX_NODES,
    assert_equal,
    assert_raises_rpc_error,
    holepunch_port,
    p2p_port,
)

BOARD_SERVICES = NODE_HOLEPUNCH_BOARD | NODE_P2P_V2
ENTRY_SERVICES = NODE_NETWORK | NODE_WITNESS | NODE_P2P_V2


def new_pubkey():
    key = ECKey()
    key.generate()
    return key.get_pubkey().get_bytes()


def punchkey_element(ip, port, pubkey, services=ENTRY_SERVICES, net=CAddress.NET_IPV4):
    """A PUNCHKEY element announcing `ip:port` under `pubkey`."""
    addr = CAddress()
    addr.net = CAddress.NET_PUNCHKEY
    addr.ip = bytes([net]) + socket.inet_aton(ip) + pubkey
    addr.port = port
    addr.nServices = services
    addr.time = int(time.time())
    return addr


def free_port():
    """A loopback port nothing listens on."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class PickModel:
    """What a node picks in its rounds, computed from the entries' keys as the draft
    specifies: pair values rank the candidates, the pair value's last bit and the key
    order give the role, at most three picks per round and two per source, one
    initiator slot, and entries take part only once the tip reached the parent after
    they arrived."""

    def __init__(self, node_pubkey, own_endpoint):
        self.node_pubkey = node_pubkey
        self.own = own_endpoint
        self.entries = []  # (ip, port, key, source, height when served)
        self.active = 0
        self.initiator_free = True

    def serve(self, entries, source, height):
        self.entries.extend((ip, port, key, source, height) for ip, port, key in entries)

    @staticmethod
    def _endpoint(ip, port):
        return b"\x01\x04" + socket.inet_aton(ip) + port.to_bytes(2, "big")

    def pair(self, ip, port, key, block_hash):
        secret = int.from_bytes(key.get_bytes(), "big")
        x = (secret * GE.from_bytes(self.node_pubkey)).x.to_bytes()
        endpoints = sorted([self._endpoint(*self.own), self._endpoint(ip, port)])
        tag = hashlib.sha256(b"tcp-holepunch/pair").digest()
        return hashlib.sha256(tag + tag + x + bytes.fromhex(block_hash)[::-1] + endpoints[0] + endpoints[1]).digest()

    def round(self, height, block_hash):
        """The (endpoint, role) picks of the round for the block at `height`."""
        candidates = []
        for ip, port, key, source, served in self.entries:
            if served > height - 2:
                continue  # the tip reached the parent before the entry arrived (R-7.2)
            pair = self.pair(ip, port, key, block_hash)
            smaller_key_initiates = (pair[31] & 1) == 0
            node_is_smaller = self.node_pubkey < key.get_pubkey().get_bytes()
            role = "initiator" if node_is_smaller == smaller_key_initiates else "responder"
            candidates.append((pair, f"{ip}:{port}", role, source, (ip, port, key, source, served)))
        candidates.sort()
        picks = []
        per_source = {}
        for pair, endpoint, role, source, entry in candidates:
            if len(picks) >= 3 or self.active >= 6:
                break
            if per_source.get(source, 0) >= 2:
                continue
            if role == "initiator":
                if not self.initiator_free:
                    continue
                self.initiator_free = False
            picks.append((endpoint, role))
            per_source[source] = per_source.get(source, 0) + 1
            self.entries.remove(entry)
            self.active += 1
        return sorted(picks)


def decode_element(addr):
    """(ip, port, pubkey) of a PUNCHKEY element with an IPv4 address."""
    assert_equal(addr.net, CAddress.NET_PUNCHKEY)
    assert_equal(addr.ip[0], CAddress.NET_IPV4)
    return socket.inet_ntoa(addr.ip[1:5]), addr.port, addr.ip[5:]

HOLEPUNCH_FEATURE_ID = "https://delvingbitcoin.org/t/2497/22"
FLAG_BOARD = 1 << 0
FLAG_VISITOR = 1 << 1


def feature_data(flags, version=0):
    return version.to_bytes(1, "little") + flags.to_bytes(4, "little")


class HolePunchPeer(P2PInterface):
    """A test peer that sends the hole punching feature with `flags` before verack, or nothing if None.
    `data` replaces the feature payload, to send a malformed one. `report` is the (ip, port) it
    reports as the node's address in version.addr_recv."""

    def __init__(self, flags=None, data=None, report=None, echo=False):
        super().__init__()
        self.flags = flags
        self.data = data
        self.report = report
        # Answer every addrv2 with its elements, as a board acknowledges with its live entries.
        self.echo = echo
        self.features = []
        self.elements = []
        self.addrv2_messages = []

    def on_addrv2(self, message):
        self.elements.extend(message.addrs)
        self.addrv2_messages.append(message)
        if self.echo:
            self.send_without_ping(message)

    def local_port(self):
        """The port the node sees this connection come from."""
        return self._transport.get_extra_info("sockname")[1]

    def announce(self, ip, port, pubkey):
        """Send one element and return the elements of the answer."""
        msg = msg_addrv2()
        msg.addrs = [punchkey_element(ip, port, pubkey)]
        before = len(self.addrv2_messages)
        self.send_and_ping(msg)
        assert_equal(len(self.addrv2_messages), before + 1)
        return [decode_element(a) for a in self.addrv2_messages[-1].addrs]

    def announced(self):
        """(ip, port, pubkey) of the last element the node announced."""
        return decode_element(self.elements[-1])

    def peer_connect_send_version(self, services):
        super().peer_connect_send_version(services)
        if self.report is not None:
            self.on_connection_send_msg.addrTo.ip, self.on_connection_send_msg.addrTo.port = self.report
        # A visitor's version has transaction relay disabled (R-3.5). The other test
        # peers do the same, so that the cap on tx-relaying inbound peers stays out
        # of the way when inbound slots are counted.
        self.on_connection_send_msg.relay = 0

    def on_feature(self, message):
        self.features.append(message)

    def on_version(self, message):
        # Our version has to go out before the feature. P2PInterface sends it in
        # on_version for accepted connections; doing it here first makes its own
        # call a no-op.
        if not self.p2p_connected_to_node:
            self.send_version()
        if self.data is not None:
            self.send_without_ping(msg_feature(HOLEPUNCH_FEATURE_ID, self.data))
        elif self.flags is not None:
            self.send_without_ping(msg_feature(HOLEPUNCH_FEATURE_ID, feature_data(self.flags)))
        # P2PInterface sends a getaddr after verack on connections it made, which
        # a board connection does not allow.
        connected_to_node = self.p2p_connected_to_node
        if self.flags is not None and self.flags & FLAG_VISITOR:
            self.p2p_connected_to_node = False
        super().on_version(message)
        self.p2p_connected_to_node = connected_to_node

    def holepunch_flags(self):
        """The flags the node sent in its hole punching feature, None if it sent none."""
        for m in self.features:
            if m.feature_id == HOLEPUNCH_FEATURE_ID:
                return int.from_bytes(m.feature_data[1:5], "little")
        return None


class HolePunchTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.extra_args = [
            # A visitor: it opens board connections from its punch port.
            ["-v2transport=1", "-holepunch=1", f"-holepunchport={holepunch_port(0)}"],
            # A board.
            ["-v2transport=1", "-holepunchboard=1"],
            # A second visitor, for the back-off test.
            ["-v2transport=1", "-holepunch=1", f"-holepunchport={holepunch_port(2)}"],
        ]
        # Board connections are opened by the automatic connection logic.
        self.disable_autoconnect = False

    def setup_network(self):
        self.setup_nodes()

    def test_options(self):
        self.log.info("Bad options are refused at startup")
        node = self.nodes[0]
        self.stop_node(0)
        node.assert_start_raises_init_error(
            ["-holepunch=1", "-v2transport=0"],
            "Error: -holepunch requires -v2transport")
        node.assert_start_raises_init_error(
            ["-v2transport=1", "-holepunch=1", "-holepunchport=70000"],
            "Error: Invalid port specified in -holepunchport: '70000'")
        node.assert_start_raises_init_error(
            ["-v2transport=1", "-holepunch=1", "-holepunchport=22"],
            "Error: Port 22 in -holepunchport is one other nodes refuse to connect to, choose another")
        node.assert_start_raises_init_error(
            ["-holepunchboard=1", "-v2transport=0"],
            "Error: -holepunchboard requires -v2transport")
        node.assert_start_raises_init_error(
            ["-v2transport=1", "-holepunchboard=1", "-listen=0"],
            "Error: -holepunchboard requires -listen")
        self.start_node(0)

        self.log.info("A board advertises the service bit, a visitor does not")
        assert "HOLEPUNCH_BOARD" not in self.nodes[0].getnetworkinfo()["localservicesnames"]
        assert "HOLEPUNCH_BOARD" in self.nodes[1].getnetworkinfo()["localservicesnames"]

    def test_board_connection_port(self):
        node = self.nodes[0]
        punch_port = holepunch_port(0)

        # For a connection accepted by a test peer, dstport is the node's source port as
        # the peer sees it: the port that version.addr_recv will report back.
        self.log.info("Board connections are made from the punch port")
        board = node.add_outbound_p2p_connection(HolePunchPeer(flags=FLAG_BOARD), p2p_idx=0, connection_type="holepunch-board")
        assert_equal(board.dstport, punch_port)
        peers = node.getpeerinfo()
        assert_equal(len(peers), 1)
        assert_equal(peers[0]["connection_type"], "holepunch-board")
        assert_equal(peers[0]["addrbind"], f"127.0.0.1:{punch_port}")

        self.log.info("Ordinary outbound connections are not")
        full = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=1)
        assert full.dstport != punch_port

        self.log.info("Several board connections share the punch port")
        board2 = node.add_outbound_p2p_connection(HolePunchPeer(flags=FLAG_BOARD), p2p_idx=2, connection_type="holepunch-board")
        assert_equal(board2.dstport, punch_port)
        assert_equal(len([p for p in node.getpeerinfo() if p["connection_type"] == "holepunch-board"]), 2)

        node.disconnect_p2ps()

    def test_feature_exchange(self):
        visitor, board = self.nodes[0], self.nodes[1]

        self.log.info("A visitor sends VISITOR on a board connection and keeps it when the board answers BOARD")
        peer = visitor.add_outbound_p2p_connection(HolePunchPeer(flags=FLAG_BOARD), p2p_idx=0, connection_type="holepunch-board")
        assert_equal(peer.holepunch_flags(), FLAG_VISITOR)
        assert_equal(visitor.getpeerinfo()[0]["holepunch_flags"], ["BOARD"])
        visitor.disconnect_p2ps()

        self.log.info("A visitor closes a board connection whose peer does not answer BOARD")
        for flags in [None, 0, FLAG_VISITOR]:
            peer = visitor.add_outbound_p2p_connection(HolePunchPeer(flags=flags), p2p_idx=0, connection_type="holepunch-board", wait_for_disconnect=True)
            assert_equal(peer.holepunch_flags(), FLAG_VISITOR)

        self.log.info("A visitor sends no feature on an ordinary outbound connection")
        peer = visitor.add_outbound_p2p_connection(HolePunchPeer(flags=FLAG_BOARD), p2p_idx=0)
        assert_equal(peer.holepunch_flags(), None)
        assert_equal(visitor.getpeerinfo()[0]["holepunch_flags"], ["BOARD"])
        visitor.disconnect_p2ps()

        self.log.info("A board answers BOARD to a visitor, and sends it on every other connection too")
        peer = board.add_p2p_connection(HolePunchPeer(flags=FLAG_VISITOR))
        assert_equal(peer.holepunch_flags(), FLAG_BOARD)
        assert_equal(board.getpeerinfo()[0]["holepunch_flags"], ["VISITOR"])
        peer2 = board.add_p2p_connection(HolePunchPeer(flags=None))
        assert_equal(peer2.holepunch_flags(), FLAG_BOARD)
        assert_equal(board.getpeerinfo()[1]["holepunch_flags"], [])
        board.disconnect_p2ps()

        self.log.info("Malformed feature data disconnects")
        peer = board.add_p2p_connection(HolePunchPeer(data=b"\x00\x01"), wait_for_verack=False)
        peer.wait_for_disconnect()

    def test_board_connection_protocol(self):
        visitor, board = self.nodes[0], self.nodes[1]
        quiet = ["getaddr", "sendheaders", "getheaders", "sendcmpct", "inv", "feefilter"]

        self.log.info("A visitor disables transaction relay and sends nothing but pings after verack")
        peer = visitor.add_outbound_p2p_connection(HolePunchPeer(flags=FLAG_BOARD), p2p_idx=0, connection_type="holepunch-board")
        assert_equal(peer.relay, 0)
        for msg in quiet:
            assert_equal(peer.message_count[msg], 0)

        self.log.info("A visitor closes a board connection on any other message")
        peer.send_without_ping(msg_inv([]))
        peer.wait_for_disconnect()
        peer = visitor.add_outbound_p2p_connection(HolePunchPeer(flags=FLAG_BOARD), p2p_idx=0, connection_type="holepunch-board")
        peer.send_without_ping(msg_getaddr())
        peer.wait_for_disconnect()
        visitor.disconnect_p2ps()

        self.log.info("A board sends nothing but pings to a visitor and closes on any other message")
        peer = board.add_p2p_connection(HolePunchPeer(flags=FLAG_VISITOR))
        for msg in quiet:
            assert_equal(peer.message_count[msg], 0)
        peer.send_without_ping(msg_getaddr())
        peer.wait_for_disconnect()
        board.disconnect_p2ps()

        self.log.info("A board refuses a visitor beyond its pool size")
        for _ in range(32):
            board.add_p2p_connection(HolePunchPeer(flags=FLAG_VISITOR))
        extra = board.add_p2p_connection(HolePunchPeer(flags=FLAG_VISITOR), wait_for_verack=False)
        extra.wait_for_disconnect()
        assert_equal(len([p for p in board.getpeerinfo() if p["holepunch_flags"] == ["VISITOR"]]), 32)
        board.disconnect_p2ps()

    def test_external_address(self):
        visitor = self.nodes[0]

        def external():
            return visitor.getholepunchinfo()["families"][0]

        def board(idx, report):
            return visitor.add_outbound_p2p_connection(HolePunchPeer(flags=FLAG_BOARD, report=report), p2p_idx=idx, connection_type="holepunch-board")

        self.log.info("Nothing is known without reports")
        info = visitor.getholepunchinfo()
        assert_equal(info["enabled"], True)
        assert_equal(info["board"], False)
        assert_equal(info["port"], holepunch_port(0))
        assert_equal(external()["reports"], 0)
        assert_equal(external()["conflicting"], False)
        assert "address" not in external()

        self.log.info("One board's report is not enough, two agreeing boards give the external address")
        board(0, ("1.2.3.4", 5555))
        assert_equal(external()["reports"], 1)
        assert "address" not in external()
        board(1, ("1.2.3.4", 5555))
        assert_equal(external()["address"], "1.2.3.4:5555")
        assert_equal(external()["reporters"], 2)

        self.log.info("A single dissenting board changes nothing")
        board(2, ("1.2.3.4", 6666))
        assert_equal(external()["address"], "1.2.3.4:5555")
        assert_equal(external()["conflicting"], False)

        self.log.info("A second board agreeing with the dissenter is replaced, and the address stays")
        dissenter2 = visitor.add_outbound_p2p_connection(HolePunchPeer(flags=FLAG_BOARD, report=("1.2.3.4", 6666)), p2p_idx=3, connection_type="holepunch-board", wait_for_disconnect=True)
        self.wait_until(lambda: external()["reports"] == 3)
        assert_equal(external()["address"], "1.2.3.4:5555")
        assert_equal(external()["conflicting"], False)

        self.log.info("Ordinary outbound connections do not report")
        visitor.add_outbound_p2p_connection(HolePunchPeer(flags=FLAG_BOARD, report=("9.9.9.9", 1)), p2p_idx=4)
        assert_equal(external()["reports"], 3)
        visitor.disconnect_p2ps()
        self.wait_until(lambda: external()["reports"] == 0)

    def listen_as_board(self, idx, flags=FLAG_BOARD):
        """Listen like a board on the test framework's port for `idx`. Returns the mock
        and the port; `-holepunchboardseed` points a visitor at it."""
        peer = HolePunchPeer(flags=flags)
        peer.peer_accept_connection(connect_cb=lambda address, port: None, connect_id=idx + 1, net=self.chain, timeout_factor=self.options.timeout_factor, supports_v2_p2p=True, reconnect=False, services=BOARD_SERVICES)()
        return peer, p2p_port(MAX_NODES - (idx + 1))

    def test_board_connections(self):
        visitor = self.nodes[0]

        def boards():
            return visitor.getholepunchinfo()["families"][0]["boards"]

        def connected(mocks):
            return [m for m in mocks if m.is_connected]

        self.log.info("A visitor keeps two board connections per family, from the punch port")
        listeners = [self.listen_as_board(idx) for idx in range(3)]
        seeds = [f"-holepunchboardseed=127.0.0.1:{port}" for _, port in listeners]
        self.restart_node(0, extra_args=self.extra_args[0] + seeds)
        mocks = [mock for mock, _ in listeners]
        self.wait_until(lambda: len(connected(mocks)) == 2)
        for mock in connected(mocks):
            mock.wait_for_verack()
        self.wait_until(lambda: len(boards()) == 2)
        for mock in connected(mocks):
            assert_equal(mock.dstport, holepunch_port(0))
        for peer in visitor.getpeerinfo():
            assert_equal(peer["connection_type"], "holepunch-board")
            assert_equal(peer["transport_protocol_type"], "v2")
        for board in boards():
            assert 5 * 3600 <= board["until"] - board["connected"] <= 7 * 3600
        # The third board is left alone while two connections are open.
        connected(mocks)[0].sync_with_ping()
        assert_equal(len(connected(mocks)), 2)
        assert_equal(len(boards()), 2)

        self.log.info("A closed board connection is replaced by one to another board")
        closing = connected(mocks)[0]
        closing_idx = mocks.index(closing)
        # Listen again on the closing board's port first, so that either it or the
        # third board can be picked as the replacement.
        mocks[closing_idx], _ = self.listen_as_board(closing_idx)
        closing.peer_disconnect()
        closing.wait_for_disconnect()
        self.wait_until(lambda: len(connected(mocks)) == 2)
        for mock in connected(mocks):
            mock.wait_for_verack()
        self.wait_until(lambda: len(boards()) == 2)
        assert_equal(visitor.getholepunchinfo()["families"][0]["board_fails"], 0)
        # Forget the seeds before dropping the mocks, so that nothing reconnects to them.
        self.restart_node(0)
        for mock in mocks:
            mock.peer_disconnect()

        self.log.info("After four board connections in a row without a result, a family pauses for an hour")
        visitor2 = self.nodes[2]
        family = lambda: visitor2.getholepunchinfo()["families"][0]
        # A board address nothing listens on: every attempt is refused.
        self.restart_node(2, extra_args=self.extra_args[2] + [f"-holepunchboardseed=127.0.0.1:{p2p_port(MAX_NODES)}"])
        self.wait_until(lambda: family()["board_backoff_until"] > 0)
        assert_equal(family()["board_fails"], 0)
        paused_until = family()["board_backoff_until"]
        # Once the pause is over, attempts resume.
        visitor2.setmocktime(paused_until + 1)
        self.wait_until(lambda: family()["board_fails"] > 0)
        visitor2.setmocktime(0)

    def test_announcements(self):
        visitor = self.nodes[0]
        self.restart_node(0)

        def family():
            return visitor.getholepunchinfo()["families"][0]

        def table():
            return visitor.getholepunchinfo()["table"]

        def board(idx, echo=True, report=("1.2.3.4", 5555)):
            return visitor.add_outbound_p2p_connection(HolePunchPeer(flags=FLAG_BOARD, report=report, echo=echo), p2p_idx=idx, connection_type="holepunch-board")

        self.log.info("Once the external address is known, a visitor announces it with its key on every board connection")
        board_a = board(0)
        board_a.sync_with_ping()
        assert_equal(board_a.elements, [])
        assert "key" not in family()
        board_b = board(1)
        for mock in (board_a, board_b):
            mock.wait_until(lambda: len(mock.elements) == 1)
        ip, port, pubkey = board_a.announced()
        assert_equal((ip, port), ("1.2.3.4", 5555))
        assert_equal(len(pubkey), 33)
        assert pubkey[0] in (2, 3)
        assert_equal(board_b.announced(), (ip, port, pubkey))
        assert_equal(board_a.elements[0].nServices & NODE_P2P_V2, NODE_P2P_V2)
        assert_equal(family()["key"], pubkey.hex())
        assert_equal(family()["announced"], "1.2.3.4:5555")
        now = int(time.time())
        assert 12 * 3600 - 60 <= family()["key_rotates_at"] - now <= 24 * 3600

        self.log.info("Entries a board serves go to the table; our own entry is the acknowledgement and is not stored")
        others = [("8.8.8.%d" % i, 9000 + i, new_pubkey()) for i in range(1, 4)]
        board_a.send_and_ping(msg_addrv2())  # an empty answer
        elements = [punchkey_element(ip, port, key) for ip, port, key in others]
        elements.append(punchkey_element("1.2.3.4", 5555, pubkey))  # our own, served back
        elements.append(punchkey_element("1.2.3.4", 5555, new_pubkey()))  # our address under another key
        elements.append(punchkey_element("5.5.5.5", 5, pubkey))  # our key under another address
        elements.append(punchkey_element("8.8.8.9", 9009, new_pubkey(), services=NODE_NETWORK))  # no NODE_P2P_V2
        elements.append(punchkey_element("10.0.0.1", 9010, new_pubkey()))  # routable on regtest
        msg = msg_addrv2()
        msg.addrs = elements
        board_a.send_and_ping(msg)
        assert_equal(table()["entries"], 4)
        assert_equal(len(table()["sources"]), 1)

        self.log.info("A visitor never forwards an element")
        board_b.sync_with_ping()
        assert_equal(len(board_b.elements), 1)

        self.log.info("An element that is not PUNCHKEY on a board connection disconnects")
        msg = msg_addrv2()
        ordinary = CAddress()
        ordinary.ip, ordinary.port, ordinary.nServices = "8.8.8.8", 8333, NODE_NETWORK
        msg.addrs = [ordinary]
        board_a.send_without_ping(msg)
        board_a.wait_for_disconnect()

        self.log.info("A PUNCHKEY element on an ordinary connection disconnects")
        peer = visitor.add_p2p_connection(HolePunchPeer(flags=None))
        msg = msg_addrv2()
        msg.addrs = [punchkey_element("8.8.8.1", 9001, new_pubkey())]
        peer.send_without_ping(msg)
        peer.wait_for_disconnect()

        self.log.info("A board that does not acknowledge the element within BOARD_ACK is replaced")
        board_c = board(2, echo=False)
        board_c.wait_until(lambda: len(board_c.elements) == 1)
        fails = family()["board_fails"]
        visitor.setmocktime(int(time.time()) + 61)
        board_c.wait_for_disconnect()
        assert_equal(family()["board_fails"], fails + 1)
        board_b.sync_with_ping()  # acknowledged, stays
        visitor.setmocktime(0)

        self.log.info("A new external address is announced under a new key, with the other family's key untouched")
        visitor.disconnect_p2ps()
        self.wait_until(lambda: family()["reports"] == 0)
        board_d = board(3, report=("1.2.3.5", 5555))
        board_e = board(4, report=("1.2.3.5", 5555))
        for mock in (board_d, board_e):
            mock.wait_until(lambda: len(mock.elements) == 1)
        ip, port, pubkey2 = board_d.announced()
        assert_equal((ip, port), ("1.2.3.5", 5555))
        assert pubkey2 != pubkey
        assert_equal(family()["key"], pubkey2.hex())
        assert "key" not in visitor.getholepunchinfo()["families"][1]

        self.log.info("A key is replaced at the latest after KEY_ROTATE, and announced again")
        visitor.setmocktime(family()["key_rotates_at"] + 1)
        for mock in (board_d, board_e):
            mock.wait_until(lambda: len(mock.elements) == 2)
        ip, port, pubkey3 = board_d.announced()
        assert_equal((ip, port), ("1.2.3.5", 5555))
        assert pubkey3 != pubkey2
        assert_equal(board_e.announced(), (ip, port, pubkey3))
        visitor.setmocktime(0)
        visitor.disconnect_p2ps()

    def test_board_serving(self):
        board = self.nodes[1]
        self.restart_node(1)

        def entries():
            return board.getholepunchinfo()["board_entries"]

        self.log.info("A board stores a visitor's element if it names the connection's endpoint, and answers with it")
        visitor1 = board.add_p2p_connection(HolePunchPeer(flags=FLAG_VISITOR))
        key1 = new_pubkey()
        before = int(time.time())
        assert_equal(visitor1.announce("127.0.0.1", visitor1.local_port(), key1), [("127.0.0.1", visitor1.local_port(), key1)])
        answer = visitor1.addrv2_messages[-1].addrs[0]
        assert before <= answer.time <= int(time.time())
        assert_equal(answer.nServices, ENTRY_SERVICES)
        assert_equal(entries(), {"live": 1, "total": 1})

        self.log.info("An element for another endpoint is ignored, and the answer shows it")
        other_key = new_pubkey()
        assert_equal(visitor1.announce("127.0.0.1", visitor1.local_port() + 1, other_key), [("127.0.0.1", visitor1.local_port(), key1)])
        assert_equal(visitor1.announce("1.2.3.4", visitor1.local_port(), other_key), [("127.0.0.1", visitor1.local_port(), key1)])
        assert_equal(entries(), {"live": 1, "total": 1})

        self.log.info("A stored element is pushed to the other visitors, and every visitor gets all live entries")
        visitor2 = board.add_p2p_connection(HolePunchPeer(flags=FLAG_VISITOR))
        key2 = new_pubkey()
        answer = visitor2.announce("127.0.0.1", visitor2.local_port(), key2)
        assert_equal(sorted(answer), sorted([("127.0.0.1", visitor1.local_port(), key1), ("127.0.0.1", visitor2.local_port(), key2)]))
        visitor1.wait_until(lambda: len(visitor1.addrv2_messages) == 4)
        assert_equal([decode_element(a) for a in visitor1.addrv2_messages[-1].addrs], [("127.0.0.1", visitor2.local_port(), key2)])
        assert_equal(entries(), {"live": 2, "total": 2})

        self.log.info("A later element on the same connection replaces the entry")
        key1b = new_pubkey()
        visitor1.announce("127.0.0.1", visitor1.local_port(), key1b)
        visitor2.wait_until(lambda: len(visitor2.addrv2_messages) == 2)
        assert_equal([decode_element(a) for a in visitor2.addrv2_messages[-1].addrs], [("127.0.0.1", visitor1.local_port(), key1b)])
        assert_equal(entries(), {"live": 2, "total": 2})

        self.log.info("After a visitor leaves, its entry is kept for the grace period but no longer served")
        port1 = visitor1.local_port()
        visitor1.peer_disconnect()
        visitor1.wait_for_disconnect()
        self.wait_until(lambda: entries() == {"live": 1, "total": 2})
        assert_equal(visitor2.announce("127.0.0.1", visitor2.local_port(), key2), [("127.0.0.1", visitor2.local_port(), key2)])
        assert port1 not in [p for _, p, _ in visitor2.announce("127.0.0.1", visitor2.local_port(), key2)]

        self.log.info("Entries never reach ordinary peers")
        peer = board.add_p2p_connection(HolePunchPeer(flags=None))
        peer.send_and_ping(msg_getaddr())
        assert all(a.net != CAddress.NET_PUNCHKEY for m in peer.addrv2_messages for a in m.addrs)
        board.disconnect_p2ps()

    def test_punched_connection(self):
        initiator, responder = self.nodes[0], self.nodes[2]
        self.restart_node(0)
        self.restart_node(2)
        initiator_endpoint = f"127.0.0.1:{holepunch_port(0)}"
        responder_endpoint = f"127.0.0.1:{holepunch_port(2)}"

        self.log.info("Two nodes punching to each other at the same time get one connection")
        initiator.holepunchsession("initiator", responder_endpoint)
        responder.holepunchsession("responder", initiator_endpoint)
        self.wait_until(lambda: len(initiator.getpeerinfo()) == 1 and initiator.getpeerinfo()[0]["version"] != 0)
        self.wait_until(lambda: len(responder.getpeerinfo()) == 1 and responder.getpeerinfo()[0]["version"] != 0)
        outbound = initiator.getpeerinfo()[0]
        inbound = responder.getpeerinfo()[0]
        for peer in (outbound, inbound):
            assert_equal(peer["hole_punched"], True)
            assert_equal(peer["transport_protocol_type"], "v2")
        # The initiator holds an outbound from its punch port to the responder's punch port.
        assert_equal(outbound["inbound"], False)
        assert_equal(outbound["connection_type"], "outbound-full-relay")
        assert_equal(outbound["addrbind"], initiator_endpoint)
        assert_equal(outbound["addr"], responder_endpoint)
        # The responder holds the same connection as an inbound.
        assert_equal(inbound["inbound"], True)
        assert_equal(inbound["connection_type"], "inbound")
        assert_equal(inbound["addrbind"], responder_endpoint)
        assert_equal(inbound["addr"], initiator_endpoint)
        assert_equal(initiator.getholepunchinfo()["sessions"], [])
        assert_equal(initiator.getholepunchinfo()["session_stats"]["initiator"], {"started": 1, "established": 1, "failed": 0})
        assert_equal(responder.getholepunchinfo()["session_stats"]["responder"], {"started": 1, "established": 1, "failed": 0})

        self.log.info("A punched peer reports our address, like a board does")
        self.wait_until(lambda: initiator.getholepunchinfo()["families"][0]["reports"] == 1)
        self.wait_until(lambda: responder.getholepunchinfo()["families"][0]["reports"] == 1)

        self.log.info("The hole-punch outbound takes its own slot, not one of the automatic ones")
        assert_equal(initiator.getnetworkinfo()["connections_out"], 1)
        # A second session as initiator is refused while the slot is taken.
        assert_raises_rpc_error(-1, "no free slot for the role", initiator.holepunchsession, "initiator", "127.0.0.1:1")
        # As responder, a session with a peer already connected to is refused too.
        assert_raises_rpc_error(-1, "already connected to the endpoint", initiator.holepunchsession, "responder", responder_endpoint)

        self.log.info("A session that produces no connection fails after the window and the grace period")
        responder.holepunchsession("responder", "127.0.0.1:1")
        assert_equal(len(responder.getholepunchinfo()["sessions"]), 1)
        assert_equal(responder.getholepunchinfo()["sessions"][0]["role"], "responder")
        responder.setmocktime(int(time.time()) + 126)
        self.wait_until(lambda: responder.getholepunchinfo()["sessions"] == [])
        assert_equal(responder.getholepunchinfo()["session_stats"]["responder"]["failed"], 1)
        responder.setmocktime(0)
        self.disconnect_nodes(0, 2)

    def test_rounds(self):
        visitor = self.nodes[0]
        self.restart_node(0)

        def info():
            return visitor.getholepunchinfo()

        def board(idx):
            return visitor.add_outbound_p2p_connection(HolePunchPeer(flags=FLAG_BOARD, report=("1.2.3.4", 5555), echo=True), p2p_idx=idx, connection_type="holepunch-board")

        def serve(mock, entries):
            msg = msg_addrv2()
            msg.addrs = [punchkey_element(ip, port, key.get_pubkey().get_bytes()) for ip, port, key in entries]
            mock.send_and_ping(msg)

        def new_entries(n):
            entries = []
            for _ in range(n):
                key = ECKey()
                key.generate()
                entries.append(("127.0.0.1", free_port(), key))
            return entries

        def sessions():
            return sorted((s["endpoint"], s["role"]) for s in info()["sessions"])

        self.log.info("A round is held for every new block")
        held = info()["rounds"]["held"]
        self.generate(visitor, 1, sync_fun=self.no_op)
        assert_equal(info()["rounds"]["held"], held + 1)
        assert_equal(info()["rounds"]["last_height"], visitor.getblockcount())

        board_a, board_b = board(0), board(1)
        for mock in (board_a, board_b):
            mock.wait_until(lambda: len(mock.elements) == 1)
        model = PickModel(bytes.fromhex(info()["families"][0]["key"]), ("1.2.3.4", 5555))

        self.log.info("Entries take part in a round only once the tip reached the parent after they arrived")
        entries_a = new_entries(6)
        serve(board_a, entries_a)
        model.serve(entries_a, "a", visitor.getblockcount())
        assert_equal(info()["table"]["entries"], 6)
        # The block right after the entries arrived: its parent came before them, no pick.
        height = visitor.getblockcount() + 1
        block = self.generate(visitor, 1, sync_fun=self.no_op)[0]
        assert_equal(model.round(height, block), [])
        assert_equal(sessions(), [])
        assert_equal(info()["rounds"]["picks"], 0)

        self.log.info("The lowest pair values are picked, at most two from one board, one as initiator")
        height = visitor.getblockcount() + 1
        block = self.generate(visitor, 1, sync_fun=self.no_op)[0]
        expected = model.round(height, block)
        assert 1 <= len(expected) <= 2
        self.wait_until(lambda: sessions() == expected)
        assert_equal(info()["rounds"]["picks"], len(expected))
        assert_equal(info()["table"]["entries"], 6 - len(expected))

        self.log.info("With entries from two boards, up to three sessions start per round")
        entries_b = new_entries(6)
        serve(board_b, entries_b)
        model.serve(entries_b, "b", visitor.getblockcount())
        for _ in range(2):
            height = visitor.getblockcount() + 1
            block = self.generate(visitor, 1, sync_fun=self.no_op)[0]
            model.round(height, block)
            self.wait_until(lambda: len(sessions()) == model.active)
        assert_equal(len(sessions()), model.active)
        assert_equal(info()["rounds"]["picks"], model.active)
        assert model.active >= 3

        self.log.info("A reorganisation to a chain of equal height holds no round")
        held = info()["rounds"]["held"]
        visitor.invalidateblock(visitor.getbestblockhash())
        # Another coinbase, so that the replacement is not the block just invalidated.
        self.generatetoaddress(visitor, 1, ADDRESS_BCRT1_UNSPENDABLE, sync_fun=self.no_op)
        assert_equal(info()["rounds"]["held"], held)
        self.generate(visitor, 1, sync_fun=self.no_op)
        assert_equal(info()["rounds"]["held"], held + 1)
        visitor.disconnect_p2ps()

    def test_visitors_outside_inbound_limit(self):
        board = self.nodes[1]
        self.log.info("Visitors do not take inbound slots at a board")
        # Room for two inbound connections next to the automatic outbound ones.
        self.restart_node(1, extra_args=self.extra_args[1] + ["-maxconnections=13"])
        for _ in range(2):
            board.add_p2p_connection(HolePunchPeer(flags=FLAG_VISITOR))
        for _ in range(2):
            board.add_p2p_connection(HolePunchPeer(flags=None))
        assert_equal(len(board.getpeerinfo()), 4)
        # The inbound slots are full now: the next ordinary connection is dropped,
        # and the visitors are not evicted to make room.
        board.add_p2p_connection(HolePunchPeer(flags=None), wait_for_verack=False, expect_success=False)
        assert_equal(len(board.getpeerinfo()), 4)
        assert_equal(len([p for p in board.getpeerinfo() if p["holepunch_flags"] == ["VISITOR"]]), 2)
        board.disconnect_p2ps()

    def run_test(self):
        self.test_options()
        self.test_board_connection_port()
        self.test_feature_exchange()
        self.test_board_connection_protocol()
        self.test_external_address()
        self.test_board_connections()
        self.test_announcements()
        self.test_board_serving()
        self.test_rounds()
        self.test_punched_connection()
        self.test_visitors_outside_inbound_limit()


if __name__ == '__main__':
    HolePunchTest(__file__).main()
