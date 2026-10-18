#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Check whether this host's NAT allows TCP hole punching (-holepunch).

Hole punching needs the NAT in front of this host to keep one local port
mapped to one external address and port whatever the destination is, which
RFC 4787 calls an endpoint-independent mapping. This script measures that
with the Bitcoin P2P protocol itself: it opens connections to several
reachable nodes from one local port and reads the address each of them
reports back in its version message, which is the same signal a node with
-holepunch uses. If every node reports the same external endpoint, hole
punching can work from here.

The connections are plain v1 and are closed as soon as the version message
has arrived. Nothing is sent to the network beyond one version message per
peer. Run it on the host that cannot accept incoming connections.
"""

import argparse
import hashlib
import ipaddress
import random
import socket
import struct
import sys
import time

# Chain magics and default ports, from src/kernel/chainparams.cpp. Signet
# derives its magic from the challenge, so pass --magic for a custom signet.
CHAINS = {
    "main": ("f9beb4d9", 8333),
    "testnet3": ("0b110907", 18333),
    "testnet4": ("1c163f28", 48333),
    "signet": ("0a03cf40", 38333),
    "regtest": ("fabfb5da", 18444),
}

DNS_SEEDS = {
    "main": ["seed.bitcoin.sipa.be", "dnsseed.bluematt.me", "seed.bitcoin.sprovoost.nl",
             "dnsseed.emzy.de", "seed.bitcoin.wiz.biz"],
    "testnet3": ["testnet-seed.bitcoin.jonasschnelli.ch", "seed.tbtc.petertodd.net"],
    "testnet4": ["seed.testnet4.bitcoin.sprovoost.nl", "seed.testnet4.wiz.biz"],
    "signet": ["seed.signet.bitcoin.sprovoost.nl"],
    "regtest": [],
}

PROTOCOL_VERSION = 70016
USER_AGENT = b"/nat-check:0.1/"
# The dynamic port range a node picks its punch port from.
PUNCH_PORT_MIN = 49152
PUNCH_PORT_MAX = 65535


def double_sha256(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def encode_address(host, port):
    """services, 16 byte address and big-endian port, as a version message carries it."""
    try:
        packed = socket.inet_pton(socket.AF_INET6, host)
    except OSError:
        packed = b"\x00" * 10 + b"\xff\xff" + socket.inet_pton(socket.AF_INET, host)
    return struct.pack("<Q", 0) + packed + struct.pack(">H", port)


# Offset of addr_recv in a version payload: version, services and timestamp.
ADDR_RECV_OFFSET = 4 + 8 + 8
# Its own length: services, 16 address bytes and the port.
ADDR_LENGTH = 8 + 16 + 2


def decode_addr_recv(payload):
    """The address and port a version message reports for its receiver, which is us."""
    field = payload[ADDR_RECV_OFFSET:ADDR_RECV_OFFSET + ADDR_LENGTH]
    packed, port = field[8:24], struct.unpack(">H", field[24:26])[0]
    if packed[:12] == b"\x00" * 10 + b"\xff\xff":
        return socket.inet_ntop(socket.AF_INET, packed[12:]), port
    return socket.inet_ntop(socket.AF_INET6, packed), port


def version_message(magic, peer_host, peer_port):
    payload = struct.pack("<iQq", PROTOCOL_VERSION, 0, int(time.time()))
    payload += encode_address(peer_host, peer_port)
    payload += encode_address("0.0.0.0", 0)
    payload += struct.pack("<Q", random.getrandbits(64))
    payload += bytes([len(USER_AGENT)]) + USER_AGENT
    payload += struct.pack("<i", 0) + b"\x00"  # start height, relay
    header = magic + b"version".ljust(12, b"\x00") + struct.pack("<I", len(payload))
    return header + double_sha256(payload)[:4] + payload


def read_exactly(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError("the peer closed the connection")
        data += chunk
    return data


def read_version(sock, magic):
    """Read messages until the peer's version arrives and return its addr_recv."""
    while True:
        header = read_exactly(sock, 24)
        if header[:4] != magic:
            raise ValueError("wrong network magic in the answer, is --chain right?")
        command = header[4:16].rstrip(b"\x00").decode("ascii", "replace")
        length = struct.unpack("<I", header[16:20])[0]
        if length > 4_000_000:
            raise ValueError(f"absurd {command} message length {length}")
        payload = read_exactly(sock, length)
        if command == "version":
            if length < ADDR_RECV_OFFSET + ADDR_LENGTH:
                raise ValueError("truncated version message")
            return decode_addr_recv(payload)


def bind_local(port, family):
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(("" if family == socket.AF_INET else "::", port))
    return sock


def ask_peer(host, port, local_port, magic, timeout):
    """Connect from local_port and return the endpoint the peer reports, plus the socket."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = bind_local(local_port, family)
    sock.settimeout(timeout)
    sock.connect((host, port))
    sock.sendall(version_message(magic, host, port))
    return read_version(sock, magic), sock


def network_group(host, port=0):
    """The /16 of an IPv4 address or the /32 of an IPv6 one, as the node groups peers.

    A node on a test network counts every peer as its own group, since they all
    share one address, so a peer that is not globally routable is grouped by its
    full endpoint here too.
    """
    addr = ipaddress.ip_address(host)
    if not addr.is_global:
        return f"{host}:{port}"
    prefix = 16 if addr.version == 4 else 32
    return str(ipaddress.ip_network(f"{host}/{prefix}", strict=False))


def resolve_peers(chain, port, count):
    """Addresses from the DNS seeds, at most one per network group."""
    peers, groups = [], set()
    seeds = list(DNS_SEEDS[chain])
    random.shuffle(seeds)
    for seed in seeds:
        try:
            infos = socket.getaddrinfo(seed, port, socket.AF_INET, socket.SOCK_STREAM)
        except OSError as e:
            print(f"  {seed}: {e}", file=sys.stderr)
            continue
        random.shuffle(infos)
        for info in infos:
            host = info[4][0]
            group = network_group(host, port)
            if group in groups:
                continue
            groups.add(group)
            peers.append((host, port))
            if len(peers) >= count:
                return peers
    return peers


def local_addresses():
    try:
        return {info[4][0] for info in socket.getaddrinfo(socket.gethostname(), None)}
    except OSError:
        return set()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--chain", choices=sorted(CHAINS), default="main", help="which network to speak to (default: main)")
    parser.add_argument("--magic", help="network magic as hex, for a custom signet")
    parser.add_argument("--peers", help="comma separated ip:port list to ask instead of the DNS seeds")
    parser.add_argument("--port", type=int, help="local port to connect from (default: a random port from the dynamic range, as a node picks its punch port)")
    parser.add_argument("--count", type=int, default=3, help="how many peers to ask (default: 3)")
    parser.add_argument("--timeout", type=float, default=10.0, help="seconds to wait per peer (default: 10)")
    args = parser.parse_args()

    magic_hex, default_port = CHAINS[args.chain]
    magic = bytes.fromhex(args.magic if args.magic else magic_hex)
    local_port = args.port if args.port else random.randint(PUNCH_PORT_MIN, PUNCH_PORT_MAX)

    if not hasattr(socket, "SO_REUSEPORT"):
        print("This system has no SO_REUSEPORT, which a node needs to share its punch port.")

    if args.peers:
        peers = []
        for entry in args.peers.split(","):
            host, _, port = entry.strip().rpartition(":")
            peers.append((host.strip("[]"), int(port)))
    else:
        print(f"Asking the {args.chain} DNS seeds for peers in distinct network groups")
        peers = resolve_peers(args.chain, default_port, args.count)
    if len(peers) < 2:
        print("Need at least two peers to compare, give them with --peers.")
        return 2

    print(f"Connecting to {len(peers)} peers from local port {local_port}\n")
    results, sockets = [], []
    for host, port in peers:
        try:
            # The sockets stay open together, as a node holds its board connections.
            (reported_host, reported_port), sock = ask_peer(host, port, local_port, magic, args.timeout)
            sockets.append(sock)
            results.append((host, port, reported_host, reported_port))
            print(f"  {host}:{port} ({network_group(host, port)}) sees us as {reported_host}:{reported_port}")
        except (OSError, EOFError, ValueError) as e:
            print(f"  {host}:{port} failed: {e}")
    for sock in sockets:
        sock.close()

    usable = [r for r in results if r[3] != 0]
    groups = {network_group(r[0], r[1]) for r in usable}
    print()
    if len(usable) < 2 or len(groups) < 2:
        print("Inconclusive: fewer than two peers in distinct network groups answered with an address.")
        print("A node behind a proxy, or one the peers cannot see, gets no address this way.")
        return 2

    ports = {r[3] for r in usable}
    addresses = {r[2] for r in usable}
    if len(ports) == 1 and len(addresses) == 1:
        external_port = ports.pop()
        print(f"Endpoint-independent mapping: every peer sees {addresses.pop()}:{external_port}.")
        print("Hole punching can work from this host, so -holepunch is worth enabling.")
        if external_port == local_port:
            print("The port is preserved, so the mapping is the simplest kind.")
        else:
            print(f"The external port {external_port} differs from the local one, which is fine.")
        if addresses & local_addresses():
            print("The address is one of this host's own, so there is no NAT, only a firewall.")
        return 0

    print("Endpoint-dependent mapping: the peers above do not agree on our endpoint.")
    print("This NAT gives each destination its own mapping, so hole punching cannot work.")
    print("A node here will find no external address and will not announce.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
