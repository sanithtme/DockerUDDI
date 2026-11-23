"""Minimal DHCPv4 packet builder/parser (RFC 2131/2132), standard library only.

Used by the native DHCP provider to act like a relay agent: it sets ``giaddr`` so the server picks
the subnet from it, and unicasts the request to the server. Only what the demo needs is supported.
"""
from __future__ import annotations

import ipaddress
import os
import struct
from dataclasses import dataclass, field

MAGIC = b"\x63\x82\x53\x63"
BOOTREQUEST, BOOTREPLY = 1, 2

DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, INFORM = 1, 2, 3, 4, 5, 6, 7, 8
MSG_NAMES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK",
             7: "RELEASE", 8: "INFORM"}

OPT_HOSTNAME, OPT_REQUESTED_IP, OPT_LEASE_TIME, OPT_MSG_TYPE = 12, 50, 51, 53
OPT_SERVER_ID, OPT_PARAM_REQUEST, OPT_CLIENT_ID, OPT_END = 54, 55, 61, 255
DEFAULT_PARAM_REQUEST = bytes([1, 3, 6, 15, 51, 54])  # mask, router, DNS, domain, lease time, server id


def mac_bytes(mac: str) -> bytes:
    raw = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    if len(raw) != 6:
        raise ValueError(f"not a 6-byte MAC: {mac!r}")
    return raw


def mac_text(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw[:6])


def new_xid() -> int:
    return int.from_bytes(os.urandom(4), "big")


def build_packet(msg_type: int, mac: str, xid: int, giaddr: str = "0.0.0.0", ciaddr: str = "0.0.0.0",
                 hostname: str | None = None, requested_ip: str | None = None,
                 server_id: str | None = None, broadcast: bool = False) -> bytes:
    """Build a client->server message with relay address ``giaddr``."""
    chaddr = mac_bytes(mac)
    header = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", BOOTREQUEST, 1, 6, 0, xid, 0,
                         0x8000 if broadcast else 0, ipaddress.IPv4Address(ciaddr).packed,
                         b"\0" * 4, b"\0" * 4, ipaddress.IPv4Address(giaddr).packed,
                         chaddr.ljust(16, b"\0"), b"\0" * 64, b"\0" * 128)
    opts = bytes([OPT_MSG_TYPE, 1, msg_type])
    opts += bytes([OPT_CLIENT_ID, 7, 1]) + chaddr
    if hostname:
        host = hostname.encode("ascii")
        opts += bytes([OPT_HOSTNAME, len(host)]) + host
    if requested_ip:
        opts += bytes([OPT_REQUESTED_IP, 4]) + ipaddress.IPv4Address(requested_ip).packed
    if server_id:
        opts += bytes([OPT_SERVER_ID, 4]) + ipaddress.IPv4Address(server_id).packed
    if msg_type in (DISCOVER, REQUEST):
        opts += bytes([OPT_PARAM_REQUEST, len(DEFAULT_PARAM_REQUEST)]) + DEFAULT_PARAM_REQUEST
    opts += bytes([OPT_END])
    return (header + MAGIC + opts).ljust(300, b"\0")  # BOOTP minimum size


@dataclass
class Packet:
    op: int
    xid: int
    ciaddr: str
    yiaddr: str
    siaddr: str
    giaddr: str
    mac: str
    options: dict[int, bytes] = field(default_factory=dict)

    @property
    def msg_type(self) -> int | None:
        v = self.options.get(OPT_MSG_TYPE)
        return v[0] if v else None

    @property
    def msg_name(self) -> str:
        return MSG_NAMES.get(self.msg_type or 0, "?")

    @property
    def server_id(self) -> str | None:
        v = self.options.get(OPT_SERVER_ID)
        return str(ipaddress.IPv4Address(v)) if v and len(v) == 4 else None

    @property
    def requested_ip(self) -> str | None:
        v = self.options.get(OPT_REQUESTED_IP)
        return str(ipaddress.IPv4Address(v)) if v and len(v) == 4 else None

    @property
    def lease_time(self) -> int | None:
        v = self.options.get(OPT_LEASE_TIME)
        return struct.unpack("!I", v)[0] if v and len(v) == 4 else None

    @property
    def hostname(self) -> str | None:
        v = self.options.get(OPT_HOSTNAME)
        return v.decode("ascii", "replace") if v else None


def parse_packet(data: bytes) -> Packet:
    if len(data) < 240 or data[236:240] != MAGIC:
        raise ValueError("not a DHCP packet")
    op, htype, hlen, _hops, xid, _secs, _flags, ci, yi, si, gi, chaddr = struct.unpack(
        "!BBBBIHH4s4s4s4s16s", data[:44])
    options: dict[int, bytes] = {}
    pos = 240
    while pos < len(data):
        code = data[pos]
        if code == 0:  # pad
            pos += 1
            continue
        if code == OPT_END or pos + 1 >= len(data):
            break
        length = data[pos + 1]
        options[code] = data[pos + 2: pos + 2 + length]
        pos += 2 + length
    ip = lambda b: str(ipaddress.IPv4Address(b))  # noqa: E731
    return Packet(op, xid, ip(ci), ip(yi), ip(si), ip(gi), mac_text(chaddr[: hlen or 6]), options)
