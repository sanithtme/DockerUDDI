"""Minimal DNS client (A, AAAA, PTR, TXT) using only the standard library.

Deliberately dependency-free so the demo runs on a bare lab VM. Supports UDP with TCP
fallback on truncation, optional source-address binding, and response validation.
"""
from __future__ import annotations

import ipaddress
import random
import socket
import struct
import time
from dataclasses import dataclass

# A/AAAA/PTR/TXT are the default traffic mix; the rest exist for zone/record testing
QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28,
          "SRV": 33, "CAA": 257}
QTYPE_NAMES = {v: k for k, v in QTYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def encode_name(name: str) -> bytes:
    name = name.rstrip(".")
    if not name:
        return b"\x00"
    try:
        ascii_name = name.encode("idna")
    except UnicodeError as exc:
        raise ValueError(f"invalid domain name {name!r}: {exc}") from None
    out = b""
    for label in ascii_name.split(b"."):
        if not label or len(label) > 63:
            raise ValueError(f"invalid label in {name!r}")
        out += bytes([len(label)]) + label
    if len(out) + 1 > 255:
        raise ValueError(f"domain name too long: {name!r}")
    return out + b"\x00"


EdnsOption = tuple[int, bytes]  # (option code, raw option data)


def build_query(txid: int, name: str, qtype: str, recursion_desired: bool = True,
                edns_options: list[EdnsOption] | None = None, udp_payload: int = 1232) -> bytes:
    """Build a query. ``edns_options=None`` sends no OPT record; a list (even empty) adds one."""
    header = struct.pack("!HHHHHH", txid, 0x0100 if recursion_desired else 0, 1, 0, 0,
                         0 if edns_options is None else 1)
    msg = header + encode_name(name) + struct.pack("!HH", QTYPES[qtype], 1)
    if edns_options is not None:
        rdata = b"".join(struct.pack("!HH", code, len(data)) + data for code, data in edns_options)
        # OPT pseudo-RR: root name, TYPE 41, CLASS = UDP payload size, TTL = ext-rcode/version/flags (0)
        msg += b"\x00" + struct.pack("!HHIH", 41, udp_payload, 0, len(rdata)) + rdata
    return msg


def parse_edns_options(query: bytes) -> list[EdnsOption]:
    """EDNS options carried by a *query* (one question, no answer/authority records)."""
    _txid, _flags, _qd, _an, _ns, ar = struct.unpack("!HHHHHH", query[:12])
    _name, _qt, _qc, pos = parse_question(query)
    options: list[EdnsOption] = []
    for _ in range(ar):
        if query[pos] != 0:  # only root-named records (the OPT RR) are expected here
            return options
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", query[pos + 1 : pos + 11])
        pos += 11
        end = pos + rdlen
        if rtype == 41:
            while pos + 4 <= end:
                code, ln = struct.unpack("!HH", query[pos : pos + 4])
                options.append((code, query[pos + 4 : pos + 4 + ln]))
                pos += 4 + ln
        pos = end
    return options


def reverse_name(ip: str) -> str:
    return ipaddress.ip_address(ip).reverse_pointer


@dataclass
class Header:
    txid: int
    qr: bool
    truncated: bool
    rcode: int
    qdcount: int
    ancount: int
    aa: bool = False  # authoritative answer


def parse_header(data: bytes) -> Header:
    if len(data) < 12:
        raise ValueError("short DNS message")
    txid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    return Header(txid, bool(flags & 0x8000), bool(flags & 0x0200), flags & 0xF, qd, an,
                  bool(flags & 0x0400))


def parse_question(data: bytes) -> tuple[str, int, int, int]:
    """Return ``(name, qtype, qclass, end_offset)`` for the first question."""
    pos, labels = 12, []
    while True:
        if pos >= len(data):
            raise ValueError("truncated question")
        ln = data[pos]
        if ln == 0:
            pos += 1
            break
        if ln & 0xC0:
            raise ValueError("compressed name in question not supported")
        labels.append(data[pos + 1 : pos + 1 + ln].decode("ascii", "replace"))
        pos += 1 + ln
    qtype, qclass = struct.unpack("!HH", data[pos : pos + 4])
    return ".".join(labels), qtype, qclass, pos + 4


def build_response(query: bytes, rcode: int = 0, aa: bool = False) -> bytes:
    """Build a minimal answer (used by the mock DNS server). ``aa`` sets the authoritative bit."""
    name, qtype, _qclass, end = parse_question(query)
    txid = struct.unpack("!H", query[:2])[0]
    answers = b""
    count = 0
    if rcode == 0:
        ptr = b"\xc0\x0c"
        if qtype == QTYPES["A"]:
            rdata = socket.inet_aton("192.0.2.1")
        elif qtype == QTYPES["AAAA"]:
            rdata = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        elif qtype == QTYPES["TXT"]:
            rdata = b"\x04mock"
        elif qtype == QTYPES["PTR"]:
            rdata = encode_name("mock-host.example.")
        elif qtype in (QTYPES["CNAME"], QTYPES["NS"]):
            rdata = encode_name("target.mock.test.")
        elif qtype == QTYPES["MX"]:
            rdata = struct.pack("!H", 10) + encode_name("mail.mock.test.")
        elif qtype == QTYPES["SRV"]:
            rdata = struct.pack("!HHH", 0, 0, 5060) + encode_name("host.mock.test.")
        elif qtype == QTYPES["CAA"]:
            rdata = struct.pack("!BB", 0, 5) + b"issue" + b"ca.test"
        else:
            rdata = b""
        if rdata:
            answers = ptr + struct.pack("!HHIH", qtype, 1, 60, len(rdata)) + rdata
            count = 1
    header = struct.pack("!HHHHHH", txid, 0x8180 | (0x0400 if aa else 0) | rcode, 1, count, 0, 0)
    return header + query[12:end] + answers


@dataclass
class QueryResult:
    name: str
    qtype: str
    ok: bool  # a DNS response was received (any RCODE)
    rcode: int | None = None
    latency_ms: float = 0.0
    error: str | None = None
    tcp_fallback: bool = False
    aa: bool | None = None  # authoritative-answer flag from the response
    ancount: int | None = None  # answer records in the response

    @property
    def rcode_name(self) -> str:
        return RCODES.get(self.rcode, f"RCODE{self.rcode}") if self.rcode is not None else "-"


def _family(server: str) -> int:
    return socket.AF_INET6 if ":" in server else socket.AF_INET


def _udp(server: str, port: int, payload: bytes, txid: int, timeout: float,
         source_ip: str | None) -> bytes:
    sock = socket.socket(_family(server), socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        if source_ip:
            sock.bind((source_ip, 0))
        sock.sendto(payload, (server, port))
        deadline = time.monotonic() + timeout
        while True:
            data, _ = sock.recvfrom(4096)
            if len(data) >= 12 and struct.unpack("!H", data[:2])[0] == txid:
                return data
            if time.monotonic() > deadline:
                raise socket.timeout("timed out waiting for matching response")
    finally:
        sock.close()


def _tcp(server: str, port: int, payload: bytes, txid: int, timeout: float,
         source_ip: str | None) -> bytes:
    sock = socket.socket(_family(server), socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if source_ip:
            sock.bind((source_ip, 0))
        sock.connect((server, port))
        sock.sendall(struct.pack("!H", len(payload)) + payload)
        raw_len = _recv_exact(sock, 2)
        data = _recv_exact(sock, struct.unpack("!H", raw_len)[0])
        if struct.unpack("!H", data[:2])[0] != txid:
            raise ValueError("TCP response txid mismatch")
        return data
    finally:
        sock.close()


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed mid-message")
        buf += chunk
    return buf


def resolve(server: str, port: int, name: str, qtype: str, timeout: float = 2.0,
            source_ip: str | None = None, rng: random.Random | None = None,
            edns_options: list[EdnsOption] | None = None) -> QueryResult:
    """Send one query. Never raises for network problems; returns ``ok=False`` instead.

    ``OSError`` from source binding is re-raised as-is so callers can apply bind fallback.
    """
    txid = (rng or random).randrange(0, 65536)
    try:
        payload = build_query(txid, name, qtype, edns_options=edns_options)
    except ValueError as exc:
        return QueryResult(name, qtype, ok=False, error=str(exc))
    start = time.monotonic()
    tcp = False
    try:
        data = _udp(server, port, payload, txid, timeout, source_ip)
        if parse_header(data).truncated:
            tcp = True
            data = _tcp(server, port, payload, txid, timeout, source_ip)
        hdr = parse_header(data)
        return QueryResult(name, qtype, ok=True, rcode=hdr.rcode,
                           latency_ms=(time.monotonic() - start) * 1000, tcp_fallback=tcp,
                           aa=hdr.aa, ancount=hdr.ancount)
    except socket.timeout:
        return QueryResult(name, qtype, ok=False, error="timeout",
                           latency_ms=(time.monotonic() - start) * 1000, tcp_fallback=tcp)
    except OSError as exc:
        if source_ip and exc.errno in (99, 49, 10049, 22):  # EADDRNOTAVAIL (linux/mac/win), EINVAL
            raise
        return QueryResult(name, qtype, ok=False, error=f"{type(exc).__name__}: {exc}",
                           latency_ms=(time.monotonic() - start) * 1000, tcp_fallback=tcp)
    except ValueError as exc:
        return QueryResult(name, qtype, ok=False, error=f"bad response: {exc}", tcp_fallback=tcp)
