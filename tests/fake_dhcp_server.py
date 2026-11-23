"""Test-only fake DHCP server speaking RFC 2131 over UDP on localhost.

Real servers reply to giaddr on port 67; this one replies to the sender's address so tests need no
privileges. Behaviours: "ok", "nak" (NAK every REQUEST), "silent" (ignore everything),
"offer_only" (answer DISCOVER, ignore REQUEST).
"""
from __future__ import annotations

import ipaddress
import socket
import struct
import threading

from generators import dhcpwire as W


def reply(req: W.Packet, msg_type: int, yiaddr: str, server_id: str) -> bytes:
    hdr = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", W.BOOTREPLY, 1, 6, 0, req.xid, 0, 0,
                      ipaddress.IPv4Address(req.ciaddr).packed, ipaddress.IPv4Address(yiaddr).packed,
                      ipaddress.IPv4Address(server_id).packed, ipaddress.IPv4Address(req.giaddr).packed,
                      W.mac_bytes(req.mac).ljust(16, b"\0"), b"\0" * 64, b"\0" * 128)
    opts = bytes([53, 1, msg_type, 54, 4]) + ipaddress.IPv4Address(server_id).packed
    opts += bytes([51, 4]) + struct.pack("!I", 3600) + bytes([1, 4, 255, 255, 240, 0, 255])
    return (hdr + W.MAGIC + opts).ljust(300, b"\0")


class FakeDhcp:
    def __init__(self, mode="ok", pool_start="172.31.47.100", server_id="10.9.9.9"):
        self.mode, self.server_id = mode, server_id
        self.next_ip = int(ipaddress.IPv4Address(pool_start))
        self.leases: dict[str, str] = {}   # mac -> ip (confirmed)
        self.offered: dict[str, str] = {}  # mac -> ip (offered)
        self.received: list[W.Packet] = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._loop, daemon=True)
        self._t.start()

    def types(self):
        return [p.msg_name for p in self.received]

    def stop(self):
        self._stop.set()
        self._t.join(2)
        self.sock.close()

    def _loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                p = W.parse_packet(data)
            except ValueError:
                continue
            self.received.append(p)
            if self.mode == "silent":
                continue
            out = None
            if p.msg_type == W.DISCOVER:
                ip = self.leases.get(p.mac) or self.offered.get(p.mac)
                if not ip:
                    ip = str(ipaddress.IPv4Address(self.next_ip))
                    self.next_ip += 1
                self.offered[p.mac] = ip
                out = reply(p, W.OFFER, ip, self.server_id)
            elif p.msg_type == W.REQUEST and self.mode != "offer_only":
                if self.mode == "nak":
                    out = reply(p, W.NAK, "0.0.0.0", self.server_id)
                elif p.ciaddr != "0.0.0.0":  # renew
                    ok = self.leases.get(p.mac) == p.ciaddr
                    out = reply(p, W.ACK if ok else W.NAK, p.ciaddr if ok else "0.0.0.0", self.server_id)
                elif p.requested_ip and self.offered.get(p.mac) == p.requested_ip:
                    self.leases[p.mac] = p.requested_ip
                    out = reply(p, W.ACK, p.requested_ip, self.server_id)
                else:
                    out = reply(p, W.NAK, "0.0.0.0", self.server_id)
            elif p.msg_type == W.RELEASE:
                self.leases.pop(p.mac, None)
            if out:
                self.sock.sendto(out, addr)
