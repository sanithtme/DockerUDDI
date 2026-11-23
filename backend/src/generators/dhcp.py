"""DHCP activity generator.

``DHCPProvider`` is the abstraction. Two implementations ship:

* ``DRADHCPProvider`` wraps the Infoblox ``dras`` DHCP Relay Agent Simulator and ONLY uses
  invocations documented in internal material (see docs/verified-sources.md):

      request  : dras -i <server> -a <mac> [-c <relay>] [-O 12:<hex hostname>] -o <leasefile> -v
      discover : dras -i <server> -a <mac> [-c <relay>] -p            (-p ends after DHCPOFFER)
      renew    : dras -i <server> -f <leasefile> -w renew -v          (lease file: "<MAC> <IP>")
      release  : dras -i <server> -a <mac> [-c <relay>] -r            (-r = release after ACK)

* ``MockDHCPProvider`` is an in-memory lease table for local development and CI.

Known limits (documented, not hidden)
-------------------------------------
* ``release`` is documented only as "send release after ACK received", so a release is
  performed as request-then-release. A standalone release of a pre-existing lease is a TODO
  until verified with the tool owners.
* ``dras`` normally needs root (documented examples use sudo); ``use_sudo`` uses ``sudo -n``.
* dras requests a lease for the asset's *MAC*. The IP the server hands out only equals the
  third-party asset IP if the demo tenant has a matching fixed address / reservation for that
  MAC. The lease actually granted is recorded and reported.
* dras output format beyond "no replies received" and the DORA summary counters is not
  documented, so success detection is best-effort: exit code, "no replies received", and the
  "Acks Received" counter when present.
"""
from __future__ import annotations

import errno
import ipaddress
import json
import logging
import re
import shutil
import socket
import subprocess
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from demo_core.config import Config, DraConfig, NativeDhcpConfig
from demo_core.errors import ConfigError, ProviderError
from demo_core.models import Asset, utcnow_iso

from . import dhcpwire as W

log = logging.getLogger(__name__)

OPERATIONS = ("discover", "request", "renew", "release")


@dataclass
class DHCPResult:
    asset_id: str
    operation: str
    ok: bool
    mac: str | None = None
    ip: str | None = None
    message: str = ""
    command: list[str] = field(default_factory=list)
    returncode: int | None = None
    output_excerpt: str = ""
    dry_run: bool = False
    timestamp: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


class DHCPProvider(ABC):
    """Abstract DHCP lifecycle provider."""

    name = "abstract"

    @abstractmethod
    def discover(self, asset: Asset) -> DHCPResult: ...

    @abstractmethod
    def request(self, asset: Asset) -> DHCPResult: ...

    @abstractmethod
    def renew(self, asset: Asset) -> DHCPResult: ...

    @abstractmethod
    def release(self, asset: Asset) -> DHCPResult: ...

    def perform(self, operation: str, asset: Asset) -> DHCPResult:
        if operation not in OPERATIONS:
            raise ConfigError(f"unknown DHCP operation {operation!r}; use one of {OPERATIONS}")
        if not asset.dhcp_eligible:
            return DHCPResult(asset.asset_id, operation, False, message="skipped: no validated MAC")
        return getattr(self, operation)(asset)


# --------------------------------------------------------------------------- mock
class MockDHCPProvider(DHCPProvider):
    """In-memory lease table. Mirrors the *semantics* of the real operations."""

    name = "mock"

    def __init__(self, pool_prefix: str = "10.20.30.", pool_start: int = 100,
                 state_path: str | Path | None = None):
        """``state_path`` persists leases across CLI invocations (renew needs a prior request)."""
        self._state_path = Path(state_path) if state_path else None
        self._leases: dict[str, str] = {}
        self._pool_prefix, self._next = pool_prefix, pool_start
        self._lock = threading.Lock()
        self.calls: list[tuple[str, str]] = []
        if self._state_path and self._state_path.exists():
            try:
                data = json.loads(self._state_path.read_text())
                self._leases, self._next = data["leases"], data["next"]
            except (OSError, ValueError, KeyError):
                pass

    def _persist(self) -> None:
        if self._state_path:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            self._state_path.write_text(json.dumps({"leases": self._leases, "next": self._next}))

    def _record(self, op: str, asset: Asset) -> None:
        self.calls.append((op, asset.asset_id))

    def discover(self, asset: Asset) -> DHCPResult:
        self._record("discover", asset)
        return DHCPResult(asset.asset_id, "discover", True, asset.mac, message="mock OFFER")

    def request(self, asset: Asset) -> DHCPResult:
        self._record("request", asset)
        with self._lock:
            ip = self._leases.get(asset.mac or "")
            if ip is None:
                ip = asset.ip if asset.ipv4 else f"{self._pool_prefix}{self._next}"
                self._next += 1
                self._leases[asset.mac or ""] = ip
                self._persist()
        return DHCPResult(asset.asset_id, "request", True, asset.mac, ip, "mock ACK")

    def renew(self, asset: Asset) -> DHCPResult:
        self._record("renew", asset)
        with self._lock:
            ip = self._leases.get(asset.mac or "")
        if ip is None:
            return DHCPResult(asset.asset_id, "renew", False, asset.mac, message="mock NAK: no lease")
        return DHCPResult(asset.asset_id, "renew", True, asset.mac, ip, "mock ACK (renewed)")

    def release(self, asset: Asset) -> DHCPResult:
        self._record("release", asset)
        with self._lock:
            ip = self._leases.pop(asset.mac or "", None)
            self._persist()
        if ip is None:
            return DHCPResult(asset.asset_id, "release", False, asset.mac, message="no lease to release")
        return DHCPResult(asset.asset_id, "release", True, asset.mac, ip, "mock released")


# --------------------------------------------------------------------------- dras
Runner = Callable[[list[str], float], "subprocess.CompletedProcess[str]"]


def _default_runner(cmd: list[str], timeout: float) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


_ACKS = re.compile(r"acks?\s+received\D*(\d+)", re.IGNORECASE)


def relay_for(asset: Asset, cfg: DraConfig) -> str | None:
    """giaddr for an asset: a matching ``relay_map`` entry wins, else ``relay_agent_ip``."""
    if asset.ipv4:
        for entry in cfg.relay_map:
            if ipaddress.ip_address(asset.ipv4) in ipaddress.ip_network(entry["cidr"], strict=False):
                return entry["relay"]
    return cfg.relay_agent_ip


class DRADHCPProvider(DHCPProvider):
    name = "dra"

    def __init__(self, server: str, cfg: DraConfig, port: int = 67, dry_run: bool = False,
                 runner: Runner = _default_runner):
        try:
            ipaddress.ip_address(server)
        except ValueError:
            raise ConfigError(f"dhcp.server {server!r} is not an IP address") from None
        self.server, self.cfg, self.port = server, cfg, port
        self.dry_run, self._runner = dry_run, runner
        self.lease_dir = Path(cfg.lease_dir)
        self._state_file = self.lease_dir / "leases.json"
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ helpers
    def check_binaries(self) -> list[str]:
        """Return a list of problems (empty = OK)."""
        problems = []
        for b in {self.cfg.binary, self.cfg.renew_binary}:
            if shutil.which(b) is None:
                problems.append(f"'{b}' not found on PATH (see docs: dras install within the lab)")
        if self.cfg.use_sudo and shutil.which("sudo") is None:
            problems.append("dhcp.dra.use_sudo is true but 'sudo' is not installed")
        return problems

    def _relay_for(self, asset: Asset) -> str | None:
        return relay_for(asset, self.cfg)

    def _argv(self, binary: str) -> list[str]:
        argv = (["sudo", "-n"] if self.cfg.use_sudo else []) + [binary, "-i", self.server]
        if self.port != 67:
            argv += ["-P", str(self.port)]
        return argv

    def _lease_file(self, asset: Asset) -> Path:
        return self.lease_dir / f"{asset.asset_id}.lease"

    def _load_state(self) -> dict[str, Any]:
        try:
            return json.loads(self._state_file.read_text())
        except (OSError, json.JSONDecodeError):
            return {}

    def _save_lease(self, asset: Asset, ip: str | None) -> None:
        with self._lock:
            state = self._load_state()
            if ip:
                state[asset.asset_id] = {"mac": asset.mac, "ip": ip, "updated": utcnow_iso()}
            else:
                state.pop(asset.asset_id, None)
            self.lease_dir.mkdir(parents=True, exist_ok=True)
            self._state_file.write_text(json.dumps(state, indent=2, sort_keys=True))

    def _known_ip(self, asset: Asset) -> str | None:
        rec = self._load_state().get(asset.asset_id)
        return (rec or {}).get("ip") or asset.ipv4

    @staticmethod
    def _parse_lease_file(path: Path) -> str | None:
        """Lease files are '<MAC> <IP> [hostname]' per line (format from internal tool docs)."""
        try:
            for line in path.read_text().splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        return str(ipaddress.ip_address(parts[1]))
                    except ValueError:
                        continue
        except OSError:
            pass
        return None

    def _exec(self, asset: Asset, op: str, cmd: list[str]) -> tuple[DHCPResult, str]:
        base = DHCPResult(asset.asset_id, op, False, mac=asset.mac, command=cmd, dry_run=self.dry_run)
        if self.dry_run:
            base.ok, base.message = True, "dry-run: command not executed"
            return base, ""
        try:
            proc = self._runner(cmd, self.cfg.timeout)
        except FileNotFoundError:
            base.message = f"{cmd[0] if cmd[0] != 'sudo' else cmd[2]} not found"
            return base, ""
        except subprocess.TimeoutExpired:
            base.message = f"timed out after {self.cfg.timeout:.0f}s"
            return base, ""
        out = (proc.stdout or "") + (proc.stderr or "")
        base.returncode = proc.returncode
        base.output_excerpt = out.strip()[-600:]
        low = out.lower()
        acks = _ACKS.search(out)
        if proc.returncode != 0:
            base.message = f"exit code {proc.returncode}"
            if "password is required" in low or "a terminal is required" in low:
                base.message += " (sudo needs a password: configure passwordless sudo for dras)"
        elif "no replies received" in low:
            base.message = "no replies received from DHCP server"
        elif acks and int(acks.group(1)) == 0 and op != "discover":
            base.message = "server sent no ACK"
        else:
            base.ok, base.message = True, "ok"
        return base, out

    def _common(self, asset: Asset, binary: str) -> list[str]:
        cmd = self._argv(binary) + ["-a", asset.mac or ""]
        relay = self._relay_for(asset)
        if relay:
            cmd += ["-c", relay]
        if self.cfg.interface and binary.endswith("raw"):
            cmd += ["-I", self.cfg.interface]
        return cmd

    # ------------------------------------------------------------------ operations
    def discover(self, asset: Asset) -> DHCPResult:
        cmd = self._common(asset, self.cfg.binary) + ["-p"] + self.cfg.extra_args
        if self.cfg.verbose:
            cmd.append("-v")
        res, _ = self._exec(asset, "discover", cmd)
        return res

    def request(self, asset: Asset) -> DHCPResult:
        lease_file = self._lease_file(asset)
        cmd = self._common(asset, self.cfg.binary)
        if self.cfg.send_hostname and asset.hostname and asset.hostname.isascii() and len(asset.hostname) <= 63:
            cmd += ["-O", f"12:{asset.hostname.encode().hex()}"]  # option 12, documented form
        cmd += ["-o", str(lease_file)] + self.cfg.extra_args
        if self.cfg.verbose:
            cmd.append("-v")
        if not self.dry_run:
            self.lease_dir.mkdir(parents=True, exist_ok=True)
            lease_file.unlink(missing_ok=True)
        res, _ = self._exec(asset, "request", cmd)
        if res.ok and not self.dry_run:
            res.ip = self._parse_lease_file(lease_file)
            if res.ip:
                self._save_lease(asset, res.ip)
            else:
                res.message = "ok (lease IP not captured: output lease file empty/unparseable)"
        return res

    def renew(self, asset: Asset) -> DHCPResult:
        ip = self._known_ip(asset)
        if not ip:
            return DHCPResult(asset.asset_id, "renew", False, asset.mac,
                              message="no known lease IP: run 'dhcp request' first or discover an IPv4")
        lease_file = self._lease_file(asset)
        if not self.dry_run:
            self.lease_dir.mkdir(parents=True, exist_ok=True)
            lease_file.write_text(f"{asset.mac} {ip}\n")  # documented '<MAC> <IP>' format
        cmd = self._argv(self.cfg.renew_binary) + ["-f", str(lease_file), "-w", "renew"] + self.cfg.extra_args
        if self.cfg.verbose:
            cmd.append("-v")
        res, _ = self._exec(asset, "renew", cmd)
        res.ip = ip
        return res

    def release(self, asset: Asset) -> DHCPResult:
        cmd = self._common(asset, self.cfg.binary) + ["-r"] + self.cfg.extra_args
        if self.cfg.verbose:
            cmd.append("-v")
        res, _ = self._exec(asset, "release", cmd)
        if res.ok and not self.dry_run:
            self._save_lease(asset, None)
        res.message += " (request-then-release; standalone release is a TODO, see module docs)" \
            if res.ok else ""
        return res


# --------------------------------------------------------------------------- native client
class NativeDHCPProvider(DHCPProvider):
    """Built-in relay-style DHCP client: DISCOVER/OFFER/REQUEST/ACK, renew, release.

    Behaves like ``dras -c <relay>``: giaddr is the relay address, packets are unicast to the DHCP
    server, and the server replies to giaddr on UDP 67. So the relay address must be one this host
    owns, UDP 67 must be free here, and binding it needs root (``sudo $(which demo) -c \"$DEMO_CONFIG\" ...``).
    """

    name = "native"

    def __init__(self, server: str, dra: DraConfig, native: NativeDhcpConfig, port: int = 67,
                 dry_run: bool = False):
        try:
            ipaddress.ip_address(server)
        except ValueError:
            raise ConfigError(f"dhcp.server {server!r} is not an IP address") from None
        self.server, self.dra, self.native, self.port, self.dry_run = server, dra, native, port, dry_run
        self.lease_dir = Path(dra.lease_dir)
        self._state_file = self.lease_dir / "native-leases.json"
        self._lock = threading.Lock()

    # -- lease state
    def _load(self) -> dict[str, Any]:
        try:
            return json.loads(self._state_file.read_text())
        except (OSError, json.JSONDecodeError):
            return {}

    def _save(self, asset: Asset, lease: dict[str, Any] | None) -> None:
        with self._lock:
            state = self._load()
            if lease:
                state[asset.asset_id] = {"mac": asset.mac, **lease, "updated": utcnow_iso()}
            else:
                state.pop(asset.asset_id, None)
            self.lease_dir.mkdir(parents=True, exist_ok=True)
            self._state_file.write_text(json.dumps(state, indent=2, sort_keys=True))

    def _known(self, asset: Asset) -> dict[str, Any] | None:
        rec = self._load().get(asset.asset_id)
        if rec and rec.get("ip"):
            return rec
        return {"ip": asset.ipv4, "server_id": self.server} if asset.ipv4 else None

    # -- transport
    def _relay(self, asset: Asset) -> str:
        relay = relay_for(asset, self.dra)
        if not relay:
            raise ConfigError("dhcp.dra.relay_agent_ip is required (it is the giaddr that selects the "
                              "subnet). Use an address inside your DHCP subnet that this host owns.")
        return relay

    def _hostname(self, asset: Asset) -> str | None:
        h = asset.hostname
        return h if (self.dra.send_hostname and h and h.isascii() and len(h) <= 63) else None

    def _open(self, relay: str) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((relay, self.native.listen_port))
        except OSError as exc:
            sock.close()
            if exc.errno in (errno.EACCES, errno.EPERM):
                raise _Fail(f"binding UDP port {self.native.listen_port} needs root. Run: "
                            "sudo $(which demo) -c \"$DEMO_CONFIG\" dhcp ... (then: sudo chown -R $USER state)") from None
            if exc.errno == errno.EADDRINUSE:
                raise _Fail(f"UDP port {self.native.listen_port} is already in use on this host (another "
                            "DHCP server/relay/client?). Check: sudo ss -ulpn | grep ':67 '") from None
            if exc.errno == errno.EADDRNOTAVAIL:
                raise _Fail(f"relay address {relay} is not an address this host owns. giaddr must be a "
                            "local address, e.g. the VM's own VPC address.") from None
            raise _Fail(f"cannot bind {relay}:{self.native.listen_port}: {exc}") from None
        return sock

    def _exchange(self, sock: socket.socket, pkt: bytes, xid: int, mac: str, want: set[int]
                  ) -> W.Packet | None:
        """Send ``pkt`` (retrying) and return the first reply of a wanted type for this xid/MAC."""
        for _ in range(self.native.retries):
            sock.sendto(pkt, (self.server, self.port))
            deadline = time.monotonic() + self.native.timeout
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                sock.settimeout(left)
                try:
                    data, _addr = sock.recvfrom(4096)
                except socket.timeout:
                    break
                try:
                    reply = W.parse_packet(data)
                except ValueError:
                    continue
                if reply.xid == xid and reply.mac == mac and reply.op == W.BOOTREPLY and \
                        reply.msg_type in want:
                    return reply
        return None

    def _run(self, asset: Asset, op: str, body) -> DHCPResult:
        base = DHCPResult(asset.asset_id, op, False, mac=asset.mac)
        try:
            relay = self._relay(asset)
        except ConfigError as exc:
            base.message = str(exc)
            return base
        base.command = [f"native-dhcp {op}", f"server={self.server}:{self.port}", f"giaddr={relay}",
                        f"chaddr={asset.mac}", f"hostname={self._hostname(asset) or '-'}"]
        if self.dry_run:
            base.dry_run, base.ok, base.message = True, True, "dry-run: nothing sent"
            return base
        try:
            sock = self._open(relay)
        except _Fail as exc:
            base.message = str(exc)
            return base
        try:
            body(sock, relay, base)
        except _Fail as exc:
            base.message = str(exc)
        finally:
            sock.close()
        return base

    # -- operations
    def _discover(self, sock, relay: str, asset: Asset) -> tuple[W.Packet | None, int]:
        xid = W.new_xid()
        pkt = W.build_packet(W.DISCOVER, asset.mac or "", xid, giaddr=relay, hostname=self._hostname(asset))
        return self._exchange(sock, pkt, xid, asset.mac or "", {W.OFFER}), xid

    def discover(self, asset: Asset) -> DHCPResult:
        def body(sock, relay, res):
            offer, _ = self._discover(sock, relay, asset)
            if offer is None:
                raise _Fail("no replies received from DHCP server")
            res.ok, res.ip = True, offer.yiaddr
            res.message = f"OFFER {offer.yiaddr} from {offer.server_id or self.server}"
        return self._run(asset, "discover", body)

    def request(self, asset: Asset) -> DHCPResult:
        def body(sock, relay, res):
            offer, _ = self._discover(sock, relay, asset)
            if offer is None:
                raise _Fail("no replies received from DHCP server")
            sid = offer.server_id or self.server
            xid = W.new_xid()
            pkt = W.build_packet(W.REQUEST, asset.mac or "", xid, giaddr=relay,
                                 hostname=self._hostname(asset), requested_ip=offer.yiaddr, server_id=sid)
            reply = self._exchange(sock, pkt, xid, asset.mac or "", {W.ACK, W.NAK})
            if reply is None:
                raise _Fail("server sent no ACK")
            if reply.msg_type == W.NAK:
                raise _Fail(f"server sent NAK for {offer.yiaddr} (is the range exhausted, or the "
                            "address reserved for another client?)")
            res.ok, res.ip = True, reply.yiaddr
            res.message = f"ACK {reply.yiaddr} from {sid}" + (f", lease {reply.lease_time}s" if reply.lease_time else "")
            self._save(asset, {"ip": reply.yiaddr, "server_id": sid, "lease_time": reply.lease_time})
        return self._run(asset, "request", body)

    def renew(self, asset: Asset) -> DHCPResult:
        def body(sock, relay, res):
            known = self._known(asset)
            if not known:
                raise _Fail("no known lease: run 'dhcp request' first")
            xid = W.new_xid()
            pkt = W.build_packet(W.REQUEST, asset.mac or "", xid, giaddr=relay, ciaddr=known["ip"],
                                 hostname=self._hostname(asset))
            reply = self._exchange(sock, pkt, xid, asset.mac or "", {W.ACK, W.NAK})
            if reply is None:
                raise _Fail("no replies received from DHCP server")
            if reply.msg_type == W.NAK:
                raise _Fail(f"server sent NAK: {known['ip']} is no longer this client's lease")
            res.ok, res.ip = True, reply.yiaddr or known["ip"]
            res.message = f"ACK (renewed) {res.ip}" + (f", lease {reply.lease_time}s" if reply.lease_time else "")
            self._save(asset, {"ip": res.ip, "server_id": known.get("server_id") or self.server,
                               "lease_time": reply.lease_time})
        return self._run(asset, "renew", body)

    def release(self, asset: Asset) -> DHCPResult:
        def body(sock, relay, res):
            known = self._known(asset)
            if not known:
                raise _Fail("no known lease to release")
            pkt = W.build_packet(W.RELEASE, asset.mac or "", W.new_xid(), giaddr=relay, ciaddr=known["ip"],
                                 server_id=known.get("server_id") or self.server)
            sock.sendto(pkt, (self.server, self.port))  # RELEASE has no reply
            res.ok, res.ip = True, known["ip"]
            res.message = f"RELEASE sent for {known['ip']} (the protocol gives no reply)"
            self._save(asset, None)
        return self._run(asset, "release", body)


class _Fail(Exception):
    """Internal: carries a user-facing failure message out of a DHCP operation."""


# --------------------------------------------------------------------------- factory / runner
def build_dhcp_provider(cfg: Config, dry_run: bool = False) -> DHCPProvider:
    choice = cfg.dhcp.provider
    if choice == "auto":
        if cfg.infrastructure.type == "mock":
            choice = "mock"
        else:  # prefer the real tool when installed, otherwise the built-in client
            choice = "dra" if shutil.which(cfg.dhcp.dra.binary) else "native"
    if choice == "mock":
        return MockDHCPProvider(state_path=Path(cfg.dhcp.dra.lease_dir) / "mock-leases.json")
    if not cfg.dhcp.server:
        raise ConfigError("dhcp.server is required for a real DHCP provider")
    if choice == "native":
        return NativeDHCPProvider(cfg.dhcp.server, cfg.dhcp.dra, cfg.dhcp.native, cfg.dhcp.port, dry_run=dry_run)
    provider = DRADHCPProvider(cfg.dhcp.server, cfg.dhcp.dra, cfg.dhcp.port, dry_run=dry_run)
    if not dry_run:
        problems = provider.check_binaries()
        if problems:
            raise ProviderError("DRA DHCP provider unavailable:\n  - " + "\n  - ".join(problems)
                                + "\nUse dhcp.provider: native (built in), --dry-run, or dhcp.provider: mock.")
    return provider


def run_dhcp_operation(provider: DHCPProvider, operation: str, assets: list[Asset],
                       delay: float = 0.0, sleep: Callable[[float], None] = time.sleep
                       ) -> list[DHCPResult]:
    """Run one operation per asset sequentially (DHCP load is deliberately gentle)."""
    results = []
    for i, asset in enumerate(assets):
        if i and delay > 0:
            sleep(delay)
        results.append(provider.perform(operation, asset))
    return results
