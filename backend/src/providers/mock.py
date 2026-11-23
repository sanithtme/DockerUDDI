"""Mock infrastructure: a local UDP DNS responder so the whole demo runs offline (dev + CI)."""
from __future__ import annotations

import socketserver
import threading
import time
from collections import Counter

from generators import dnswire

from .base import Capabilities, CheckResult, Endpoint, InfrastructureProvider


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        srv: "MockDNSServer" = self.server  # type: ignore[assignment]
        try:
            name, qtype, _qc, _end = dnswire.parse_question(data)
        except (ValueError, IndexError):
            return
        try:
            edns = dnswire.parse_edns_options(data)
        except (ValueError, IndexError):
            edns = []
        srv.record(name, dnswire.QTYPE_NAMES.get(qtype, str(qtype)), self.client_address[0], edns)
        if srv.latency:
            time.sleep(srv.latency)
        lname = name.lower().rstrip(".")
        verdict = srv.authoritative_verdict(lname, dnswire.QTYPE_NAMES.get(qtype, ""))
        if verdict is not None:  # we are authoritative for this zone
            rcode, aa = verdict
        else:
            rcode, aa = (3 if lname in srv.nxdomain else 0), False
        sock.sendto(dnswire.build_response(data, rcode, aa), self.client_address)


class MockDNSServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, host: str = "127.0.0.1", port: int = 0, nxdomain: list[str] | None = None,
                 latency_ms: float = 0.0):
        super().__init__((host, port), _Handler)
        self.nxdomain = {d.lower().rstrip(".") for d in (nxdomain or [])}
        self.latency = latency_ms / 1000.0
        self.by_name: Counter[str] = Counter()
        self.by_type: Counter[str] = Counter()
        self.by_source: Counter[str] = Counter()
        self.by_edns: Counter[tuple[int, str]] = Counter()  # (option code, data hex) -> queries
        self.total = 0
        self._lock = threading.Lock()
        self._zones: dict[str, set[tuple[str, str]]] = {}  # zone fqdn -> {(name, TYPE)}

    # -- authoritative zones (lets tests/rehearsals emulate a server that serves created zones)
    def add_zone(self, fqdn: str, records: set[tuple[str, str]] | None = None) -> None:
        with self._lock:
            self._zones[fqdn.lower().rstrip(".")] = {(n.lower().rstrip("."), t.upper())
                                                      for n, t in (records or set())}

    def add_record(self, fqdn: str, name: str, qtype: str) -> None:
        with self._lock:
            self._zones.setdefault(fqdn.lower().rstrip("."), set()).add(
                (name.lower().rstrip("."), qtype.upper()))

    def remove_zone(self, fqdn: str) -> None:
        with self._lock:
            self._zones.pop(fqdn.lower().rstrip("."), None)

    def authoritative_verdict(self, lname: str, qtype: str) -> tuple[int, bool] | None:
        """``(rcode, aa)`` if ``lname`` is inside a zone we serve, else None."""
        with self._lock:
            for zone, records in self._zones.items():
                if lname == zone or lname.endswith("." + zone):
                    return (0, True) if (lname, qtype) in records else (3, True)
        return None

    def record(self, name: str, qtype: str, source: str, edns: list | None = None) -> None:
        with self._lock:
            self.total += 1
            self.by_name[name.lower()] += 1
            self.by_type[qtype] += 1
            self.by_source[source] += 1
            for code, value in edns or []:
                self.by_edns[(code, value.hex())] += 1


class MockProvider(InfrastructureProvider):
    kind = "mock"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.server: MockDNSServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self.server:
            return
        m = self.cfg.infrastructure.mock
        self.server = MockDNSServer("127.0.0.1", 0, m.nxdomain_domains, m.latency_ms)
        self._thread = threading.Thread(target=self.server.serve_forever, name="mock-dns", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    def dns_endpoint(self) -> Endpoint:
        if not self.server:
            self.start()
        assert self.server is not None
        return Endpoint("127.0.0.1", self.server.server_address[1])

    def dhcp_endpoint(self) -> Endpoint | None:
        return None  # DHCP uses MockDHCPProvider (in-memory)

    def emulate_zones(self, specs) -> None:
        """Rehearsal only: make the mock DNS authoritative for the configured zones/records.

        There is no real server behind the mock, so this mirrors the config, not the tenant."""
        self.dns_endpoint()  # ensure started
        assert self.server is not None
        for spec in specs:
            self.server.add_zone(spec.fqdn, {(spec.absolute(r), r.type) for r in spec.records})

    def capabilities(self) -> Capabilities:
        return Capabilities(local_infrastructure=True,
                            notes=["Mock only: no real portal visibility. For dev/CI/rehearsal."])

    def deployment_notes(self) -> str:
        return ("Mock provider: local UDP DNS responder + in-memory DHCP. Nothing reaches the "
                "Infoblox portal; use it to rehearse the flow and for CI.")

    def _specific_checks(self) -> list[CheckResult]:
        return [CheckResult("mock.dns", "ok", "local responder started")]
