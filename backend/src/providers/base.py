"""Infrastructure provider interface.

The demo framework must not depend on one deployment model. A provider answers:
  * where is the DNS (and DHCP) service the generators should target?
  * what can this deployment do (DNS / DHCP / Threat Defense DNS path)?
  * is it ready (preflight)?
  * what deployment-specific prerequisites should the presenter know about?

Providers do NOT provision infrastructure. Provisioning NIOS-X as a Service, OVA hosts or bare
metal is done in the Infoblox portal / lab and is documented in docs/deployment-options.md.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from demo_core.config import Config
from generators import dnswire


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int


@dataclass
class CheckResult:
    name: str
    status: str  # ok | warn | fail
    detail: str = ""


@dataclass
class Capabilities:
    dns: bool = True
    dhcp: bool = True
    threat_defense_dns_path: bool = True  # queries reach a resolver with a TD policy
    local_infrastructure: bool = False  # on-prem style behaviour (local resolver/DHCP)
    physical: bool = False
    notes: list[str] = field(default_factory=list)


class InfrastructureProvider(ABC):
    kind = "abstract"

    def __init__(self, cfg: Config):
        self.cfg = cfg

    # lifecycle (no-ops except for the mock)
    def start(self) -> None:  # pragma: no cover - trivial
        pass

    def stop(self) -> None:  # pragma: no cover - trivial
        pass

    def dns_endpoint(self) -> Endpoint:
        return Endpoint(self.cfg.dns.server or "", self.cfg.dns.port)

    def dhcp_endpoint(self) -> Endpoint | None:
        if self.cfg.dhcp.server:
            return Endpoint(self.cfg.dhcp.server, self.cfg.dhcp.port)
        return None

    @abstractmethod
    def capabilities(self) -> Capabilities: ...

    @abstractmethod
    def deployment_notes(self) -> str: ...

    def preflight(self, probe_network: bool = True) -> list[CheckResult]:
        """Provider-specific checks plus a common DNS reachability probe."""
        checks = list(self._specific_checks())
        ep = self.dns_endpoint()
        if not ep.host:
            checks.append(CheckResult("dns.server", "fail", "no DNS server configured"))
        elif probe_network:
            probe = self.cfg.dns.normal_domains[0] if self.cfg.dns.normal_domains else "www.example.com"
            res = dnswire.resolve(ep.host, ep.port, probe, "A", timeout=self.cfg.dns.timeout)
            if res.ok:
                checks.append(CheckResult("dns.reachable", "ok",
                                          f"{ep.host}:{ep.port} answered {res.rcode_name} "
                                          f"in {res.latency_ms:.0f} ms"))
            else:
                checks.append(CheckResult("dns.reachable", "fail",
                                          f"{ep.host}:{ep.port} did not answer ({res.error})"))
        td_enabled = [s for s in self.cfg.threat_defense.enabled_scenarios if s != "normal-dns"]
        if td_enabled and not self.capabilities().threat_defense_dns_path:
            checks.append(CheckResult("threat-defense.path", "warn",
                                      "this deployment does not expose a Threat Defense DNS path"))
        return checks

    def _specific_checks(self) -> list[CheckResult]:
        return []


@dataclass
class Recommendation:
    type: str
    reason: str
    order: list[str]


def recommend_infrastructure(needs_local_dns_dhcp: bool = False, needs_physical: bool = False,
                             xaas_supports_required: bool = True) -> Recommendation:
    """Preferred demo deployment order: XaaS, then OVA, then bare metal."""
    order = ["xaas", "ova", "baremetal"]
    if needs_physical:
        return Recommendation(
            "baremetal",
            "Physical infrastructure is part of what is being demonstrated; only bare metal covers that.",
            ["baremetal", "ova", "xaas"])
    if needs_local_dns_dhcp:
        return Recommendation(
            "ova",
            "The demo needs local DNS/DHCP infrastructure or on-prem-style behaviour; use a NIOS-X "
            "OVA as the fallback to XaaS.", ["ova", "xaas", "baremetal"])
    if not xaas_supports_required:
        return Recommendation(
            "ova", "The required DNS/DHCP capabilities are not supported on XaaS for this demo; "
            "fall back to OVA.", ["ova", "baremetal", "xaas"])
    return Recommendation(
        "xaas", "Managed service gives a stable, reusable demo tenant with no hardware to maintain "
        "(preferred default when the needed DNS/DHCP capabilities are supported).", order)
