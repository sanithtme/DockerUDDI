"""XaaS, OVA and bare-metal infrastructure providers.

Only facts found in internal documentation are encoded here (AU Realm CSP Tenant Test Plan,
IQ DNS Traffic Generation Setup). Anything else is left to config or the presenter.
"""
from __future__ import annotations

from .base import Capabilities, CheckResult, InfrastructureProvider


class XaaSProvider(InfrastructureProvider):
    """NIOS-X as a Service (managed). Preferred default for a reusable demo tenant."""

    kind = "xaas"

    def capabilities(self) -> Capabilities:
        caps = {c.lower() for c in self.cfg.infrastructure.xaas.capabilities}
        return Capabilities(
            dns="dns" in caps, dhcp="dhcp" in caps, threat_defense_dns_path="dfp" in caps,
            local_infrastructure=False, physical=False,
            notes=["Capabilities come from infrastructure.xaas.capabilities (what you enabled on "
                   "the universal service); this tool does not query the portal for them."])

    def _specific_checks(self) -> list[CheckResult]:
        x = self.cfg.infrastructure.xaas
        checks = []
        caps = {c.lower() for c in x.capabilities}
        for needed, why in (("dns", "DNS generation"), ("dhcp", "DHCP lease activity"),
                            ("dfp", "Threat Defense scenarios (DNS Forwarding Proxy)")):
            checks.append(CheckResult(f"xaas.capability.{needed}",
                                      "ok" if needed in caps else "warn",
                                      f"enabled for {why}" if needed in caps
                                      else f"'{needed}' not listed; needed for {why}"))
        if x.cloud_service_ip and self.cfg.dns.server and x.cloud_service_ip != self.cfg.dns.server:
            checks.append(CheckResult("xaas.cloud_service_ip", "warn",
                                      f"dns.server {self.cfg.dns.server} differs from the configured "
                                      f"Cloud Service IP {x.cloud_service_ip}"))
        return checks

    def deployment_notes(self) -> str:
        return (
            "XaaS (NIOS-X as a Service) - recommended default.\n"
            "  * Create a universal service with DNS, DHCP and DFP capabilities and a location; the "
            "service must reach Ready and be assigned a Cloud Service IP.\n"
            "  * Clients reach the service through the IPsec tunnel (VyOS static/dynamic routing or "
            "cloud VPN) - the generator host must have a route through that tunnel.\n"
            "  * Set dns.server to the service's DNS address and dhcp.server to its DHCP address.\n"
            "  * DHCP via dras goes through the tunnel; lab egress to the Infoblox portal endpoints "
            "(TCP 443) must be open per your realm's documentation.")


class _HostBased(InfrastructureProvider):
    label = ""

    def _services(self) -> list[str]:  # pragma: no cover - overridden
        return []

    def capabilities(self) -> Capabilities:
        svc = {s.lower() for s in self._services()}
        return Capabilities(dns="dns" in svc, dhcp="dhcp" in svc,
                            threat_defense_dns_path="dfp" in svc, local_infrastructure=True,
                            physical=self.kind == "baremetal")

    def _specific_checks(self) -> list[CheckResult]:
        svc = {s.lower() for s in self._services()}
        return [CheckResult(f"{self.kind}.service.{s}", "ok" if s in svc else "warn",
                            "listed in config" if s in svc else "not listed in config")
                for s in ("dns", "dhcp", "dfp")]


class OVAProvider(_HostBased):
    """NIOS-X virtual appliance (OVA) hosts - fallback when local infrastructure is needed."""

    kind = "ova"

    def _services(self) -> list[str]:
        return self.cfg.infrastructure.ova.services

    def deployment_notes(self) -> str:
        return (
            "OVA (NIOS-X virtual appliance) - fallback to XaaS.\n"
            "  * Use when the demo needs local DNS/DHCP infrastructure or on-prem-style behaviour.\n"
            "  * Deploy the NIOS-X OVA, join it to the portal with a join token, enable DNS/DHCP/DFP.\n"
            "  * Enable DNSSEC validation in the views used for testing if SERVFAIL scenarios are "
            "wanted (documented requirement of the internal IQ DNS traffic scripts).\n"
            "  * The generator host needs L3 reachability to the host; for per-asset attribution use "
            "dns.source_mode: bind with lab IP aliases.")


class BareMetalProvider(_HostBased):
    """Physical NIOS-X appliance - only when physical infrastructure is part of the demo."""

    kind = "baremetal"

    def _services(self) -> list[str]:
        return self.cfg.infrastructure.baremetal.services

    def deployment_notes(self) -> str:
        return (
            "Bare metal - use only when physical infrastructure is part of the demonstration.\n"
            "  * Same configuration surface as OVA, but needs rack/network/power logistics, so it "
            "is the least reusable option.\n"
            "  * Prefer XaaS, or OVA when local infrastructure is required, for everything else.")
