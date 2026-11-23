"""Typed configuration loaded from YAML.

* Unknown keys are rejected so typos fail loudly instead of being silently ignored.
* ``${VAR}`` / ``${VAR:-default}`` are interpolated from the environment.
* Secrets are never stored in the file: auth uses ``token_env`` (an env var *name*).
"""
from __future__ import annotations

import dataclasses
import ipaddress
import os
import re
import typing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .errors import ConfigError

VALID_QTYPES = ("A", "AAAA", "PTR", "TXT", "CNAME", "MX", "SRV", "NS", "SOA", "CAA")
INFRA_TYPES = ("xaas", "ova", "baremetal", "mock")


# --------------------------------------------------------------------------- asset source
@dataclass
class RetryConfig:
    max_attempts: int = 5
    backoff_base: float = 0.5
    backoff_max: float = 30.0
    timeout: float = 30.0
    retry_statuses: list[int] = field(default_factory=lambda: [429, 500, 502, 503, 504])


@dataclass
class IPSelectionConfig:
    """Which of an asset's addresses may be used for generated traffic."""

    private_only: bool = True  # skip public/global addresses (cloud assets often carry both)
    include_cidrs: list[str] = field(default_factory=list)  # if set, ONLY these ranges
    exclude_cidrs: list[str] = field(default_factory=list)


@dataclass
class AssetSourceConfig:
    """Infoblox Universal Asset Insights public API (POST <base_url>/api/v1/assets/search).

    Contract source: internal "Asset Inventory Public API" design doc + the Service Graph
    Connector guides (API key sent as ``Authorization: token <key>``). Confirm against your
    tenant with ``demo discover --probe``.
    """

    base_url: str = ""  # your tenant URL, e.g. https://<your-tenant>.<domain>
    search_path: str = "/api/v1/assets/search"
    api_key_env: str = "INFOBLOX_API_KEY"  # NAME of the env var holding the API key
    auth_scheme: str = "token"  # "token" (API key) or "Bearer" (JWT)
    client_id: str | None = "asset-insights-ddi-demo"  # sent as X-Client-Id
    filter: str | None = None  # optional FilterEL expression, e.g. vendor = "Dell"
    category: str | None = None  # optional: devices | network | services | unverified
    fields: list[str] | None = None  # None = all normalised fields
    providers: list[str] = field(default_factory=list)  # keep only assets seen by ANY of these
                                                       # (case-insensitive, client-side), e.g. [Tenable]
    sync_mode: str | None = "FULL"  # FULL | None (omit)
    page_size: int = 100  # API max is 1000
    max_pages: int = 1000
    max_assets: int = 500  # stop early; 0 = no limit (fetch the whole inventory)
    retry: RetryConfig = field(default_factory=RetryConfig)
    verify_tls: bool = True
    default_source: str = "third-party"
    dedupe_by: list[str] = field(default_factory=lambda: ["asset_id"])
    ip_selection: IPSelectionConfig = field(default_factory=IPSelectionConfig)


@dataclass
class StoreConfig:
    type: str = "json"  # json | sqlite
    path: str = "state/assets.json"


# --------------------------------------------------------------------------- infrastructure
@dataclass
class XaaSConfig:
    service_name: str | None = None
    location: str | None = None
    capabilities: list[str] = field(default_factory=lambda: ["dns", "dhcp", "dfp"])
    cloud_service_ip: str | None = None


@dataclass
class OVAConfig:
    host_name: str | None = None
    services: list[str] = field(default_factory=lambda: ["dns", "dhcp", "dfp"])


@dataclass
class BareMetalConfig:
    host_name: str | None = None
    services: list[str] = field(default_factory=lambda: ["dns", "dhcp", "dfp"])


@dataclass
class MockInfraConfig:
    nxdomain_domains: list[str] = field(default_factory=list)
    latency_ms: float = 0.0


@dataclass
class InfrastructureConfig:
    type: str = "xaas"
    xaas: XaaSConfig = field(default_factory=XaaSConfig)
    ova: OVAConfig = field(default_factory=OVAConfig)
    baremetal: BareMetalConfig = field(default_factory=BareMetalConfig)
    mock: MockInfraConfig = field(default_factory=MockInfraConfig)


# --------------------------------------------------------------------------- DNS / DHCP / TD
@dataclass
class EdnsConfig:
    """Client-attribution EDNS0 options for ``dns.source_mode: edns`` (no BloxOne endpoint).

    Option codes are from the internal "EDNS Options" engineering doc and the NIOS/DFP KB:
    0xFFF3 (65523) = client source IP (4 or 16 bytes), 0xFFF4 (65524) = client MAC (6 bytes).
    NIOS or NIOS-X with "Add/Copy client IP, MAC addresses, and DNS View name to outgoing
    recursive queries" forwards options it receives to Threat Defense.
    """

    ip_option: int = 65523
    mac_option: int = 65524
    send_mac: bool = True
    payload_size: int = 1232
    allow_public_target: bool = False  # refuse to send forged attribution to a public resolver


@dataclass
class DNSConfig:
    server: str | None = None
    port: int = 53
    query_types: list[str] = field(default_factory=lambda: ["A", "AAAA", "PTR", "TXT"])
    qtype_weights: dict[str, float] = field(
        default_factory=lambda: {"A": 60, "AAAA": 25, "PTR": 10, "TXT": 5}
    )
    rate_per_asset: float = 1.0  # queries / second / asset
    duration: float = 30.0  # seconds
    concurrency: int = 10
    timeout: float = 2.0
    source_mode: str = "direct"  # direct | bind | edns | spoof (authorized lab only)
    domains_file: str | None = None  # optional JSON: {"domains": [...]} or a JSON list
    spoof_interface: str | None = None  # optional Scapy interface; default routing decision
    edns: EdnsConfig = field(default_factory=EdnsConfig)
    bind_fallback: str = "direct"  # direct | skip
    seed: int | None = None
    normal_domains: list[str] = field(
        default_factory=lambda: [
            "www.example.com",
            "api.example.com",
            "updates.example.com",
            "cdn.example.com",
        ]
    )


@dataclass
class DraConfig:
    binary: str = "dras"
    renew_binary: str = "dras"  # tool notes say drasraw for -I/-f; Exercise 2 uses dras
    use_sudo: bool = True
    relay_agent_ip: str | None = None
    relay_map: list[dict[str, str]] = field(default_factory=list)  # [{cidr:, relay:}]
    interface: str | None = None  # -I (drasraw only)
    timeout: float = 30.0
    lease_dir: str = "state/dhcp"
    send_hostname: bool = True
    verbose: bool = True
    extra_args: list[str] = field(default_factory=list)


@dataclass
class NativeDhcpConfig:
    """Built-in DHCP client (used when `dras` is not installed). Acts like a relay agent.

    The server sends replies to giaddr on UDP port 67, so ``listen_port`` is 67 and binding it needs
    root. Relay settings are shared with dhcp.dra (relay_agent_ip, relay_map, send_hostname,
    lease_dir, timeout is separate below).
    """

    listen_port: int = 67
    timeout: float = 4.0  # seconds to wait for each reply
    retries: int = 2  # sends per message


@dataclass
class DHCPConfig:
    provider: str = "auto"  # auto (mock for mock infra, else dras if installed, else native) | dra | native | mock
    server: str | None = None
    port: int = 67
    delay_between: float = 0.5
    dra: DraConfig = field(default_factory=DraConfig)
    native: NativeDhcpConfig = field(default_factory=NativeDhcpConfig)


@dataclass
class TideConfig:
    """Pull *active* threat domains from the portal's TIDE (Threat Intelligence Data Exchange).

    Endpoint/params from internal TIDE API docs: ``GET <base>/tide/api/data/threats/state?type=host
    &rlimit=N&data_format=json`` with ``Authorization: Token <key>``. Needs the TIDE Active
    Indicators entitlement (Advanced tier). Off by default; fetch with ``demo td fetch``.
    """

    enabled: bool = False  # include the stored TIDE snapshot in Threat Defense scenarios
    base_url: str = ""  # default: asset_source.base_url (same portal)
    api_key_env: str = "INFOBLOX_API_KEY"
    path: str = "/tide/api/data/threats/state"
    limit: int = 100  # rlimit, 1..1000
    classes: list[str] = field(default_factory=list)  # e.g. [APT, Bot]
    properties: list[str] = field(default_factory=list)  # e.g. [Phishing_Generic]
    profile: str | None = None  # e.g. IID
    category: str = "blocked"  # which scenario set these domains join
    verify_tls: bool = True
    timeout: float = 30.0
    max_attempts: int = 4


@dataclass
class ThreatDefenseConfig:
    tide: TideConfig = field(default_factory=TideConfig)
    # Each entry: "name" or {name, category, expected_action, note}. NEVER hard-coded.
    domains: list[Any] = field(default_factory=list)
    enabled_scenarios: list[str] = field(default_factory=list)
    scenarios: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass
class ZonesConfig:
    """Test zones/records created in Universal DDI so the DNS server answers authoritatively.

    API contract (internal KBs/QA docs): ``<base>/api/ddi/v1/dns/auth_zone`` and ``.../dns/record``,
    ``Authorization: Token <key>``, tag filters ``tags.ManagedBy=="..."``. The key's user needs a
    DNS role (DDI DNS Operator or Manager). Nothing here touches objects it did not create.
    """

    enabled: bool = False  # run-demo creates/verifies the zones and sends internal-domain queries
    base_url: str = ""  # default: asset_source.base_url
    api_key_env: str = "INFOBLOX_API_KEY"
    view: str | None = None  # DNS view NAME; None = the tenant's default view
    dns_host: str | None = None  # optional override; otherwise auto-resolved from dns.server
    nsg: str | None = None  # alternative: name of a name server group (auth_nsg)
    primary_type: str | None = "cloud"  # retried without it if the API rejects it as read-only
    managed_tag: str = "asset-insights-ddi-demo"  # value of the ManagedBy tag put on everything created
    allowed_suffixes: list[str] = field(default_factory=lambda: [
        ".internal.", ".test.", ".example.", ".invalid.", ".localhost.", ".home.arpa."])
    wait_seconds: float = 90.0  # how long `verify` waits for the DNS server to start answering
    verify_tls: bool = True
    timeout: float = 30.0
    max_attempts: int = 4
    zones: list[dict[str, Any]] = field(default_factory=list)  # [{fqdn, comment, records: [...]}]
    negative_names: list[str] = field(default_factory=lambda: ["does-not-exist"])  # expect NXDOMAIN
    query_devices: int = 5  # devices used for the internal-domain queries in run-demo


@dataclass
class IpamConfig:
    """DHCP network for the lease demo: IP space + subnet + range, served by one DHCP host.

    API (internal KB 000010531, Jira UDDIST-3407/3508): POST ipam/ip_space, ipam/subnet (with
    ``dhcp_host: dhcp/host/<id>``), ipam/range (inherits the host from its subnet); lease read-back
    via GET dhcp/lease. Everything created is tagged ManagedBy=<managed_tag>.
    """

    enabled: bool = False  # run-demo creates the network before the DHCP step
    base_url: str = ""  # default: asset_source.base_url
    api_key_env: str = "INFOBLOX_API_KEY"
    ip_space: str = "asset-insights-ddi-demo"  # IP space NAME
    create_ip_space: bool = True  # false = use an existing space (REQUIRED if the host already serves one)
    dhcp_host: str | None = None  # optional override; otherwise auto-resolved from dhcp.server
    managed_tag: str = "asset-insights-ddi-demo"
    wait_seconds: float = 60.0  # DHCP config takes about a minute to reach the host
    verify_tls: bool = True
    timeout: float = 30.0
    max_attempts: int = 4
    subnets: list[dict[str, Any]] = field(default_factory=list)  # [{address, cidr, name, ranges: [{start,end,name}]}]


@dataclass
class SafetyConfig:
    allowed_dns_servers: list[str] = field(default_factory=list)
    allow_public_dns_server: bool = False
    max_total_qps: float = 200.0
    max_duration: float = 900.0
    max_assets_per_run: int = 500


@dataclass
class ReportingConfig:
    output_dir: str = "reports"
    state_dir: str = "state"
    verification_buffer_minutes: int = 5


@dataclass
class Config:
    asset_source: AssetSourceConfig = field(default_factory=AssetSourceConfig)
    store: StoreConfig = field(default_factory=StoreConfig)
    infrastructure: InfrastructureConfig = field(default_factory=InfrastructureConfig)
    dns: DNSConfig = field(default_factory=DNSConfig)
    dhcp: DHCPConfig = field(default_factory=DHCPConfig)
    threat_defense: ThreatDefenseConfig = field(default_factory=ThreatDefenseConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    zones: ZonesConfig = field(default_factory=ZonesConfig)
    ipam: IpamConfig = field(default_factory=IpamConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    log_level: str = "INFO"

    # ------------------------------------------------------------------ validation
    def validate(self) -> "Config":
        errs: list[str] = []
        if self.infrastructure.type not in INFRA_TYPES:
            errs.append(f"infrastructure.type must be one of {INFRA_TYPES}")
        if self.store.type not in ("json", "sqlite"):
            errs.append("store.type must be 'json' or 'sqlite'")
        a = self.asset_source
        if a.sync_mode not in (None, "FULL"):
            errs.append("asset_source.sync_mode must be FULL or unset")
        if a.category not in (None, "devices", "network", "services", "unverified"):
            errs.append("asset_source.category must be devices|network|services|unverified")
        if not 1 <= a.page_size <= 1000:
            errs.append("asset_source.page_size must be 1..1000")
        if a.max_assets < 0:
            errs.append("asset_source.max_assets must be >= 0 (0 = no limit)")
        z = self.zones
        if z.dns_host and z.nsg:
            errs.append("zones: set dns_host OR nsg, not both")
        if z.dns_host and not z.dns_host.startswith("dns/host/"):
            errs.append("zones.dns_host must look like 'dns/host/<id>' (the DNS host id, not the on-prem host id)")
        if z.enabled and not (z.dns_host or z.nsg or self.dns.server):
            errs.append("zones.enabled needs dns.server, zones.dns_host, or zones.nsg so a server serves the zone")
        if z.enabled and not z.zones:
            errs.append("zones.enabled is true but zones.zones is empty")
        ip = self.ipam
        if ip.dhcp_host and not ip.dhcp_host.startswith("dhcp/host/"):
            errs.append("ipam.dhcp_host must look like 'dhcp/host/<id>' (a DHCP host id, not a dns/host id)")
        if ip.enabled and not (ip.dhcp_host or self.dhcp.server):
            errs.append("ipam.enabled needs dhcp.server or ipam.dhcp_host")
        if ip.enabled and not ip.subnets:
            errs.append("ipam.enabled is true but ipam.subnets is empty")
        t = self.threat_defense.tide
        if not 1 <= t.limit <= 1000:
            errs.append("threat_defense.tide.limit must be 1..1000")
        if not t.category.strip():
            errs.append("threat_defense.tide.category must not be empty")
        for key in ("include_cidrs", "exclude_cidrs"):
            for cidr in getattr(a.ip_selection, key):
                try:
                    ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    errs.append(f"asset_source.ip_selection.{key}: {cidr!r} is not a CIDR")
        bad_q = [q for q in self.dns.query_types if q not in VALID_QTYPES]
        if bad_q or not self.dns.query_types:
            errs.append(f"dns.query_types must be a non-empty subset of {VALID_QTYPES} (got {bad_q})")
        if self.dns.source_mode not in ("direct", "bind", "edns", "spoof"):
            errs.append("dns.source_mode must be 'direct', 'bind', 'edns' or 'spoof'")
        for opt in ("ip_option", "mac_option"):
            if not 65001 <= getattr(self.dns.edns, opt) <= 65534:
                errs.append(f"dns.edns.{opt} must be in the local/experimental range 65001..65534")
        if self.dns.bind_fallback not in ("direct", "skip"):
            errs.append("dns.bind_fallback must be 'direct' or 'skip'")
        for name in ("rate_per_asset", "duration", "timeout"):
            if getattr(self.dns, name) <= 0:
                errs.append(f"dns.{name} must be > 0")
        if self.dns.concurrency < 1:
            errs.append("dns.concurrency must be >= 1")
        if self.dhcp.provider not in ("auto", "dra", "native", "mock"):
            errs.append("dhcp.provider must be auto|dra|native|mock")
        if self.dhcp.native.retries < 1 or self.dhcp.native.timeout <= 0:
            errs.append("dhcp.native: retries must be >= 1 and timeout > 0")
        if self.infrastructure.type != "mock":
            for label, val in (("dns.server", self.dns.server), ("dhcp.server", self.dhcp.server)):
                if val is None:
                    if label == "dns.server":
                        errs.append("dns.server is required unless infrastructure.type is 'mock'")
                    continue
                try:
                    ipaddress.ip_address(val)
                except ValueError:
                    errs.append(f"{label}: {val!r} is not an IP address")
        for entry in self.dhcp.dra.relay_map:
            if set(entry) != {"cidr", "relay"}:
                errs.append("dhcp.dra.relay_map entries need exactly 'cidr' and 'relay'")
                continue
            try:
                ipaddress.ip_network(entry["cidr"], strict=False)
                ipaddress.ip_address(entry["relay"])
            except ValueError as exc:
                errs.append(f"dhcp.dra.relay_map: {exc}")
        if errs:
            raise ConfigError("invalid configuration:\n  - " + "\n  - ".join(errs))
        return self


# --------------------------------------------------------------------------- loading
_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _interp(value: Any) -> Any:
    if isinstance(value, str):

        def repl(m: re.Match[str]) -> str:
            got = os.environ.get(m.group(1))
            if got is None:
                if m.group(2) is not None:
                    return m.group(2)
                raise ConfigError(f"environment variable {m.group(1)} is referenced but not set")
            return got

        return _ENV.sub(repl, value)
    if isinstance(value, list):
        return [_interp(v) for v in value]
    if isinstance(value, dict):
        return {k: _interp(v) for k, v in value.items()}
    return value


def _build(cls: type, data: Any, path: str) -> Any:
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected a mapping, got {type(data).__name__}")
    fields = {f.name: f for f in dataclasses.fields(cls)}
    unknown = sorted(set(data) - set(fields))
    if unknown:
        raise ConfigError(f"{path}: unknown key(s) {unknown}; valid keys: {sorted(fields)}")
    hints = typing.get_type_hints(cls)
    kwargs: dict[str, Any] = {}
    for name, value in data.items():
        hint = hints[name]
        kwargs[name] = _build(hint, value, f"{path}.{name}") if dataclasses.is_dataclass(hint) else value
    return cls(**kwargs)


def config_from_dict(raw: dict[str, Any]) -> Config:
    raw = dict(_interp(raw or {}))
    log_level = raw.pop("logging", {}).get("level", "INFO") if isinstance(raw.get("logging"), dict) else "INFO"
    raw.pop("logging", None)
    cfg = _build(Config, raw, "config")
    cfg.log_level = str(log_level).upper()
    return cfg.validate()


def load_config(path: str | os.PathLike[str] | None = None) -> Config:
    candidate = path or os.environ.get("DEMO_CONFIG") or "config/config.yaml"
    p = Path(candidate)
    if not p.exists():
        raise ConfigError(
            f"config file not found: {p}\n"
            "Copy config/config.example.yaml to config/config.yaml (or use "
            "--config config/config.mock.yaml for a zero-setup local run)."
        )
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{p}: invalid YAML: {exc}") from exc
    cfg = config_from_dict(raw or {})
    # File paths that belong to this config may be relative to the config file itself.
    if cfg.dns.domains_file:
        q = Path(cfg.dns.domains_file).expanduser()
        if not q.is_absolute():
            cfg.dns.domains_file = str((p.parent / q).resolve())
    return cfg
