"""DNS traffic generator.

Generates A / AAAA / PTR / TXT queries per discovered asset against the configured resolver.

Source-address attribution (important for the demo story)
---------------------------------------------------------
Infoblox attributes DNS activity to the *source IP of the query*. This tool never spoofs
packets. Two honest modes exist:

* ``direct`` (default): queries leave from the generator host. Portal activity is attributed
  to the generator's IP; the asset context is carried in the demo report only.
* ``bind``: the socket binds to the asset's IP before sending. This only works when the
  generator host actually owns that address (e.g. lab IP aliases / a routed test subnet).
  Per-asset attribution in the portal then matches the discovered assets.
"""
from __future__ import annotations

import ipaddress
import logging
import random
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from typing import Any, Callable

from demo_core.config import Config
from demo_core.errors import ConfigError, SafetyError
from demo_core.models import Asset, utcnow_iso
from demo_core.ratelimit import Pacer, VirtualClock
from demo_core.safety import check_asset_count, check_dns_target, clamp_duration

from . import dnswire
from .domains import DomainSelector, StaticDomainSelector, AssetMappedDomainSelector, load_domain_file, parse_domain_entries

log = logging.getLogger(__name__)

Resolver = Callable[[str, str, "Asset", "DNSRunSettings"], dnswire.QueryResult]


@dataclass
class DNSRunSettings:
    server: str
    port: int = 53
    query_types: list[str] = field(default_factory=lambda: ["A", "AAAA", "PTR", "TXT"])
    qtype_weights: dict[str, float] = field(default_factory=dict)
    rate_per_asset: float = 1.0
    duration: float = 30.0
    concurrency: int = 10
    timeout: float = 2.0
    source_mode: str = "direct"
    bind_fallback: str = "direct"
    seed: int | None = None
    max_total_qps: float = 200.0
    dry_run: bool = False
    edns_ip_option: int = 65523
    edns_mac_option: int = 65524
    edns_send_mac: bool = True
    edns_payload_size: int = 1232
    edns_allow_public: bool = False

    @classmethod
    def from_config(cls, cfg: Config, server: str | None = None, port: int | None = None, **over: Any
                    ) -> "DNSRunSettings":
        d = cfg.dns
        base = dict(
            server=server or d.server or "", port=port or d.port, query_types=list(d.query_types),
            qtype_weights=dict(d.qtype_weights), rate_per_asset=d.rate_per_asset,
            duration=d.duration, concurrency=d.concurrency, timeout=d.timeout,
            source_mode=d.source_mode, bind_fallback=d.bind_fallback, seed=d.seed,
            max_total_qps=cfg.safety.max_total_qps, edns_ip_option=d.edns.ip_option,
            edns_mac_option=d.edns.mac_option, edns_send_mac=d.edns.send_mac,
            edns_payload_size=d.edns.payload_size, edns_allow_public=d.edns.allow_public_target,
        )
        base.update({k: v for k, v in over.items() if v is not None})
        return cls(**base)


@dataclass
class RunSummary:
    kind: str  # "dns" | "threat-defense"
    label: str  # profile or scenario name
    started: str
    finished: str = ""
    assets: list[dict[str, Any]] = field(default_factory=list)
    planned_qps: float = 0.0
    achieved_qps: float = 0.0
    duration_s: float = 0.0
    total: int = 0
    answered: int = 0
    failed: int = 0
    rcodes: dict[str, int] = field(default_factory=dict)
    by_qtype: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)
    by_domain: dict[str, int] = field(default_factory=dict)
    by_asset: dict[str, int] = field(default_factory=dict)
    errors: dict[str, int] = field(default_factory=dict)
    latency_ms_p50: float = 0.0
    latency_ms_p95: float = 0.0
    dns_server: str = ""
    source_mode: str = "direct"
    dry_run: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


class _Stats:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.total = self.answered = self.failed = 0
        self.rcodes: Counter[str] = Counter()
        self.qtypes: Counter[str] = Counter()
        self.categories: Counter[str] = Counter()
        self.domains: Counter[str] = Counter()
        self.assets: Counter[str] = Counter()
        self.errors: Counter[str] = Counter()
        self.latencies: list[float] = []

    def record(self, asset_id: str, category: str, res: dnswire.QueryResult) -> None:
        with self.lock:
            self.total += 1
            self.qtypes[res.qtype] += 1
            self.categories[category] += 1
            self.domains[res.name] += 1
            self.assets[asset_id] += 1
            if res.ok:
                self.answered += 1
                self.rcodes[res.rcode_name] += 1
                if len(self.latencies) < 50000:
                    self.latencies.append(res.latency_ms)
            else:
                self.failed += 1
                self.errors[res.error or "unknown"] += 1


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(p * len(ordered)))], 2)


def expand_ip_streams(assets: list[Asset]) -> list[Asset]:
    """One entry per distinct usable IP, each a copy of its first owning asset with ``ips=[that IP]``.

    An asset with several selected addresses yields one stream per address; an address shared
    by several assets yields a single stream, so duplicates never double the load.
    """
    by_ip: dict[str, Asset] = {}
    for a in assets:
        if not a.dns_eligible:
            continue
        for addr in (a.ips or [a.ip or ""]):
            if addr and addr not in by_ip:
                v4 = ":" not in addr
                by_ip[addr] = replace(a, ip=addr, ips=[addr], ipv4=addr if v4 else None,
                                      ipv6=None if v4 else addr)
    return list(by_ip.values())


def edns_options_for(asset: Asset, s: "DNSRunSettings") -> list[dnswire.EdnsOption]:
    """Client-attribution options for one asset: source IP (and MAC when known)."""
    opts: list[dnswire.EdnsOption] = [(s.edns_ip_option, ipaddress.ip_address(asset.ip or "").packed)]
    if s.edns_send_mac and asset.mac:
        opts.append((s.edns_mac_option, bytes.fromhex(asset.mac.replace(":", ""))))
    return opts


class NetworkResolver:
    """Real resolver. Honours ``source_mode`` with a per-asset bind fallback."""

    def __init__(self, rng: random.Random):
        self._rng = rng
        self._unbindable: set[str] = set()
        self._lock = threading.Lock()

    def __call__(self, name: str, qtype: str, asset: Asset, s: DNSRunSettings) -> dnswire.QueryResult:
        source = asset.ip if s.source_mode == "bind" and asset.ip else None
        edns = (edns_options_for(asset, s) if s.source_mode == "edns" and asset.ip else None)
        if source and asset.asset_id in self._unbindable:
            if s.bind_fallback == "skip":
                return dnswire.QueryResult(name, qtype, ok=False, error="cannot bind to asset IP")
            source = None
        try:
            return dnswire.resolve(s.server, s.port, name, qtype, s.timeout, source, self._rng,
                                   edns_options=edns)
        except OSError as exc:
            with self._lock:
                first = asset.asset_id not in self._unbindable
                self._unbindable.add(asset.asset_id)
            if first:
                log.warning("cannot bind source %s for %s (%s); %s", source, asset.asset_id, exc,
                            "falling back to direct" if s.bind_fallback == "direct" else "skipping")
            if s.bind_fallback == "skip":
                return dnswire.QueryResult(name, qtype, ok=False, error="cannot bind to asset IP")
            return dnswire.resolve(s.server, s.port, name, qtype, s.timeout, None, self._rng,
                                   edns_options=edns)


class SpoofResolver:
    """Send-only Scapy resolver for an authorized lab. No EDNS/ECS and no reply is expected."""
    def __call__(self, name: str, qtype: str, asset: Asset, s: DNSRunSettings) -> dnswire.QueryResult:
        if not asset.ip or ":" in asset.ip:
            return dnswire.QueryResult(name, qtype, ok=False, error="spoof mode currently requires IPv4")
        try:
            from scapy.all import DNS, DNSQR, IP, UDP, RandShort, send
            started = time.monotonic()
            pkt = (IP(src=asset.ip, dst=s.server) / UDP(sport=RandShort(), dport=s.port) /
                   DNS(id=random.randint(1, 65535), rd=1, qd=DNSQR(qname=name, qtype=qtype)))
            send(pkt, verbose=False)
            return dnswire.QueryResult(name, qtype, ok=True, rcode=0,
                                       latency_ms=(time.monotonic()-started)*1000)
        except Exception as exc:
            return dnswire.QueryResult(name, qtype, ok=False, error=f"spoof send failed: {exc}")


class DryRunResolver:
    def __call__(self, name: str, qtype: str, asset: Asset, s: DNSRunSettings) -> dnswire.QueryResult:
        return dnswire.QueryResult(name, qtype, ok=True, rcode=0, latency_ms=0.0)


class DNSTrafficGenerator:
    def __init__(self, cfg: Config, resolver: Resolver | None = None):
        self.cfg = cfg
        self._resolver = resolver

    # ------------------------------------------------------------------ profiles
    def selector_for_profile(self, profile: str) -> DomainSelector:
        if profile == "normal":
            if self.cfg.dns.domains_file:
                entries = load_domain_file(self.cfg.dns.domains_file)
            else:
                entries = parse_domain_entries(self.cfg.dns.normal_domains, "dns.normal_domains")
            entries = [type(e)(e.name, "normal") for e in entries]
            return AssetMappedDomainSelector(entries)
        if profile == "security-demo":
            from .threat_defense import load_threat_domains

            return StaticDomainSelector(load_threat_domains(self.cfg))
        raise ConfigError(f"unknown DNS profile {profile!r} (use 'normal' or 'security-demo')")

    # ------------------------------------------------------------------ guards
    def _guard_target(self, settings: "DNSRunSettings") -> None:
        check_dns_target(settings.server, self.cfg.safety)
        if settings.source_mode == "edns" and not settings.edns_allow_public and \
                not ipaddress.ip_address(settings.server).is_private:
            raise SafetyError(
                "dns.source_mode 'edns' attaches client IP/MAC metadata, which is only meaningful "
                "when sent to your own NIOS / NIOS-X forwarder with Add/Copy client IP enabled. "
                f"{settings.server} is a public address; set dns.edns.allow_public_target: true "
                "only if you know that endpoint honours it.")

    # ------------------------------------------------------------------ single query
    def send_one(self, asset: Asset, name: str, qtype: str, settings: "DNSRunSettings"
                 ) -> dnswire.QueryResult:
        """Send exactly one query as ``asset`` (same guards and identity handling as ``run``)."""
        if qtype not in dnswire.QTYPES:
            raise ConfigError(f"unsupported query type {qtype!r}; use one of {sorted(dnswire.QTYPES)}")
        if not asset.dns_eligible:
            raise ConfigError(f"asset {asset.asset_id} has no validated IP address")
        if not settings.dry_run:
            self._guard_target(settings)
        resolver = self._resolver or (DryRunResolver() if settings.dry_run else
                                      SpoofResolver() if settings.source_mode == "spoof" else
                                      NetworkResolver(random.Random(settings.seed)))
        return resolver(name, qtype, asset, settings)

    # ------------------------------------------------------------------ run
    def run(
        self,
        assets: list[Asset],
        selector: DomainSelector,
        settings: DNSRunSettings,
        label: str = "normal",
        kind: str = "dns",
        extra_notes: list[str] | None = None,
    ) -> RunSummary:
        eligible = [a for a in assets if a.dns_eligible]
        targets = expand_ip_streams(eligible)
        skipped = len(assets) - len(eligible)

        summary = RunSummary(kind=kind, label=label, started=utcnow_iso(), dns_server=settings.server,
                             source_mode=settings.source_mode, dry_run=settings.dry_run,
                             notes=list(extra_notes or []))
        if skipped:
            summary.notes.append(f"{skipped} asset(s) skipped: no validated IP address")
        total_addrs = sum(len(a.ips or [a.ip or ""]) for a in eligible)
        if total_addrs > len(targets):
            summary.notes.append(f"{total_addrs - len(targets)} duplicate address(es) across assets; "
                                 "generating one stream per distinct IP")
        if not targets:
            summary.notes.append("no DNS-eligible assets; nothing generated")
            summary.finished = utcnow_iso()
            return summary

        check_asset_count(len(targets), self.cfg.safety)
        if not settings.dry_run:
            self._guard_target(settings)
        duration, d_clamped = clamp_duration(settings.duration, self.cfg.safety)
        wanted = settings.rate_per_asset * len(targets)
        total_qps = min(wanted, settings.max_total_qps)
        q_clamped = wanted > settings.max_total_qps
        if d_clamped:
            summary.notes.append(f"duration clamped to safety.max_duration={duration:.0f}s")
        if q_clamped:
            summary.notes.append(f"total rate clamped from {wanted:.1f} to {total_qps:.1f} qps "
                                 "(safety.max_total_qps)")
        summary.planned_qps = round(total_qps, 2)
        summary.assets = [{"asset_id": a.asset_id, "hostname": a.hostname, "ip": a.ip, "mac": a.mac}
                          for a in targets]
        if settings.source_mode == "edns":
            summary.notes.append(
                f"source_mode=edns: each query carries the asset IP (option {settings.edns_ip_option})"
                + (f" and MAC (option {settings.edns_mac_option})" if settings.edns_send_mac else "")
                + ". Attribution works only if a NIOS/NIOS-X forwarder with Add/Copy client IP "
                  "enabled passes them to Threat Defense; confirm with a packet capture.")
        if settings.source_mode == "direct":
            summary.notes.append("source_mode=direct: portal activity is attributed to the generator host IP, not the asset IPs")
        if settings.source_mode == "spoof":
            summary.notes.append("source_mode=spoof: Scapy puts the asset IPv4 directly in the IP header; send-only, no EDNS/ECS, authorized lab only")

        rng = random.Random(settings.seed)
        qtypes = [q for q in settings.query_types if q in dnswire.QTYPES]
        weights = [float(settings.qtype_weights.get(q, 1.0)) for q in qtypes]

        virtual = VirtualClock() if settings.dry_run else None
        clock = virtual if virtual else time.monotonic
        sleep = virtual.sleep if virtual else time.sleep
        resolver = self._resolver or (DryRunResolver() if settings.dry_run else
                                      SpoofResolver() if settings.source_mode == "spoof" else NetworkResolver(rng))
        pacer = Pacer(total_qps, clock=clock, sleep=sleep)

        stats = _Stats()
        inflight = threading.BoundedSemaphore(max(2, settings.concurrency * 2))

        def work(asset: Asset, name: str, qtype: str, category: str) -> None:
            try:
                res = resolver(name, qtype, asset, settings)
            except Exception as exc:  # a resolver bug must not kill the run
                res = dnswire.QueryResult(name, qtype, ok=False, error=f"{type(exc).__name__}: {exc}")
            stats.record(asset.asset_id, category, res)
            inflight.release()

        start = clock()
        end = start + duration
        idx = 0
        with ThreadPoolExecutor(max_workers=settings.concurrency, thread_name_prefix="dns") as pool:
            while clock() < end:
                asset = targets[idx % len(targets)]
                idx += 1
                qtype = rng.choices(qtypes, weights=weights, k=1)[0]
                if qtype == "PTR":
                    name, category = dnswire.reverse_name(asset.ip or ""), "ptr"
                else:
                    name, category = selector.pick(rng, asset)
                pacer.acquire()
                inflight.acquire()
                pool.submit(work, asset, name, qtype, category)
        elapsed = max(clock() - start, 1e-9)

        summary.finished = utcnow_iso()
        summary.duration_s = round(elapsed, 2)
        summary.total, summary.answered, summary.failed = stats.total, stats.answered, stats.failed
        summary.achieved_qps = round(stats.total / elapsed, 2)
        summary.rcodes = dict(stats.rcodes)
        summary.by_qtype = dict(stats.qtypes)
        summary.by_category = dict(stats.categories)
        summary.by_domain = dict(stats.domains)
        summary.by_asset = dict(stats.assets)
        summary.errors = dict(stats.errors)
        summary.latency_ms_p50 = _pct(stats.latencies, 0.50)
        summary.latency_ms_p95 = _pct(stats.latencies, 0.95)
        return summary
