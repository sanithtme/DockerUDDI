"""Threat Defense demo scenarios, generated purely as DNS queries.

Safety model
------------
* No malware, exploits, or non-DNS traffic. Every scenario is a DNS query load.
* No domains are hard-coded. Threat domains come from ``threat_defense.domains`` and must
  be approved for the demo tenant by whoever owns the config.
* A scenario only runs if it is listed in ``threat_defense.enabled_scenarios``.

The Infoblox security service observes these queries when they reach a resolver that has a
Threat Defense policy attached (for example a NIOS-X / NIOS-X as a Service DFP). Whether a
given domain is blocked, logged or ignored is decided by your tenant policy, not by this tool.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from demo_core.config import Config
from demo_core.errors import ConfigError, SafetyError
from demo_core.models import Asset

from .dns import DNSRunSettings, DNSTrafficGenerator, RunSummary
from .tide import load_snapshot
from .domains import (DomainEntry, DomainSelector, StaticDomainSelector, WeightedSelector,
                      parse_domain_entries)


@dataclass(frozen=True)
class ScenarioDef:
    name: str
    description: str
    threat_ratio: float  # share of queries to configured threat domains (0..1)
    categories: tuple[str, ...] | None = None  # None = every configured category
    rate_multiplier: float = 1.0
    duration: float | None = None  # None = dns.duration
    query_types: tuple[str, ...] | None = None


DEFAULT_SCENARIOS: dict[str, ScenarioDef] = {
    "normal-dns": ScenarioDef(
        "normal-dns", "Baseline realistic DNS only; no threat domains.", threat_ratio=0.0),
    "blocked-domain": ScenarioDef(
        "blocked-domain", "Queries for domains your policy is expected to block.",
        threat_ratio=1.0, categories=("blocked", "default"), query_types=("A", "AAAA")),
    "suspicious-domain": ScenarioDef(
        "suspicious-domain", "Queries for domains your policy flags as suspicious.",
        threat_ratio=1.0, categories=("suspicious", "default"), query_types=("A", "AAAA", "TXT")),
    "high-volume-dns": ScenarioDef(
        "high-volume-dns", "Elevated query rate across normal and configured domains.",
        threat_ratio=0.3, rate_multiplier=5.0),
    "mixed-workload": ScenarioDef(
        "mixed-workload", "Mostly normal DNS with a minority of configured threat domains.",
        threat_ratio=0.2),
}

_OVERRIDABLE = {"description", "threat_ratio", "categories", "rate_multiplier", "duration",
                "query_types"}


def load_threat_domains(cfg: Config, allow_placeholder: bool = False) -> list[DomainEntry]:
    """Configured domains, plus the stored TIDE snapshot when ``threat_defense.tide.enabled``."""
    entries = parse_domain_entries(cfg.threat_defense.domains, "threat_defense.domains",
                                   allow_placeholder=allow_placeholder)
    if cfg.threat_defense.tide.enabled:
        names = {e.name for e in entries}  # explicitly configured entries win
        entries += [e for e in load_snapshot(cfg) if e.name not in names]
    if not entries:
        raise ConfigError(
            "no threat domains. This tool ships with NO threat domains by design. Either add domains "
            "approved for your Threat Defense demo tenant:\n"
            "  threat_defense:\n    domains:\n"
            "      - {name: <approved-domain>, category: blocked, expected_action: block}\n"
            "or pull active ones from the portal's TIDE: set threat_defense.tide.enabled: true, "
            "then run 'demo td fetch'."
        )
    return entries


class ThreatDefenseGenerator:
    def __init__(self, cfg: Config, dns_generator: DNSTrafficGenerator | None = None,
                 allow_placeholder: bool = False):
        self.cfg = cfg
        self.dns = dns_generator or DNSTrafficGenerator(cfg)
        self.allow_placeholder = allow_placeholder

    # ------------------------------------------------------------------ scenarios
    def scenarios(self) -> dict[str, ScenarioDef]:
        out = dict(DEFAULT_SCENARIOS)
        for name, override in self.cfg.threat_defense.scenarios.items():
            bad = set(override) - _OVERRIDABLE
            if bad:
                raise ConfigError(f"threat_defense.scenarios.{name}: unknown key(s) {sorted(bad)}")
            base = out.get(name) or ScenarioDef(name, "custom scenario", threat_ratio=0.5)
            changes: dict[str, Any] = dict(override)
            for key in ("categories", "query_types"):
                if key in changes and changes[key] is not None:
                    changes[key] = tuple(changes[key])
            ratio = changes.get("threat_ratio", base.threat_ratio)
            if not 0.0 <= float(ratio) <= 1.0:
                raise ConfigError(f"threat_defense.scenarios.{name}.threat_ratio must be 0..1")
            out[name] = replace(base, **changes)
        return out

    def resolve_scenario(self, name: str) -> ScenarioDef:
        scenarios = self.scenarios()
        if name not in scenarios:
            raise ConfigError(f"unknown scenario {name!r}. Available: {', '.join(sorted(scenarios))}")
        if name not in self.cfg.threat_defense.enabled_scenarios:
            raise SafetyError(
                f"scenario {name!r} is not enabled for this demo tenant. Add it to "
                "threat_defense.enabled_scenarios in the config to confirm it is approved."
            )
        return scenarios[name]

    def build_selector(self, scn: ScenarioDef) -> DomainSelector:
        normal = StaticDomainSelector([
            DomainEntry(e.name, "normal")
            for e in parse_domain_entries(self.cfg.dns.normal_domains, "dns.normal_domains")
        ])
        if scn.threat_ratio <= 0:
            return normal
        entries = load_threat_domains(self.cfg, self.allow_placeholder)
        if scn.categories is not None:
            wanted = set(scn.categories)
            entries = [e for e in entries if e.category in wanted]
            if not entries:
                have = sorted({e.category for e in load_threat_domains(self.cfg, self.allow_placeholder)})
                raise ConfigError(
                    f"scenario {scn.name!r} needs domains with category {sorted(wanted)} but "
                    f"threat_defense.domains only has categories {have}"
                )
        threat = StaticDomainSelector(entries)
        if scn.threat_ratio >= 1:
            return threat
        return WeightedSelector([(1 - scn.threat_ratio, normal), (scn.threat_ratio, threat)])

    # ------------------------------------------------------------------ run
    def run(self, scenario: str, assets: list[Asset], settings: DNSRunSettings) -> RunSummary:
        scn = self.resolve_scenario(scenario)
        selector = self.build_selector(scn)
        tuned = replace(
            settings,
            rate_per_asset=settings.rate_per_asset * scn.rate_multiplier,
            duration=scn.duration if scn.duration is not None else settings.duration,
            query_types=list(scn.query_types) if scn.query_types else settings.query_types,
        )
        notes = [f"scenario: {scn.description}"]
        if scn.rate_multiplier != 1.0:
            notes.append(f"rate multiplier x{scn.rate_multiplier:g} applied (capped by safety.max_total_qps)")
        summary = self.dns.run(assets, selector, tuned, label=scenario, kind="threat-defense",
                               extra_notes=notes)
        expected = {e.name: e.expected_action for e in selector.describe() if e.expected_action}
        if expected:
            summary.notes.append("expected actions (from config, not verified by this tool): "
                                 + ", ".join(f"{d}={a}" for d, a in sorted(expected.items())))
        return summary
