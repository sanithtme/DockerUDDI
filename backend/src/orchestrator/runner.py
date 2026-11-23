"""One-command customer demo.

third-party asset source -> Asset Insights discovery -> extract IP/MAC/hostname ->
DHCP + DNS activity -> Threat Defense DNS scenarios -> portal verification checklist.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from demo_core.config import Config
from demo_core.errors import ConfigError, DemoError, NotVerifiedError, SafetyError
from demo_core.models import Asset, utcnow_iso
from generators.dhcp import build_dhcp_provider, run_dhcp_operation
from generators.dns import DNSTrafficGenerator
from generators.threat_defense import ThreatDefenseGenerator
from ddi_zones import IpamManager, ZoneManager
from verification import ManualChecklistVerifier

from .services import (dns_settings, ledger_for, record_dhcp, record_run, run_discovery,
                       runtime, select_assets)


@dataclass
class DemoOptions:
    scenarios: list[str] | None = None  # None = every enabled scenario except normal-dns
    skip_dhcp: bool = False
    skip_dns: bool = False
    skip_td: bool = False
    skip_zones: bool = False  # even when zones.enabled
    skip_ipam: bool = False  # even when ipam.enabled
    skip_discovery: bool = False  # reuse the asset store as-is
    dhcp_operation: str = "renew"
    limit: int | None = None
    duration: float | None = None
    rate: float | None = None
    dry_run: bool = False
    fail_fast: bool = False
    allow_placeholder_domains: bool = False


@dataclass
class StepResult:
    name: str
    status: str = "ok"  # ok | warn | failed | skipped
    detail: str = ""
    elapsed_s: float = 0.0
    data: dict[str, Any] = field(default_factory=dict)


class DemoOrchestrator:
    def __init__(self, cfg: Config, emit: Callable[[str], None] = print):
        self.cfg = cfg
        self.emit = emit

    # ------------------------------------------------------------------ main
    def run(self, opts: DemoOptions) -> dict[str, Any]:
        started = utcnow_iso()
        out_dir = Path(self.cfg.reporting.output_dir) / ("demo-" + started.replace(":", "").replace("-", ""))
        steps: list[StepResult] = []
        ledger = ledger_for(self.cfg)
        assets: list[Asset] = []
        counter = [0]

        def nm(label: str) -> str:
            counter[0] += 1
            return f"{counter[0]}. {label}"

        def step(name: str, fn: Callable[[StepResult], None]) -> StepResult:
            res = StepResult(name)
            t0 = time.monotonic()
            self.emit(f"\n== {name}")
            try:
                fn(res)
            except SafetyError as exc:
                res.status, res.detail = "failed", f"safety guard: {exc}"
            except NotVerifiedError as exc:
                res.status, res.detail = "failed", f"not implemented (unverified): {exc}"
            except DemoError as exc:
                res.status, res.detail = "failed", str(exc)
            res.elapsed_s = round(time.monotonic() - t0, 2)
            steps.append(res)
            mark = {"ok": "OK", "warn": "WARN", "failed": "FAIL", "skipped": "SKIP"}[res.status]
            self.emit(f"   [{mark}] {res.detail}")
            if res.status == "failed" and opts.fail_fast:
                raise _Abort(name)
            return res

        try:
            with runtime(self.cfg) as (provider, store):
                ep = provider.dns_endpoint()
                self.emit(f"Infrastructure: {provider.kind}  DNS target: {ep.host}:{ep.port}  "
                          f"dry-run: {opts.dry_run}")

                def preflight(r: StepResult) -> None:
                    checks = provider.preflight(probe_network=not opts.dry_run)
                    r.data["checks"] = [c.__dict__ for c in checks]
                    for c in checks:
                        self.emit(f"   - {c.status.upper():4} {c.name}: {c.detail}")
                    fails = [c for c in checks if c.status == "fail"]
                    r.status = "failed" if fails else ("warn" if any(c.status == "warn" for c in checks) else "ok")
                    r.detail = f"{len(checks)} checks, {len(fails)} failed"

                pre = step(nm("Infrastructure preflight"), preflight)
                if pre.status == "failed":
                    raise _Abort("preflight failed; fix infrastructure before running traffic")

                def discover(r: StepResult) -> None:
                    if opts.skip_discovery:
                        r.status, r.detail = "skipped", "using existing asset store"
                        return
                    result, (ins, upd) = run_discovery(self.cfg, store)
                    r.data = {"raw": result.raw_count, "pages": result.pages, "assets": len(result.assets),
                              "duplicates_merged": result.duplicates_merged, "retries": result.retries,
                              "invalid_ip": result.invalid_ip, "invalid_mac": result.invalid_mac,
                              "inserted": ins, "updated": upd}
                    r.detail = (f"{result.raw_count} raw -> {len(result.assets)} assets "
                                f"({result.duplicates_merged} duplicates merged, {result.invalid_ip} bad IP, "
                                f"{result.invalid_mac} bad MAC); {result.dns_eligible} DNS-eligible, "
                                f"{result.dhcp_eligible} DHCP-eligible")
                    if result.invalid_ip or result.invalid_mac:
                        r.status = "warn"

                step(nm("Asset discovery"), discover)

                try:
                    assets = select_assets(store, limit=opts.limit, require="any")
                except DemoError as exc:
                    raise _Abort(str(exc)) from exc
                self.emit(f"   {len(assets)} asset(s) in scope")

                mgr: list[ZoneManager] = []

                def zones(r: StepResult) -> None:
                    m = ZoneManager(self.cfg)
                    res = m.apply(dry_run=opts.dry_run)
                    mgr.append(m)
                    r.data = {"zones_created": res.zones_created, "zones_existing": res.zones_existing,
                              "records_created": len(res.records_created),
                              "records_updated": len(res.records_updated),
                              "records_unchanged": len(res.records_unchanged), "notes": res.notes}
                    r.detail = (f"{len(res.zones_created)} zone(s) created, {len(res.zones_existing)} present; "
                                f"records +{len(res.records_created)} ~{len(res.records_updated)} "
                                f"={len(res.records_unchanged)}")
                    for n in res.notes:
                        self.emit(f"   ! {n}")
                    if opts.dry_run:
                        r.detail += " (dry run, nothing written)"
                        return
                    rows = m.verify(ep.host, ep.port, timeout=self.cfg.dns.timeout)
                    bad = [x for x in rows if not x.ok]
                    r.data["verify"] = [x.__dict__ for x in rows]
                    r.status = "ok" if not bad else "warn"
                    r.detail += ("; server answers authoritatively for every record" if not bad else
                                 f"; {len(bad)}/{len(rows)} not answered authoritatively yet "
                                 "(is the zone assigned to this DNS server?)")
                    for x in bad[:5]:
                        self.emit(f"   ! {x.name} {x.type}: rcode {x.rcode}, AA={x.aa}, answers={x.answers}")

                if self.cfg.zones.enabled and not opts.skip_zones:
                    step(nm("Test zones: create and verify the server is authoritative"), zones)

                def ipam(r: StepResult) -> None:
                    res = IpamManager(self.cfg).apply(dry_run=opts.dry_run)
                    r.data = {"space": res.space, "space_created": res.space_created,
                              "subnets_created": res.subnets_created, "subnets_existing": res.subnets_existing,
                              "ranges_created": res.ranges_created, "ranges_existing": res.ranges_existing,
                              "notes": res.notes}
                    r.detail = (f"IP space {res.space!r}; subnets +{len(res.subnets_created)} "
                                f"={len(res.subnets_existing)}; ranges +{len(res.ranges_created)} "
                                f"={len(res.ranges_existing)}")
                    for n in res.notes:
                        self.emit(f"   ! {n}")
                    if opts.dry_run:
                        r.detail += " (dry run, nothing written)"
                    elif res.subnets_created or res.ranges_created:
                        self.emit(f"   waiting {self.cfg.ipam.wait_seconds:.0f}s for the DHCP config to reach the host")
                        time.sleep(self.cfg.ipam.wait_seconds)

                if self.cfg.ipam.enabled and not opts.skip_ipam:
                    step(nm("DHCP network: create subnet/range and assign the server"), ipam)

                def dhcp(r: StepResult) -> None:
                    if opts.skip_dhcp:
                        r.status, r.detail = "skipped", "--skip-dhcp"
                        return
                    prov = build_dhcp_provider(self.cfg, dry_run=opts.dry_run)
                    eligible = [a for a in assets if a.dhcp_eligible]
                    ops = ["request", opts.dhcp_operation] if opts.dhcp_operation != "request" else ["request"]
                    results = []
                    for op in ops:
                        results.extend(run_dhcp_operation(prov, op, eligible, self.cfg.dhcp.delay_between
                                                          if not opts.dry_run else 0.0))
                    for res in results:
                        record_dhcp(ledger, res)
                    ok = sum(1 for x in results if x.ok)
                    r.data = {"provider": prov.name, "operations": ops, "ok": ok, "total": len(results)}
                    r.detail = f"{prov.name}: {ok}/{len(results)} operations succeeded ({', '.join(ops)})"
                    r.status = "ok" if ok == len(results) else "warn"
                    for bad in [x for x in results if not x.ok][:5]:
                        self.emit(f"   ! {bad.asset_id} {bad.operation}: {bad.message}")

                step(nm("DHCP activity"), dhcp)

                dns_gen = DNSTrafficGenerator(self.cfg)
                settings = dns_settings(self.cfg, provider, duration=opts.duration,
                                        rate_per_asset=opts.rate, dry_run=opts.dry_run)

                def dns(r: StepResult) -> None:
                    if opts.skip_dns:
                        r.status, r.detail = "skipped", "--skip-dns"
                        return
                    summary = dns_gen.run(assets, dns_gen.selector_for_profile("normal"), settings,
                                          label="normal")
                    record_run(ledger, summary)
                    r.data = summary.to_dict()
                    r.status = "ok" if summary.failed == 0 and summary.total else "warn"
                    r.detail = (f"{summary.total} queries, {summary.answered} answered, "
                                f"{summary.failed} failed, {summary.achieved_qps} qps, "
                                f"p95 {summary.latency_ms_p95} ms")

                step(nm("Normal DNS activity"), dns)

                def internal(r: StepResult) -> None:
                    if not mgr:
                        r.status, r.detail = "skipped", "zones step did not complete"
                        return
                    usable = [a for a in assets if a.dns_eligible][: self.cfg.zones.query_devices]
                    rows, summary = mgr[0].query_as_assets(usable, settings, dns_gen)
                    record_run(ledger, summary)
                    auth = sum(1 for x in rows if x["aa"])
                    r.data = summary.to_dict()
                    r.status = "ok" if summary.failed == 0 and rows else "warn"
                    r.detail = (f"{summary.total} queries from {len(summary.assets)} device(s) for the internal "
                                f"zones; {auth} answered authoritatively; rcodes {summary.rcodes}")

                if self.cfg.zones.enabled and not opts.skip_zones:
                    step(nm("Internal-domain queries (server acts as authoritative)"), internal)

                td = ThreatDefenseGenerator(self.cfg, dns_gen, opts.allow_placeholder_domains)
                explicit = opts.scenarios is not None
                wanted = opts.scenarios if explicit else [
                    s for s in self.cfg.threat_defense.enabled_scenarios if s != "normal-dns"]

                def threat(r: StepResult) -> None:
                    if opts.skip_td:
                        r.status, r.detail = "skipped", "--skip-td"
                        return
                    if not wanted:
                        r.status, r.detail = "skipped", "no Threat Defense scenarios enabled"
                        return
                    ran, skipped = [], []
                    for name in wanted:
                        try:
                            summary = td.run(name, assets, settings)
                        except (ConfigError, SafetyError) as exc:
                            if explicit:
                                raise
                            skipped.append(f"{name}: {exc}".splitlines()[0])
                            continue
                        record_run(ledger, summary)
                        ran.append(summary.to_dict())
                        self.emit(f"   {name}: {summary.total} queries, rcodes {summary.rcodes}")
                    r.data = {"scenarios": [x["label"] for x in ran], "skipped": skipped}
                    r.detail = f"ran {len(ran)} scenario(s)" + (f"; skipped {len(skipped)}" if skipped else "")
                    for s in skipped:
                        self.emit(f"   ! skipped {s}")
                    r.status = "ok" if ran and not skipped else "warn"

                step(nm("Threat Defense scenarios"), threat)

                def verify(r: StepResult) -> None:
                    events = ledger.since(started)
                    result = ManualChecklistVerifier().verify(self.cfg, assets, events)
                    out_dir.mkdir(parents=True, exist_ok=True)
                    (out_dir / "verification.md").write_text(result["markdown"], encoding="utf-8")
                    r.detail = f"checklist written to {out_dir / 'verification.md'}"
                    r.data = {"window": result["window"]}

                step(nm("Portal verification checklist"), verify)
        except _Abort as abort:
            self.emit(f"\nAborted: {abort}")

        failed = [s for s in steps if s.status == "failed"]
        summary = {
            "started": started, "finished": utcnow_iso(), "infrastructure": self.cfg.infrastructure.type,
            "dry_run": opts.dry_run, "assets": len(assets),
            "status": "failed" if failed else ("warn" if any(s.status == "warn" for s in steps) else "ok"),
            "steps": [s.__dict__ for s in steps],
        }
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
        self.emit(f"\nDemo {summary['status'].upper()}. Reports: {out_dir}")
        return summary


class _Abort(Exception):
    pass
