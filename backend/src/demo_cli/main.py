"""``demo`` command line interface."""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Sequence

from asset_discovery import AssetInsightsClient, IPPolicy, dedupe_assets, normalize_asset
from demo_core.config import Config, load_config
from demo_core.errors import ConfigError, DemoError
from demo_core.models import Asset
from generators.dhcp import OPERATIONS, NativeDHCPProvider, build_dhcp_provider, run_dhcp_operation
from generators.dns import DNSTrafficGenerator, RunSummary, edns_options_for, expand_ip_streams
from generators.domains import StaticDomainSelector, parse_domain_entries
from ddi_zones import DdiApiError, IpamManager, ZoneManager
from generators.threat_defense import ThreatDefenseGenerator
from generators.tide import TideClient, save_snapshot
from orchestrator import DemoOptions, DemoOrchestrator
from orchestrator.services import (dns_settings, ledger_for, record_dhcp, record_run, run_discovery,
                                   runtime, select_assets)
from providers import build_provider, recommend_infrastructure
from verification import ManualChecklistVerifier

JSON_MODE = False


# --------------------------------------------------------------------------- output helpers
def _out(obj: Any, text: str | None = None) -> None:
    if JSON_MODE:
        print(json.dumps(obj, indent=2, default=str))
    elif text is not None:
        print(text)


def _table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    cells = [[str(c) if c is not None else "-" for c in r] for r in rows]
    widths = [max(len(h), *(len(r[i]) for r in cells)) if cells else len(h) for i, h in enumerate(headers)]
    line = lambda r: "  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip()  # noqa: E731
    return "\n".join([line(headers), line(["-" * w for w in widths]), *(line(r) for r in cells)])


def _summary_text(s: RunSummary) -> str:
    lines = [
        f"{s.kind} run '{s.label}' -> {s.dns_server or '-'}  ({'DRY RUN, ' if s.dry_run else ''}"
        f"source_mode={s.source_mode})",
        f"  assets: {len(s.assets)}  duration: {s.duration_s}s  planned: {s.planned_qps} qps  "
        f"achieved: {s.achieved_qps} qps",
        f"  queries: {s.total}  answered: {s.answered}  failed: {s.failed}  "
        f"latency p50/p95: {s.latency_ms_p50}/{s.latency_ms_p95} ms",
        f"  rcodes: {s.rcodes}",
        f"  qtypes: {s.by_qtype}",
    ]
    if s.by_category:
        lines.append(f"  categories: {s.by_category}")
    if s.errors:
        lines.append(f"  errors: {s.errors}")
    lines += [f"  note: {n}" for n in s.notes]
    return "\n".join(lines)


# --------------------------------------------------------------------------- commands
def cmd_discover(cfg: Config, args: argparse.Namespace) -> int:
    if args.probe:
        info = AssetInsightsClient(cfg.asset_source).probe()
        _out(info, f"OK  {info['url']}\n  returned {info['returned']} record(s); pagination: "
                   f"{info['pagination']}\n  record keys: {', '.join(info['record_keys']) or '-'}\n"
                   "  (nothing stored; run 'demo discover' to fetch and store assets)")
        return 0
    with runtime(cfg) as (_provider, store):
        result, (ins, upd) = run_discovery(cfg, store)
        payload = {"raw": result.raw_count, "pages": result.pages, "assets": len(result.assets),
                   "distinct_ips": result.ip_count, "ip_entries": result.ip_total,
                   "duplicate_ips_removed": result.ip_total - result.ip_count, "duplicates_merged": result.duplicates_merged,
                   "skipped_deleted": result.skipped_deleted,
                   "skipped_provider": result.skipped_provider, "invalid_ip": result.invalid_ip,
                   "invalid_mac": result.invalid_mac, "retries": result.retries,
                   "snapshot_at": result.snapshot_at, "truncated": result.truncated, "inserted": ins,
                   "updated": upd, "dns_eligible": result.dns_eligible,
                   "dhcp_eligible": result.dhcp_eligible, "warnings": result.warnings}
        text = (f"Asset Insights: {result.raw_count} record(s) over {result.pages} page(s) "
                f"({result.retries} retries, snapshot {result.snapshot_at or '-'})\n"
                f"  -> {len(result.assets)} asset(s), {result.ip_count} distinct usable IP(s) "
                f"({result.ip_total - result.ip_count} duplicate address(es) removed); "
                f"{result.skipped_deleted} deleted skipped, {result.skipped_provider} other-provider skipped, "
                f"{result.duplicates_merged} merged\n"
                f"  stored: {ins} new, {upd} updated  (store: {cfg.store.type} {cfg.store.path})\n"
                f"  DNS-eligible: {result.dns_eligible}  DHCP-eligible: {result.dhcp_eligible}  "
                f"invalid IPs: {result.invalid_ip}  invalid MACs: {result.invalid_mac}")
        if result.warnings:
            text += "\n  notes:\n" + "\n".join(f"    - {w}" for w in result.warnings[:10])
        _out(payload, text)
    return 0


def cmd_prepare(cfg: Config, args: argparse.Namespace) -> int:
    """Fetch and persist all generated inputs needed by DNS demos."""
    print("Preparing demo state...")
    discover_args = argparse.Namespace(probe=False)
    rc_assets = cmd_discover(cfg, discover_args)
    if rc_assets != 0:
        return rc_assets
    print("\nFetching Threat Defense domains...")
    td_args = argparse.Namespace(limit=args.td_limit, show=False)
    rc_td = cmd_td_fetch(cfg, td_args)
    if rc_td != 0:
        return rc_td
    print("\nReady: Asset Insights inventory and TIDE domains are stored locally.")
    print(f"  assets: {cfg.store.path}")
    print(f"  domains: {Path(cfg.reporting.state_dir) / 'tide_domains.json'}")
    if cfg.dns.domains_file:
        print(f"  DNS domain source: {cfg.dns.domains_file}")
    return 0


def cmd_assets_list(cfg: Config, args: argparse.Namespace) -> int:
    with runtime(cfg) as (_p, store):
        assets = store.list()
        if args.eligible:
            assets = [a for a in assets if a.dns_eligible]
        _out([a.to_core_dict() for a in assets],
             _table(["ASSET", "HOSTNAME", "IPS", "MAC", "TYPE", "DNS", "DHCP"],
                    [(a.asset_id, a.hostname, ", ".join(a.ips) or a.ip, a.mac, a.device_type,
                      "yes" if a.dns_eligible else "NO", "yes" if a.dhcp_eligible else "NO")
                     for a in assets]) + f"\n{len(assets)} asset(s)")
    return 0


def cmd_assets_show(cfg: Config, args: argparse.Namespace) -> int:
    with runtime(cfg) as (_p, store):
        asset = store.get(args.asset_id)
        if asset is None:
            raise DemoError(f"asset {args.asset_id!r} not found")
        _out(asset.to_dict(), json.dumps(asset.to_dict(), indent=2))
    return 0


def cmd_assets_ips(cfg: Config, args: argparse.Namespace) -> int:
    """De-duplicated list of every IP DNS traffic will use, with how many assets share it."""
    with runtime(cfg) as (_p, store):
        owners: dict[str, list[str]] = {}
        for a in store.list():
            for ip in (a.ips or ([a.ip] if a.ip else [])):
                owners.setdefault(ip, []).append(a.asset_id)
    ordered = sorted(owners, key=lambda i: (ipaddress.ip_address(i).version, ipaddress.ip_address(i)))
    if args.export:
        with open(args.export, "w", encoding="utf-8") as fh:
            fh.write("\n".join(ordered) + "\n")
    shared = sum(1 for v in owners.values() if len(v) > 1)
    public = sum(1 for i in ordered if not ipaddress.ip_address(i).is_private)
    summary = f"{len(ordered)} distinct IP(s); {public} public, {shared} shared by more than one asset"
    rows = [(i, "private" if ipaddress.ip_address(i).is_private else "public", len(owners[i]),
             ",".join(owners[i][:3]) + ("..." if len(owners[i]) > 3 else "")) for i in ordered]
    _out({"distinct_ips": len(ordered), "public": public, "shared": shared,
          "ips": {i: owners[i] for i in ordered}},
         (_table(["IP", "SCOPE", "ASSETS", "OWNERS"], rows) if args.show else "") +
         ("\n" if args.show else "") + summary + (f"\nexported to {args.export}" if args.export else ""))
    return 0


def cmd_assets_summary(cfg: Config, args: argparse.Namespace) -> int:
    """One-screen picture of the inventory: the opening of a customer demo."""
    from collections import Counter

    with runtime(cfg) as (_p, store):
        assets = store.list()
    real = [a for a in assets if "demo-synthetic" not in a.tags]
    by_source: Counter[str] = Counter()
    for a in real:
        for src in (a.discovery_source or "unknown").split(","):
            by_source[src.strip() or "unknown"] += 1
    by_type = Counter((a.device_type or "unknown") for a in real)
    ips = {ip for a in real for ip in (a.ips or ([a.ip] if a.ip else []))}
    data = {"assets": len(real), "synthetic": len(assets) - len(real), "distinct_ips": len(ips),
            "with_ip": sum(1 for a in real if a.dns_eligible), "with_mac": sum(1 for a in real if a.dhcp_eligible),
            "by_source": dict(by_source.most_common()), "by_type": dict(by_type.most_common())}
    top = lambda c, n: "\n".join(f"    {k:<28}{v:>6}" for k, v in c.most_common(n))  # noqa: E731
    _out(data, f"{len(real)} assets discovered ({data['with_ip']} with an IP, {data['with_mac']} with a MAC, "
               f"{len(ips)} distinct IPs)\n\n  by discovery source (an asset can have several):\n"
               f"{top(by_source, args.top)}\n\n  by device type:\n{top(by_type, args.top)}"
               + (f"\n\n  ({data['synthetic']} synthetic demo client(s) not counted)" if data["synthetic"] else ""))
    return 0


def cmd_assets_synth(cfg: Config, args: argparse.Namespace) -> int:
    """Create fake DHCP clients (made-up locally administered MACs). They carry no IP and never touch
    real asset records. Stored locally only; nothing is sent to the tenant by this command."""
    from demo_core.models import Asset

    made = []
    for i in range(1, args.count + 1):
        name = f"{args.prefix}-{i:03d}"
        made.append(Asset(asset_id=name, hostname=name, mac=f"02:de:{(i >> 16) & 255:02x}:{(i >> 8) & 255:02x}:"
                          f"{i & 255:02x}:{args.seed & 255:02x}", device_type="synthetic-client", vendor="demo",
                          source="synthetic", discovery_source="demo-synthetic", tags=["demo-synthetic"],
                          macs=[f"02:de:{(i >> 16) & 255:02x}:{(i >> 8) & 255:02x}:{i & 255:02x}:{args.seed & 255:02x}"]))
    with runtime(cfg) as (_p, store):
        ins, upd = store.upsert_many(made)
    _out([a.to_core_dict() for a in made],
         _table(["ASSET", "HOSTNAME", "MAC"], [(a.asset_id, a.hostname, a.mac) for a in made]) +
         f"\n{ins} created, {upd} updated. Use them with:  demo dhcp request --asset {made[0].asset_id}"
         if made else "nothing to create")
    return 0


def cmd_assets_import(cfg: Config, args: argparse.Namespace) -> int:
    """Load a saved API response (``{"data": [...]}``) or a bare list: offline rehearsal/debugging."""
    try:
        doc = json.loads(open(args.file, encoding="utf-8").read())
    except (OSError, ValueError) as exc:
        raise DemoError(f"cannot read {args.file}: {exc}") from exc
    rows = doc.get("data") if isinstance(doc, dict) else doc
    if not isinstance(rows, list):
        raise DemoError("expected a JSON list or an object with a 'data' list")
    policy = IPPolicy(cfg.asset_source.ip_selection)
    assets = [a for a in (normalize_asset(r, cfg.asset_source.default_source, policy)
                          for r in rows if isinstance(r, dict) and not r.get("deleted_at")) if a]
    assets = dedupe_assets(assets, cfg.asset_source.dedupe_by)
    with runtime(cfg) as (_p, store):
        ins, upd = store.upsert_many(assets)
    _out({"imported": len(assets), "inserted": ins, "updated": upd},
         f"imported {len(assets)} asset(s): {ins} new, {upd} updated")
    return 0


def cmd_assets_clear(cfg: Config, args: argparse.Namespace) -> int:
    with runtime(cfg) as (_p, store):
        n = store.count()
        store.clear()
        _out({"cleared": n}, f"cleared {n} asset(s)")
    return 0


def _select(store: Any, args: argparse.Namespace, require: str | None = None) -> list:
    return select_assets(store, args.asset, getattr(args, "limit", None), require)


def _override_selector(domains_arg: str | None) -> StaticDomainSelector | None:
    if not domains_arg:
        return None
    names = [d.strip() for d in domains_arg.split(",") if d.strip()]
    entries = parse_domain_entries(names, "--domains")
    return StaticDomainSelector([type(e)(e.name, "cli") for e in entries])


def _chunked(cfg: Config, assets: list, args: argparse.Namespace, run_one) -> tuple[list[RunSummary], int]:
    """Run ``run_one(chunk)`` once, or once per chunk of <= --chunk-size distinct IPs.

    Chunking works on distinct IPs (a shared address is assigned to exactly one chunk), runs the
    chunks one after another, and records every chunk in the ledger. Each chunk is a full run of
    ``--duration`` seconds, so total time is chunks x duration.
    """
    ledger = ledger_for(cfg)
    size = getattr(args, "chunk_size", None)
    if not size:
        summary = run_one(assets)
        record_run(ledger, summary)
        return [summary], 1
    streams = expand_ip_streams(assets)
    chunks = [streams[i:i + size] for i in range(0, len(streams), size)]
    dur = args.duration or cfg.dns.duration
    print(f"{len(streams)} distinct IP(s) in {len(chunks)} chunk(s) of <= {size}; "
          f"about {len(chunks) * dur:.0f}s of traffic in total", file=sys.stderr)
    summaries = []
    for n, chunk in enumerate(chunks, 1):
        if n > 1 and args.pause and not args.dry_run:
            time.sleep(args.pause)
        print(f"-- chunk {n}/{len(chunks)}: {len(chunk)} IP(s)", file=sys.stderr)
        summary = run_one(chunk)
        record_run(ledger, summary)
        summaries.append(summary)
    return summaries, len(chunks)


def _chunk_report(summaries: list[RunSummary], chunks: int) -> tuple[str, int]:
    text = "\n\n".join(_summary_text(s) for s in summaries)
    if chunks > 1:
        total, failed = sum(s.total for s in summaries), sum(s.failed for s in summaries)
        text += f"\n\nall {chunks} chunks: {total} queries, {failed} failed"
    ok = sum(s.total for s in summaries) > 0 and sum(s.failed for s in summaries) < sum(s.total for s in summaries)
    return text, 0 if ok else 3


def cmd_dns_run(cfg: Config, args: argparse.Namespace) -> int:
    with runtime(cfg) as (provider, store):
        assets = _select(store, args, "dns")
        gen = DNSTrafficGenerator(cfg)
        selector = _override_selector(args.domains) or gen.selector_for_profile(args.profile)
        over: dict[str, Any] = {"duration": args.duration, "rate_per_asset": args.rate,
                                "concurrency": args.concurrency, "dry_run": args.dry_run,
                                "source_mode": args.source_mode,
                                "query_types": [q.strip().upper() for q in args.query_types.split(",")]
                                if args.query_types else None}
        settings = dns_settings(cfg, provider, **over)
        summaries, n = _chunked(cfg, assets, args,
                                lambda chunk: gen.run(chunk, selector, settings, label=args.profile))
        text, code = _chunk_report(summaries, n)
        _out([x.to_dict() for x in summaries] if n > 1 else summaries[0].to_dict(), text)
        return code


def cmd_dns_query(cfg: Config, args: argparse.Namespace) -> int:
    """Exactly one query (or --count N) for a name/type, sent as one chosen device."""
    from generators.domains import parse_domain_entries
    from demo_core.models import utcnow_iso

    qname = args.name.strip()
    qtype = args.type.upper()
    if not qtype == "PTR":
        parse_domain_entries([qname], "--name")  # rejects IP literals / malformed names
    with runtime(cfg) as (provider, store):
        asset = select_assets(store, args.asset)[0]
        streams = expand_ip_streams([asset])
        if not streams:
            raise DemoError(f"asset {asset.asset_id} has no validated IP address")
        if args.ip:
            chosen = next((x for x in streams if x.ip == args.ip), None)
            if chosen is None:
                raise DemoError(f"{args.ip} is not one of {asset.asset_id}'s IPs: "
                                f"{', '.join(x.ip or '' for x in streams)}")
        else:
            chosen = streams[0]
        if qtype == "PTR" and qname in ("", "auto"):
            from generators.dnswire import reverse_name
            qname = reverse_name(chosen.ip or "")
        settings = dns_settings(cfg, provider, source_mode=args.source_mode, dry_run=args.dry_run,
                                timeout=args.timeout)
        gen = DNSTrafficGenerator(cfg)
        started = utcnow_iso()
        results = []
        for n in range(args.count):
            if n:
                time.sleep(args.interval)
            results.append(gen.send_one(chosen, qname, qtype, settings))
        ok = [r for r in results if r.ok]
        ledger_for(cfg).append(RunSummary(
            kind="dns", label="single-query", started=started, finished=utcnow_iso(),
            assets=[{"asset_id": chosen.asset_id, "hostname": chosen.hostname, "ip": chosen.ip,
                     "mac": chosen.mac}], total=len(results), answered=len(ok),
            failed=len(results) - len(ok), rcodes={r.rcode_name: 1 for r in ok},
            by_qtype={qtype: len(results)}, by_domain={qname: len(results)},
            by_asset={chosen.asset_id: len(results)}, dns_server=settings.server,
            source_mode=settings.source_mode, dry_run=args.dry_run).to_dict())
        lines = [f"query: {chosen.hostname or chosen.asset_id} ({chosen.ip}, {chosen.mac or 'no MAC'}) -> "
                 f"{settings.server}:{settings.port}   {qname} {qtype}   "
                 f"[source_mode={settings.source_mode}{', DRY RUN' if args.dry_run else ''}]"]
        if len(streams) > 1 and not args.ip:
            lines.append(f"  note: this device has {len(streams)} IPs; used {chosen.ip} "
                         "(pick another with --ip)")
        if settings.source_mode == "edns":
            sent = ", ".join(f"{c}={'ip ' + chosen.ip if c == settings.edns_ip_option else 'mac ' + str(chosen.mac)}"
                             for c, _ in edns_options_for(chosen, settings))
            lines.append(f"  EDNS options sent: {sent}")
        for i, r in enumerate(results, 1):
            outcome = f"{r.rcode_name} in {r.latency_ms:.1f} ms" if r.ok else f"FAILED ({r.error})"
            lines.append(f"  #{i}: {outcome}")
        _out([vars(r) for r in results], "\n".join(lines))
        return 0 if len(ok) == len(results) else 3


def cmd_dhcp(cfg: Config, args: argparse.Namespace) -> int:
    with runtime(cfg) as (_provider, store):
        assets = _select(store, args, "dhcp")
        provider = build_dhcp_provider(cfg, dry_run=args.dry_run)
        results = run_dhcp_operation(provider, args.operation, assets,
                                     0.0 if args.dry_run else cfg.dhcp.delay_between)
        ledger = ledger_for(cfg)
        for r in results:
            record_dhcp(ledger, r)
        text = _table(["ASSET", "OP", "OK", "MAC", "IP", "MESSAGE"],
                      [(r.asset_id, r.operation, "yes" if r.ok else "NO", r.mac, r.ip, r.message)
                       for r in results])
        if args.dry_run or args.show_commands:
            text += "\n\ncommands:\n" + "\n".join("  " + " ".join(r.command) for r in results if r.command)
        _out([r.to_dict() for r in results], text)
        # assets skipped for lack of a validated MAC are expected, not failures
        return 0 if all(r.ok or r.message.startswith("skipped") for r in results) else 3


def _synthetic_mac(prefix: str, index: int) -> str:
    parts = prefix.replace("-", ":").split(":")
    if len(parts) != 3 or any(len(x) != 2 for x in parts):
        raise ConfigError("--mac-prefix must contain exactly 3 octets, e.g. 02:dd:10")
    try:
        head = [int(x, 16) for x in parts]
    except ValueError:
        raise ConfigError("--mac-prefix must be hexadecimal, e.g. 02:dd:10") from None
    if head[0] & 1:
        raise ConfigError("--mac-prefix must be unicast (first octet must not have multicast bit set)")
    if not 1 <= index <= 0xFFFFFF:
        raise ConfigError("synthetic client index exceeds 24-bit MAC suffix")
    tail = [(index >> 16) & 0xff, (index >> 8) & 0xff, index & 0xff]
    return ":".join(f"{x:02x}" for x in head + tail)


def cmd_dhcp_synthetic(cfg: Config, args: argparse.Namespace) -> int:
    """Run DHCP with generated identities, completely independent of Asset Insights."""
    if not cfg.dhcp.server:
        raise ConfigError("dhcp.server is required")
    if not cfg.dhcp.dra.relay_agent_ip:
        raise ConfigError("dhcp.dra.relay_agent_ip is required for synthetic relay-style DHCP; "
                          "set it to a local address on this VM that belongs to the configured DHCP subnet")
    if args.count < 1 or args.count > 1000:
        raise ConfigError("--count must be between 1 and 1000")
    if args.start < 1:
        raise ConfigError("--start must be >= 1")

    clients = []
    for i in range(args.start, args.start + args.count):
        hostname = f"{args.hostname_prefix}-{i:04d}"
        mac = _synthetic_mac(args.mac_prefix, i)
        clients.append(Asset(asset_id=hostname, hostname=hostname, mac=mac, macs=[mac],
                             device_type="synthetic-dhcp-client", source="synthetic"))

    state_dir = Path(args.state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "clients.json").write_text(json.dumps({
        "source": "synthetic", "count": len(clients),
        "clients": [{"asset_id": a.asset_id, "hostname": a.hostname, "mac": a.mac} for a in clients]
    }, indent=2) + "\n")

    # Force the built-in implementation: synthetic mode must not depend on dras being installed.
    provider = NativeDHCPProvider(cfg.dhcp.server, cfg.dhcp.dra, cfg.dhcp.native,
                                  cfg.dhcp.port, dry_run=args.dry_run)
    results = run_dhcp_operation(provider, args.dhcp_operation, clients,
                                 0.0 if args.dry_run else cfg.dhcp.delay_between)
    ledger = ledger_for(cfg)
    for r in results:
        record_dhcp(ledger, r)
    text = _table(["CLIENT", "OP", "OK", "MAC", "LEASE/OFFER", "MESSAGE"],
                  [(r.asset_id, r.operation, "yes" if r.ok else "NO", r.mac, r.ip, r.message)
                   for r in results])
    text += f"\n\nsynthetic clients: {len(clients)}; state: {state_dir / 'clients.json'}"
    if args.dry_run:
        text += "\nDRY RUN: no DHCP packets were sent."
    else:
        text += "\nProvider: built-in native relay-style DHCP (no DRAS dependency)."
    _out([r.to_dict() for r in results], text)
    return 0 if all(r.ok for r in results) else 3


def _zone_manager(cfg: Config) -> ZoneManager:
    return ZoneManager(cfg)


def cmd_zones_hosts(cfg: Config, args: argparse.Namespace) -> int:
    """List DNS hosts for diagnostics or an explicit zones.dns_host override."""
    from ddi_zones import DdiClient

    rows = DdiClient(cfg).list("dns/host")
    table = []
    for r in rows:
        extra = {k: v for k, v in r.items() if isinstance(v, (str, int)) and k not in ("id", "name")}
        table.append((r.get("id"), r.get("name"), ", ".join(f"{k}={v}" for k, v in list(extra.items())[:3])))
    _out(rows, _table(["ID (use as zones.dns_host)", "NAME", "OTHER"], table) +
         "\nUse the DNS host id (dns/host/...), NOT the on-prem host id.")
    return 0


def cmd_zones_apply(cfg: Config, args: argparse.Namespace) -> int:
    res = _zone_manager(cfg).apply(dry_run=args.dry_run)
    lines = [f"{'PLAN (dry run, nothing written)' if res.dry_run else 'APPLIED'}:",
             f"  zones   : {len(res.zones_created)} to create/created, {len(res.zones_existing)} already present",
             f"  records : {len(res.records_created)} created, {len(res.records_updated)} updated, "
             f"{len(res.records_unchanged)} unchanged"]
    lines += [f"    + {r}" for r in res.records_created] + [f"    ~ {r}" for r in res.records_updated]
    lines += [f"  note: {n}" for n in res.notes]
    _out(res.__dict__, "\n".join(lines))
    return 0


def cmd_zones_status(cfg: Config, args: argparse.Namespace) -> int:
    rows = _zone_manager(cfg).status()
    _out(rows, _table(["ZONE", "EXISTS", "MANAGED BY US", "RECORDS", "ASSIGNED TO"],
                      [(r["zone"], r["exists"], r["managed"], f"{r['records_found']}/{r['records_expected']}",
                        r["assigned"]) for r in rows]))
    return 0 if all(r["exists"] for r in rows) else 3


def cmd_zones_destroy(cfg: Config, args: argparse.Namespace) -> int:
    mgr = _zone_manager(cfg)
    if not args.dry_run and not args.yes:
        names = ", ".join(s.fqdn for s in mgr.specs)
        if input(f"Delete zone(s) {names} and the records this tool created? Type 'delete': ").strip() != "delete":
            print("cancelled")
            return 0
    done = mgr.destroy(dry_run=args.dry_run)
    text = (f"{'PLAN (dry run)' if args.dry_run else 'DELETED'}: zones {done['zones_deleted']}, "
            f"{len(done['records_deleted'])} record(s); absent: {done['absent']}")
    if done["errors"]:
        text += "\nerrors:\n  " + "\n  ".join(done["errors"])
    _out(done, text)
    return 3 if done["errors"] else 0


def _verify_table(rows) -> str:
    return _table(["NAME", "TYPE", "EXPECT", "RCODE", "AA", "ANSWERS", "OK"],
                  [(r.name, r.type, r.expect, r.rcode, r.aa, r.answers, "yes" if r.ok else "NO") for r in rows])


def cmd_zones_verify(cfg: Config, args: argparse.Namespace) -> int:
    with runtime(cfg) as (provider, _store):
        ep = provider.dns_endpoint()
        rows = _zone_manager(cfg).verify(ep.host, ep.port, wait=args.wait, timeout=cfg.dns.timeout)
        ok = all(r.ok for r in rows)
        note = "\n(mock DNS: zones are emulated from the config, nothing real was verified)" \
            if provider.kind == "mock" else ""
        _out([r.__dict__ for r in rows], f"{ep.host}:{ep.port}\n{_verify_table(rows)}\n"
             f"{'AUTHORITATIVE: the server answers for every zone record' if ok else 'NOT YET: some records are not answered authoritatively (see AA / RCODE)'}{note}")
        return 0 if ok else 3


def cmd_zones_test(cfg: Config, args: argparse.Namespace) -> int:
    with runtime(cfg) as (provider, store):
        assets = select_assets(store, None, args.limit, "dns")
        settings = dns_settings(cfg, provider, source_mode=args.source_mode, dry_run=args.dry_run)
        rows, summary = _zone_manager(cfg).query_as_assets(assets, settings)
        record_run(ledger_for(cfg), summary)
        text = _table(["DEVICE", "IP", "NAME", "TYPE", "RCODE", "AA", "ANS", "MS"],
                      [(r["asset"][:18], r["ip"], r["name"], r["type"], r["rcode"], r["aa"], r["answers"], r["ms"])
                       for r in rows])
        auth = sum(1 for r in rows if r["aa"])
        text += (f"\n{len(rows)} queries from {len(summary.assets)} device(s) -> {settings.server}  "
                 f"(source_mode={settings.source_mode}); {auth} answered authoritatively")
        _out(rows, text)
        return 0 if summary.failed == 0 else 3


def cmd_ipam_hosts(cfg: Config, args: argparse.Namespace) -> int:
    """List DHCP hosts for diagnostics or an explicit ipam.dhcp_host override."""
    rows = IpamManager(cfg).hosts()
    table = []
    for r in rows:
        extra = {k: v for k, v in r.items() if isinstance(v, (str, int)) and k not in ("id", "name")}
        table.append((r.get("id"), r.get("name"), ", ".join(f"{k}={v}" for k, v in list(extra.items())[:3])))
    _out(rows, _table(["ID (use as ipam.dhcp_host)", "NAME", "OTHER"], table) +
         "\nThis is the DHCP host id (dhcp/host/...). It differs from the dns/host id.")
    return 0


def cmd_ipam_apply(cfg: Config, args: argparse.Namespace) -> int:
    res = IpamManager(cfg).apply(dry_run=args.dry_run)
    lines = [f"{'PLAN (dry run, nothing written)' if res.dry_run else 'APPLIED'}: IP space {res.space!r} "
             f"({'to create' if res.dry_run and res.space_created else 'created' if res.space_created else 'existing'})",
             f"  subnets: {len(res.subnets_created)} to create/created, {len(res.subnets_existing)} already present",
             f"  ranges : {len(res.ranges_created)} to create/created, {len(res.ranges_existing)} already present"]
    lines += [f"    + subnet {s}" for s in res.subnets_created] + [f"    + range  {r}" for r in res.ranges_created]
    lines += [f"  note: {n}" for n in res.notes]
    _out(res.__dict__, "\n".join(lines))
    return 0


def cmd_ipam_status(cfg: Config, args: argparse.Namespace) -> int:
    rows = IpamManager(cfg).status()
    _out(rows, _table(["SUBNET", "SPACE", "EXISTS", "MANAGED BY US", "SERVED BY", "RANGES"],
                      [(r["subnet"], r["space"], r["exists"], r["managed"], r["dhcp_host"],
                        f"{r['ranges_found']}/{r['ranges_expected']}") for r in rows]))
    return 0 if all(r["exists"] for r in rows) else 3


def cmd_ipam_destroy(cfg: Config, args: argparse.Namespace) -> int:
    mgr = IpamManager(cfg)
    if not args.dry_run and not args.yes:
        names = ", ".join(f"{s.address}/{s.cidr}" for s in mgr.specs)
        if input(f"Delete subnet(s) {names}, their ranges, and the IP space if this tool created it? "
                 "Type 'delete': ").strip() != "delete":
            print("cancelled")
            return 0
    done = mgr.destroy(dry_run=args.dry_run)
    text = (f"{'PLAN (dry run)' if args.dry_run else 'DELETED'}: ranges {done['ranges_deleted']}, subnets "
            f"{done['subnets_deleted']}, space {done['space_deleted']}; absent: {done['absent']}")
    if done["errors"]:
        text += "\nerrors:\n  " + "\n  ".join(done["errors"])
    _out(done, text)
    return 3 if done["errors"] else 0


def cmd_ipam_leases(cfg: Config, args: argparse.Namespace) -> int:
    """Read leases back from the API: the terminal proof that DHCP leases exist."""
    rows = IpamManager(cfg).leases(mac=args.mac, limit=args.limit)
    table = []
    for r in rows[: args.show]:
        keys = ("address", "hostname", "hwaddr", "client_id", "state", "starts", "ends")
        shown = {k: r[k] for k in keys if k in r} or {k: v for k, v in r.items() if isinstance(v, (str, int))}
        table.append((r.get("id", ""), ", ".join(f"{k}={v}" for k, v in list(shown.items())[:5])))
    _out(rows, (_table(["ID", "FIELDS (names are not verified; use --json for everything)"], table)
                if table else "no matching leases") + f"\n{len(rows)} lease(s)" +
         (f" matching {args.mac}" if args.mac else ""))
    return 0 if rows else 3


def cmd_td_scenarios(cfg: Config, args: argparse.Namespace) -> int:
    td = ThreatDefenseGenerator(cfg)
    enabled = set(cfg.threat_defense.enabled_scenarios)
    rows = [(n, "yes" if n in enabled else "NO", f"{s.threat_ratio:.0%}", f"x{s.rate_multiplier:g}",
             s.description) for n, s in sorted(td.scenarios().items())]
    _out({n: s.__dict__ for n, s in td.scenarios().items()},
         _table(["SCENARIO", "ENABLED", "THREAT%", "RATE", "DESCRIPTION"], rows))
    return 0


def cmd_td_fetch(cfg: Config, args: argparse.Namespace) -> int:
    """Pull active threat domains from the portal's TIDE into a reviewable snapshot."""
    client = TideClient(cfg)
    res = client.fetch(args.limit)
    path = save_snapshot(cfg, res)
    t = cfg.threat_defense.tide
    lines = [f"TIDE active indicators: {res.raw_count} record(s) -> {len(res.domains)} distinct domain(s) "
             f"({res.duplicates} duplicate, {res.skipped_invalid} invalid skipped)",
             f"  classes: {res.by_class or '-'}",
             f"  category assigned: '{t.category}'   snapshot: {path}"]
    shown = res.domains if args.show else res.domains[:10]
    lines += [f"    {d.name:<45} {d.note}" for d in shown]
    if not args.show and len(res.domains) > 10:
        lines.append(f"    ... {len(res.domains) - 10} more (use --show, or open the snapshot file)")
    if not t.enabled:
        lines.append("  NOTE: threat_defense.tide.enabled is false, so scenarios will NOT use this "
                     "snapshot yet. Review it, then set it to true.")
    _out({"raw": res.raw_count, "domains": [d.name for d in res.domains], "by_class": res.by_class,
          "snapshot": str(path), "enabled": t.enabled}, "\n".join(lines))
    return 0 if res.domains else 3


def cmd_td_run(cfg: Config, args: argparse.Namespace) -> int:
    with runtime(cfg) as (provider, store):
        assets = _select(store, args, "dns")
        td = ThreatDefenseGenerator(cfg, allow_placeholder=args.allow_placeholder)
        over: dict[str, Any] = {"duration": args.duration, "rate_per_asset": args.rate,
                                "concurrency": args.concurrency, "dry_run": args.dry_run,
                                "source_mode": args.source_mode}
        settings = dns_settings(cfg, provider, **over)
        summaries, n = _chunked(cfg, assets, args, lambda chunk: td.run(args.scenario, chunk, settings))
        text, code = _chunk_report(summaries, n)
        _out([x.to_dict() for x in summaries] if n > 1 else summaries[0].to_dict(), text)
        return code


def cmd_infra(cfg: Config, args: argparse.Namespace) -> int:
    provider = build_provider(cfg)
    caps = provider.capabilities()
    if args.infra_cmd == "show":
        ep, dh = provider.dns_endpoint(), provider.dhcp_endpoint()
        _out({"type": provider.kind, "dns": ep.__dict__, "dhcp": dh.__dict__ if dh else None,
              "capabilities": caps.__dict__},
             f"infrastructure: {provider.kind}\n  dns:  {ep.host or '-'}:{ep.port}\n"
             f"  dhcp: {f'{dh.host}:{dh.port}' if dh else '-'}\n  capabilities: dns={caps.dns} "
             f"dhcp={caps.dhcp} td-dns-path={caps.threat_defense_dns_path}\n\n"
             f"{provider.deployment_notes()}")
        return 0
    # check
    provider.start()
    try:
        checks = provider.preflight(probe_network=not args.no_network)
    finally:
        provider.stop()
    _out([c.__dict__ for c in checks], _table(["STATUS", "CHECK", "DETAIL"],
                                              [(c.status.upper(), c.name, c.detail) for c in checks]))
    return 1 if any(c.status == "fail" for c in checks) else 0


def cmd_infra_recommend(cfg: Config | None, args: argparse.Namespace) -> int:
    rec = recommend_infrastructure(args.needs_local_dns_dhcp, args.needs_physical,
                                   not args.xaas_unsupported)
    _out(rec.__dict__, f"recommended: {rec.type}\n  why: {rec.reason}\n  order: {' > '.join(rec.order)}")
    return 0


def cmd_verify(cfg: Config, args: argparse.Namespace) -> int:
    ledger = ledger_for(cfg)
    events = ledger.since(args.since) if args.since else ledger.read_all()
    with runtime(cfg) as (_p, store):
        assets = store.list()
    result = ManualChecklistVerifier().verify(cfg, assets, events)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(result["markdown"])
    _out(result, result["markdown"] if not args.out else f"checklist written to {args.out}")
    return 0


def cmd_run_demo(cfg: Config, args: argparse.Namespace) -> int:
    opts = DemoOptions(
        scenarios=[s.strip() for s in args.scenarios.split(",")] if args.scenarios else None,
        skip_dhcp=args.skip_dhcp, skip_dns=args.skip_dns, skip_td=args.skip_td,
        skip_zones=args.skip_zones, skip_ipam=args.skip_ipam, skip_discovery=args.skip_discovery, dhcp_operation=args.dhcp_operation, limit=args.limit,
        duration=args.duration, rate=args.rate, dry_run=args.dry_run, fail_fast=args.fail_fast,
        allow_placeholder_domains=args.allow_placeholder)
    summary = DemoOrchestrator(cfg, emit=(lambda *_: None) if JSON_MODE else print).run(opts)
    if JSON_MODE:
        _out(summary)
    return {"ok": 0, "warn": 0, "failed": 1}[summary["status"]]


# --------------------------------------------------------------------------- parser
def _target(p: argparse.ArgumentParser, with_limit: bool = True) -> None:
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--asset", metavar="ASSET_ID", help="a single asset")
    g.add_argument("--all", action="store_true", help="every discovered asset")
    if with_limit:
        p.add_argument("--limit", type=int, help="only the first N usable assets (with --all)")


def _traffic_opts(p: argparse.ArgumentParser) -> None:
    p.add_argument("--duration", type=float, help="seconds (default dns.duration)")
    p.add_argument("--rate", type=float, help="queries/sec per asset (default dns.rate_per_asset)")
    p.add_argument("--concurrency", type=int, help="worker threads (default dns.concurrency)")
    p.add_argument("--dry-run", action="store_true", help="plan only; send nothing")
    p.add_argument("--source-mode", choices=["direct", "bind", "edns", "spoof"],
                   help="how asset identity is carried (default dns.source_mode)")
    p.add_argument("--chunk-size", type=int, metavar="N",
                   help="run in sequential batches of at most N distinct IPs (each batch lasts --duration)")
    p.add_argument("--pause", type=float, default=0.0, metavar="SEC", help="wait between chunks")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="demo", description="Asset Insights -> DDI/Threat Defense demo")
    ap.add_argument("-c", "--config", help="config file (default $DEMO_CONFIG or config/config.yaml)")
    ap.add_argument("--log-level", help="DEBUG|INFO|WARNING|ERROR (overrides config)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("prepare", help="fetch Asset Insights inventory and TIDE domains, then persist both")
    p.add_argument("--td-limit", type=int, help="max TIDE records (default threat_defense.tide.limit)")
    p.set_defaults(func=cmd_prepare)

    p = sub.add_parser("discover", help="fetch assets from the Asset Insights API and store them")
    p.add_argument("--probe", action="store_true",
                   help="one tiny request to validate URL/key/response shape; stores nothing")
    p.set_defaults(func=cmd_discover)

    a = sub.add_parser("assets", help="inspect the asset store").add_subparsers(dest="assets_cmd", required=True)
    p = a.add_parser("list", help="list assets")
    p.add_argument("--eligible", action="store_true", help="only assets with a valid IP")
    p.set_defaults(func=cmd_assets_list)
    p = a.add_parser("show", help="show one asset")
    p.add_argument("asset_id")
    p.set_defaults(func=cmd_assets_show)
    p = a.add_parser("ips", help="distinct IPs DNS traffic will use (duplicates removed)")
    p.add_argument("--show", action="store_true", help="print the full table, not just totals")
    p.add_argument("--export", metavar="FILE", help="write one IP per line")
    p.set_defaults(func=cmd_assets_ips)
    p = a.add_parser("summary", help="one-screen summary of the inventory (by source and device type)")
    p.add_argument("--top", type=int, default=8, help="rows per breakdown (default 8)")
    p.set_defaults(func=cmd_assets_summary)
    p = a.add_parser("synth", help="create fake DHCP clients (made-up MACs) that never touch real asset records")
    p.add_argument("--count", type=int, default=3)
    p.add_argument("--prefix", default="demo-dhcp")
    p.add_argument("--seed", type=int, default=1, help="last MAC byte, to keep sets distinct")
    p.set_defaults(func=cmd_assets_synth)
    p = a.add_parser("import", help="load a saved API response (JSON) into the store")
    p.add_argument("file")
    p.set_defaults(func=cmd_assets_import)
    a.add_parser("clear", help="empty the store").set_defaults(func=cmd_assets_clear)

    d = sub.add_parser("dns", help="DNS traffic").add_subparsers(dest="dns_cmd", required=True)
    p = d.add_parser("run", help="generate DNS activity")
    _target(p)
    p.add_argument("--profile", choices=["normal", "security-demo"], default="normal")
    p.add_argument("--query-types", help="comma list, e.g. A,AAAA,TXT")
    p.add_argument("--domains", help="comma list overriding the profile's domains")
    _traffic_opts(p)
    p.set_defaults(func=cmd_dns_run)

    p = d.add_parser("query", help="send exactly one query (or --count N) from one device")
    p.add_argument("--asset", required=True, metavar="ASSET_ID", help="the device to send as")
    p.add_argument("--name", required=True, help="domain to query (for PTR use 'auto' = the device's IP)")
    p.add_argument("--type", default="A",
                   choices=["A", "AAAA", "TXT", "PTR", "CNAME", "MX", "SRV", "NS", "SOA", "CAA"])
    p.add_argument("--ip", help="which of the device's IPs to use (default: its first)")
    p.add_argument("--count", type=int, default=1, help="repeat N times (default 1)")
    p.add_argument("--interval", type=float, default=1.0, help="seconds between repeats")
    p.add_argument("--timeout", type=float, help="seconds to wait for the answer")
    p.add_argument("--source-mode", choices=["direct", "bind", "edns", "spoof"],
                   help="how the device identity is carried (default dns.source_mode)")
    p.add_argument("--dry-run", action="store_true", help="show what would be sent; send nothing")
    p.set_defaults(func=cmd_dns_query)

    h = sub.add_parser("dhcp", help="DHCP lifecycle activity").add_subparsers(dest="operation", required=True)
    for op in OPERATIONS:
        p = h.add_parser(op, help=f"DHCP {op}")
        _target(p)
        p.add_argument("--dry-run", action="store_true", help="print commands only")
        p.add_argument("--show-commands", action="store_true")
        p.set_defaults(func=cmd_dhcp)

    p = h.add_parser("synthetic", help="DHCP traffic from generated clients (not Asset Insights)")
    p.add_argument("--count", type=int, default=5, help="number of synthetic clients (default 5)")
    p.add_argument("--start", type=int, default=1, help="starting client number (default 1)")
    p.add_argument("--hostname-prefix", default="demo-dhcp", help="hostname prefix")
    p.add_argument("--mac-prefix", default="02:dd:10", help="3-octet locally administered MAC prefix")
    p.add_argument("--operation", dest="dhcp_operation", choices=["discover", "request"], default="request",
                   help="discover only, or full DORA request (default request)")
    p.add_argument("--state-dir", default="state/dhcp-synthetic", help="synthetic client state directory")
    p.add_argument("--dry-run", action="store_true", help="show clients/packets but send nothing")
    p.set_defaults(func=cmd_dhcp_synthetic)

    ip = sub.add_parser("ipam", help="create the DHCP network (IP space, subnet, range) and read leases back"
                        ).add_subparsers(dest="ipam_cmd", required=True)
    ip.add_parser("hosts", help="list DHCP hosts (diagnostics / explicit override)").set_defaults(func=cmd_ipam_hosts)
    p = ip.add_parser("apply", help="create the IP space, subnet(s) and range(s) and assign the server")
    p.add_argument("--dry-run", action="store_true", help="show what would change; write nothing")
    p.set_defaults(func=cmd_ipam_apply)
    ip.add_parser("status", help="do the subnets/ranges exist and which host serves them").set_defaults(func=cmd_ipam_status)
    p = ip.add_parser("destroy", help="delete the subnets/ranges (and the IP space) this tool created")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    p.set_defaults(func=cmd_ipam_destroy)
    p = ip.add_parser("leases", help="read DHCP leases back from the API")
    p.add_argument("--mac", help="only leases whose record mentions this MAC (substring match)")
    p.add_argument("--limit", type=int, default=200, help="records to fetch (default 200)")
    p.add_argument("--show", type=int, default=20, help="rows to print (default 20)")
    p.set_defaults(func=cmd_ipam_leases)

    zp = sub.add_parser("zones", help="create/verify/query test DNS zones (authoritative internal domains)"
                        ).add_subparsers(dest="zones_cmd", required=True)
    zp.add_parser("hosts", help="list DNS hosts (diagnostics / explicit override)").set_defaults(func=cmd_zones_hosts)
    p = zp.add_parser("apply", help="create the configured zones and records (idempotent)")
    p.add_argument("--dry-run", action="store_true", help="show what would change; write nothing")
    p.set_defaults(func=cmd_zones_apply)
    zp.add_parser("status", help="show whether the zones exist and their records").set_defaults(func=cmd_zones_status)
    p = zp.add_parser("verify", help="check the DNS server answers authoritatively (AA flag)")
    p.add_argument("--wait", type=float, help="seconds to keep retrying (default zones.wait_seconds)")
    p.set_defaults(func=cmd_zones_verify)
    p = zp.add_parser("test", help="query every zone record once as each device (internal-domain traffic)")
    p.add_argument("--limit", type=int, default=5, help="devices to use (default 5)")
    p.add_argument("--source-mode", choices=["direct", "bind", "edns", "spoof"])
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_zones_test)
    p = zp.add_parser("destroy", help="delete the zones and the records this tool created")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    p.set_defaults(func=cmd_zones_destroy)

    t = sub.add_parser("td", help="Threat Defense DNS scenarios").add_subparsers(dest="td_cmd", required=True)
    t.add_parser("scenarios", help="list scenarios").set_defaults(func=cmd_td_scenarios)
    p = t.add_parser("fetch", help="pull active threat domains from the portal's TIDE (snapshot)")
    p.add_argument("--limit", type=int, help="max records (default threat_defense.tide.limit, max 1000)")
    p.add_argument("--show", action="store_true", help="list every domain, not just 10")
    p.set_defaults(func=cmd_td_fetch)
    p = t.add_parser("run", help="run a scenario")
    p.add_argument("--scenario", required=True)
    _target(p)
    p.add_argument("--allow-placeholder", action="store_true", help="permit 'replace-me' domains (CI only)")
    _traffic_opts(p)
    p.set_defaults(func=cmd_td_run)

    i = sub.add_parser("infra", help="infrastructure provider").add_subparsers(dest="infra_cmd", required=True)
    i.add_parser("show", help="endpoints, capabilities, deployment notes").set_defaults(func=cmd_infra)
    p = i.add_parser("check", help="preflight checks")
    p.add_argument("--no-network", action="store_true", help="skip the live DNS probe")
    p.set_defaults(func=cmd_infra)
    p = i.add_parser("recommend", help="recommend a deployment model (XaaS > OVA > bare metal)")
    p.add_argument("--needs-local-dns-dhcp", action="store_true")
    p.add_argument("--needs-physical", action="store_true")
    p.add_argument("--xaas-unsupported", action="store_true", help="required capabilities not on XaaS")
    p.set_defaults(func=cmd_infra_recommend, no_config=True)

    p = sub.add_parser("verify", help="generate the portal verification checklist")
    p.add_argument("--since", help="ISO timestamp, e.g. 2026-11-11T09:00:00Z")
    p.add_argument("--out", help="write markdown to a file")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("run-demo", help="run the complete customer demo")
    p.add_argument("--scenarios", help="comma list (default: all enabled except normal-dns)")
    p.add_argument("--skip-discovery", action="store_true")
    p.add_argument("--skip-dhcp", action="store_true")
    p.add_argument("--skip-dns", action="store_true")
    p.add_argument("--skip-td", action="store_true")
    p.add_argument("--skip-zones", action="store_true", help="skip the zone steps even if zones.enabled")
    p.add_argument("--skip-ipam", action="store_true", help="skip creating the DHCP network even if ipam.enabled")
    p.add_argument("--dhcp-operation", choices=["request", "renew", "release"], default="renew")
    p.add_argument("--limit", type=int)
    p.add_argument("--duration", type=float)
    p.add_argument("--rate", type=float)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--fail-fast", action="store_true")
    p.add_argument("--allow-placeholder", action="store_true")
    p.set_defaults(func=cmd_run_demo)

    return ap


def main(argv: Sequence[str] | None = None) -> int:
    global JSON_MODE
    args = build_parser().parse_args(argv)
    JSON_MODE = args.json
    try:
        cfg = None if getattr(args, "no_config", False) else load_config(args.config)
        level = (args.log_level or (cfg.log_level if cfg else "WARNING")).upper()
        logging.basicConfig(level=getattr(logging, level, logging.INFO),
                            format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)
        return args.func(cfg, args)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return exc.exit_code
    except DemoError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except BrokenPipeError:  # e.g. `demo assets list | head`
        sys.stderr.close()
        return 0
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
