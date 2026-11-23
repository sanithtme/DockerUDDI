"""Portal verification.

No Infoblox portal API for querying DNS Activity / Security Activity / lease data is
documented in the internal material this project was built from, so automated verification is
a STUB (``ApiPortalVerifier``). The default ``ManualChecklistVerifier`` produces an exact,
time-boxed checklist the presenter follows in the portal.

Portal locations named below come from the internal AU Realm CSP Tenant Test Plan
(DDI-02, DDI-04, TD-04, TD-07). Menu labels can change between portal builds: confirm them.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any

from demo_core.config import Config
from demo_core.errors import NotVerifiedError
from demo_core.models import Asset

API_TODO = """\
Automated portal verification is not implemented because these are NOT verified in the
available internal documentation:
  * an API (or approved export) to query DNS Activity / Security Activity / TI reports
  * an API to read DHCP lease or IPAM/Asset records for a given MAC/IP
  * the authentication scheme and tenant/realm base URL for those APIs
  * response schemas, time-window filtering, and indexing delay (how long until traffic appears)
Provide the API guide (or Postman collection) for these and implement ApiPortalVerifier.verify().
"""


class PortalVerifier(ABC):
    @abstractmethod
    def verify(self, cfg: Config, assets: list[Asset], events: list[dict[str, Any]]) -> dict[str, Any]:
        """Return ``{"status": ..., "markdown": ..., "checks": [...]}``."""


class ApiPortalVerifier(PortalVerifier):
    """TODO stub. Raises with an explicit list of what is required."""

    def verify(self, cfg: Config, assets: list[Asset], events: list[dict[str, Any]]) -> dict[str, Any]:
        raise NotVerifiedError(API_TODO)


def _window(events: list[dict[str, Any]], buffer_min: int) -> tuple[str, str]:
    stamps = [e.get("started") or e.get("timestamp") for e in events]
    ends = [e.get("finished") or e.get("timestamp") for e in events]
    stamps, ends = [s for s in stamps if s], [s for s in ends if s]
    if not stamps:
        return "(no activity recorded)", "(no activity recorded)"
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    lo = datetime.strptime(min(stamps), fmt).replace(tzinfo=timezone.utc) - timedelta(minutes=buffer_min)
    hi = datetime.strptime(max(ends or stamps), fmt).replace(tzinfo=timezone.utc) + timedelta(minutes=buffer_min)
    return lo.strftime(fmt), hi.strftime(fmt)


class ManualChecklistVerifier(PortalVerifier):
    """Default verifier: a precise presenter checklist generated from the run ledger."""

    def verify(self, cfg: Config, assets: list[Asset], events: list[dict[str, Any]]) -> dict[str, Any]:
        dns_events = [e for e in events if e.get("kind") == "dns"]
        td_events = [e for e in events if e.get("kind") == "threat-defense"]
        dhcp_events = [e for e in events if e.get("kind") == "dhcp"]
        lo, hi = _window(events, cfg.reporting.verification_buffer_minutes)
        by_id = {a.asset_id: a for a in assets}

        md: list[str] = ["# Portal verification checklist", ""]
        md += [f"Search window (UTC): **{lo}** to **{hi}**", ""]
        if cfg.infrastructure.type == "mock":
            md += ["> Mock infrastructure was used: nothing reached the Infoblox portal. "
                   "This checklist is a rehearsal of what you would verify on a real tenant.", ""]
        elif cfg.dns.source_mode == "edns":
            md += ["> `dns.source_mode: edns`: queries carry the asset IP/MAC as EDNS options. The portal "
                   "shows asset IPs **only if** your NIOS/NIOS-X forwarder has *Add/Copy client IP, MAC "
                   "addresses, and DNS View name* enabled; otherwise activity appears under the "
                   "generator host IP. Confirm with a packet capture (options 65523/65524).", ""]
        elif cfg.dns.source_mode == "direct":
            md += ["> `dns.source_mode: direct`: DNS activity is attributed to the **generator host IP**, "
                   "not the asset IPs. Filter by that IP, or use `bind` mode (see docs/architecture.md).",
                   ""]

        md += ["## Assets in scope", "", "| Asset | Hostname | IP | MAC | DNS queries | DHCP ops |",
               "|---|---|---|---|---|---|"]
        dns_counts: dict[str, int] = {}
        for e in dns_events + td_events:
            for aid, n in (e.get("by_asset") or {}).items():
                dns_counts[aid] = dns_counts.get(aid, 0) + n
        dhcp_ok: dict[str, list[str]] = {}
        for e in dhcp_events:
            dhcp_ok.setdefault(e["asset_id"], []).append(f"{e['operation']}{'' if e.get('ok') else '(failed)'}")
        for aid in sorted(set(dns_counts) | set(dhcp_ok)):
            a = by_id.get(aid)
            md.append(f"| {aid} | {a.hostname if a else '-'} | {(', '.join(a.ips) or a.ip) if a else '-'} | "
                      f"{a.mac if a else '-'} | {dns_counts.get(aid, 0)} | "
                      f"{', '.join(dhcp_ok.get(aid, [])) or '-'} |")

        md += ["", "## 1. Assets (Universal Asset Insights)",
               "- Open the asset inventory and confirm the assets above are present with matching "
               "IP/MAC/hostname (third-party discovery source).", ""]
        md += ["## 2. DHCP", "- Confirm leases/lease activity for the MACs above (portal DHCP lease views; "
               "the internal test plan expects leases to be visible in the portal and DHCP load to "
               "populate Monitor metrics).", ""]
        md += ["## 3. DNS activity",
               "- Monitor > DNS Activity: confirm query volume in the window above "
               "(internal test plan DDI-04: DNS Activity populates in Monitor).", ""]
        if dns_events:
            md += ["| Profile | Server | Total | Answered | Failed | RCODEs |", "|---|---|---|---|---|---|"]
            for e in dns_events:
                md.append(f"| {e['label']} | {e['dns_server']} | {e['total']} | {e['answered']} | "
                          f"{e['failed']} | {e.get('rcodes')} |")
            md.append("")

        zone_events = [e for e in dns_events if e.get("label") == "zone-test"]
        if zone_events:
            md += ["### Internal-domain (test zone) queries", "",
                   "Names below belong to zones created by this tool. If the DNS server is authoritative "
                   "for them they are answered locally; whether they appear in DNS Activity depends on the "
                   "Internal Domains / DFP settings (see docs/zone-testing.md). Observe, do not assume.", ""]
            for e in zone_events:
                for dom, n in sorted((e.get("by_domain") or {}).items()):
                    md.append(f"- `{dom}` x{n}")
            md.append("")

        md += ["## 4. Threat Defense", ""]
        if td_events:
            md += ["- Security Activity and Threat Intel reports: confirm events for the domains below "
                   "(internal test plan TD-04). Whether each is blocked/logged depends on your policy.",
                   "- SOC Insights (needs the SOC Insights SKU): confirm insights are generated from the "
                   "test traffic (TD-07). Insight generation can lag; do not expect it instantly.", ""]
            for e in td_events:
                md += [f"### Scenario `{e['label']}` ({e['total']} queries, {e['started']})", ""]
                forward = {d: n for d, n in (e.get("by_domain") or {}).items()
                           if not d.endswith(".arpa")}  # PTR lookups of asset IPs are just noise here
                for dom, n in sorted(forward.items(), key=lambda kv: -kv[1])[:15]:
                    md.append(f"- `{dom}` x{n}")
                for note in e.get("notes", []):
                    if note.startswith("expected actions"):
                        md.append(f"- {note}")
                md.append("")
        else:
            md += ["- No Threat Defense scenarios were run.", ""]

        md += ["## Notes",
               "- Portal ingestion is not instant; if nothing shows, widen the window and retry after a "
               "few minutes before concluding anything is broken.",
               "- Menu names are taken from internal test plans and may differ in your portal build."]
        return {"status": "manual", "markdown": "\n".join(md) + "\n", "window": [lo, hi]}
