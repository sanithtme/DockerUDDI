"""Create, verify and tear down test zones, and query them as discovered assets.

Safety model
------------
* Only zones listed in ``zones.zones`` are ever touched, and every zone/record this tool creates
  carries the tag ``ManagedBy=<zones.managed_tag>``. Destroy refuses anything without that tag.
* A zone that already exists but was NOT created by this tool is never modified.
* Zone names must end in one of ``zones.allowed_suffixes`` (reserved/private TLDs by default).
  Creating an authoritative zone for a real domain such as ``example.com`` would make your DNS
  server answer for it and break resolution for its clients, so that is refused.

Verified against internal docs: POST dns/auth_zone, POST/PATCH dns/record, GET filters
(``fqdn==``, ``name_in_zone== and zone== and type==``, ``tags.ManagedBy==``), ``internal_secondaries``
host refs (``dns/host/<id>``), ``nsgs``, record ``rdata`` for A (``address``) and MX
(``preference``, ``exchange``). Other record types' ``rdata`` follow the same pattern but have
NOT been verified: put the shape from your API docs (``<tenant>/apidoc``) in the config; the API's
error text is reported verbatim if it disagrees.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from demo_core.config import Config
from demo_core.errors import ConfigError, DemoError
from demo_core.models import Asset, utcnow_iso
from generators import dnswire
from generators.dns import DNSRunSettings, DNSTrafficGenerator, RunSummary, expand_ip_streams

from .client import DdiApiError, DdiClient

TAG_KEY = "ManagedBy"
SUPPORTED_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "SRV", "NS", "PTR", "CAA")
_LABEL = re.compile(r"^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")


@dataclass(frozen=True)
class RecordSpec:
    name: str
    type: str
    rdata: dict[str, Any]
    ttl: int | None = None
    comment: str | None = None


@dataclass(frozen=True)
class ZoneSpec:
    fqdn: str  # always with trailing dot
    comment: str | None
    records: tuple[RecordSpec, ...]

    def absolute(self, rec: RecordSpec) -> str:
        return f"{rec.name}.{self.fqdn.rstrip('.')}"


def _q(value: str) -> str:
    if '"' in value or "\\" in value:
        raise ConfigError(f"unsupported character in value {value!r}")
    return value


def parse_zone_specs(cfg: Config) -> list[ZoneSpec]:
    z = cfg.zones
    suffixes = [s.lower() if s.endswith(".") else s.lower() + "." for s in z.allowed_suffixes]
    specs: list[ZoneSpec] = []
    for i, raw in enumerate(z.zones):
        where = f"zones.zones[{i}]"
        if not isinstance(raw, dict) or not raw.get("fqdn"):
            raise ConfigError(f"{where}: needs 'fqdn'")
        unknown = set(raw) - {"fqdn", "comment", "records"}
        if unknown:
            raise ConfigError(f"{where}: unknown key(s) {sorted(unknown)}")
        fqdn = str(raw["fqdn"]).strip().lower()
        fqdn = fqdn if fqdn.endswith(".") else fqdn + "."
        if not all(_LABEL.match(p) for p in fqdn.rstrip(".").split(".")):
            raise ConfigError(f"{where}: {fqdn!r} is not a valid zone name")
        if not any(("." + fqdn).endswith(sfx) for sfx in suffixes):
            raise ConfigError(
                f"{where}: zone {fqdn!r} does not end in an allowed suffix {suffixes}. Creating an "
                "authoritative zone for a real domain would make your DNS server answer for it "
                "and break resolution for its clients. Use a private name (for example "
                "demo.internal.) or extend zones.allowed_suffixes deliberately.")
        recs: list[RecordSpec] = []
        for j, r in enumerate(raw.get("records") or []):
            rw = f"{where}.records[{j}]"
            if not isinstance(r, dict):
                raise ConfigError(f"{rw}: expected a mapping")
            bad = set(r) - {"name", "type", "rdata", "ttl", "comment"}
            if bad:
                raise ConfigError(f"{rw}: unknown key(s) {sorted(bad)}")
            name, rtype = str(r.get("name", "")).strip().lower(), str(r.get("type", "")).upper()
            if not name or name == "@" or not all(_LABEL.match(p) for p in name.split(".")):
                raise ConfigError(f"{rw}: 'name' must be a non-empty relative name (apex records are "
                                  "not supported by this tool)")
            if rtype not in SUPPORTED_TYPES:
                raise ConfigError(f"{rw}: type {rtype!r} not in {SUPPORTED_TYPES}")
            if not isinstance(r.get("rdata"), dict) or not r["rdata"]:
                raise ConfigError(f"{rw}: 'rdata' must be a mapping, e.g. {{address: 10.0.0.1}} for A")
            recs.append(RecordSpec(name, rtype, dict(r["rdata"]), r.get("ttl"), r.get("comment")))
        specs.append(ZoneSpec(fqdn, raw.get("comment"), tuple(recs)))
    return specs


@dataclass
class ApplyResult:
    zones_created: list[str] = field(default_factory=list)
    zones_existing: list[str] = field(default_factory=list)
    records_created: list[str] = field(default_factory=list)
    records_updated: list[str] = field(default_factory=list)
    records_unchanged: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    dry_run: bool = False


@dataclass
class VerifyRow:
    zone: str
    name: str
    type: str
    expect: str
    rcode: str = "-"
    aa: bool | None = None
    answers: int | None = None
    ok: bool = False


class ZoneManager:
    def __init__(self, cfg: Config, client: DdiClient | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic):
        self.cfg, self.z = cfg, cfg.zones
        self.specs = parse_zone_specs(cfg)
        if not self.specs:
            raise ConfigError("no zones configured: add entries under zones.zones")
        self.client = client or DdiClient(cfg)
        self._sleep, self._clock = sleep, clock
        self.dns_host = self._resolve_dns_host() if not self.z.nsg else None

    # ------------------------------------------------------------------ lookups
    def _tags(self) -> dict[str, str]:
        return {TAG_KEY: self.z.managed_tag}

    def _is_ours(self, obj: dict[str, Any]) -> bool:
        return (obj.get("tags") or {}).get(TAG_KEY) == self.z.managed_tag

    def _resolve_dns_host(self) -> str:
        """Return an explicit DNS host id or resolve dns.server to exactly one dns/host object."""
        if self.z.dns_host:
            return self.z.dns_host
        server = self.cfg.dns.server
        if not server:
            raise ConfigError("set dns.server (recommended) or zones.dns_host before provisioning zones")
        rows = self.client.list("dns/host")
        matches = [r for r in rows if str(r.get("address") or "").strip() == str(server).strip()]
        if not matches:
            raise DdiApiError(
                f"no DNS host has address {server!r}. Set dns.server to the NIOS-X DNS address, "
                "or set zones.dns_host explicitly; 'demo zones hosts' can be used for diagnostics.")
        if len(matches) > 1:
            ids = ", ".join(str(r.get("id")) for r in matches)
            raise DdiApiError(
                f"multiple DNS hosts have address {server!r}: {ids}. Set zones.dns_host explicitly.")
        host_id = str(matches[0].get("id") or "")
        if not host_id.startswith("dns/host/"):
            raise DdiApiError(f"DNS host matched {server!r} but returned invalid id {host_id!r}")
        return host_id

    def _view_id(self) -> str | None:
        if not self.z.view:
            return None
        rows = self.client.list("dns/view", f'name=="{_q(self.z.view)}"')
        if not rows:
            raise DdiApiError(f"DNS view {self.z.view!r} not found (zones.view is a view NAME)")
        return rows[0]["id"]

    def _assignment(self) -> dict[str, Any]:
        if self.dns_host:
            return {"internal_secondaries": [{"host": self.dns_host}]}
        if self.z.nsg:
            rows = self.client.list("dns/auth_nsg", f"(name=='{_q(self.z.nsg)}')")
            if not rows:
                raise DdiApiError(f"name server group {self.z.nsg!r} not found")
            return {"nsgs": [rows[0]["id"]]}
        return {}

    def _find_zone(self, fqdn: str, view_id: str | None) -> dict[str, Any] | None:
        rows = self.client.list("dns/auth_zone", f'fqdn=="{_q(fqdn.rstrip("."))}"')
        for r in rows:
            if r.get("fqdn", "").rstrip(".").lower() == fqdn.rstrip(".") and (
                    not view_id or r.get("view") == view_id):
                return r
        return None

    def _find_records(self, zone_id: str, rec: RecordSpec) -> list[dict[str, Any]]:
        flt = (f'name_in_zone=="{_q(rec.name)}" and zone=="{_q(zone_id)}" and type=="{rec.type}"')
        return self.client.list("dns/record", flt)

    @staticmethod
    def _same_rdata(existing: dict[str, Any], want: dict[str, Any]) -> bool:
        have = existing.get("rdata") or {}
        return all(str(have.get(k)).rstrip(".") == str(v).rstrip(".") for k, v in want.items())

    # ------------------------------------------------------------------ apply
    def apply(self, dry_run: bool = False) -> ApplyResult:
        if not (self.dns_host or self.z.nsg):
            raise ConfigError("no DNS server assignment could be resolved")
        res = ApplyResult(dry_run=dry_run)
        view_id = self._view_id()
        assignment = self._assignment()
        for spec in self.specs:
            zone = self._find_zone(spec.fqdn, view_id)
            if zone is None:
                res.zones_created.append(spec.fqdn)
                if dry_run:
                    zone_id = "dns/auth_zone/<new>"
                else:
                    zone = self._create_zone(spec, view_id, assignment)
                    zone_id = zone["id"]
            else:
                if not self._is_ours(zone):
                    raise DdiApiError(
                        f"zone {spec.fqdn} already exists and was not created by this tool "
                        f"(no {TAG_KEY}={self.z.managed_tag} tag). Refusing to modify it. Pick another "
                        "zone name, or remove the zone yourself first.")
                res.zones_existing.append(spec.fqdn)
                zone_id = zone["id"]
                self._ensure_assignment(zone, assignment, res, dry_run)
            for rec in spec.records:
                label = f"{spec.absolute(rec)} {rec.type}"
                existing = [] if zone is None else self._find_records(zone_id, rec)
                if not existing:
                    res.records_created.append(label)
                    if not dry_run:
                        self._create_record(zone_id, rec)
                    continue
                match = next((e for e in existing if self._same_rdata(e, rec.rdata)), None)
                if match is not None:
                    res.records_unchanged.append(label)
                elif self._is_ours(existing[0]):
                    res.records_updated.append(label)
                    if not dry_run:
                        body: dict[str, Any] = {"rdata": rec.rdata}
                        if rec.ttl is not None:
                            body["ttl"] = rec.ttl
                        self.client.patch(existing[0]["id"], body)
                else:
                    res.notes.append(f"{label}: exists with different data and is not managed by this "
                                     "tool; left untouched")
        return res

    def _create_zone(self, spec: ZoneSpec, view_id: str | None, assignment: dict[str, Any]
                     ) -> dict[str, Any]:
        body: dict[str, Any] = {"fqdn": spec.fqdn, "tags": self._tags(), **assignment}
        if spec.comment:
            body["comment"] = spec.comment
        if view_id:
            body["view"] = view_id
        if self.z.primary_type:
            body["primary_type"] = self.z.primary_type
        try:
            return self.client.create("dns/auth_zone", body)
        except DdiApiError as exc:
            # Some environments treat primary_type as read-only (internal bug DDIDNS-11568).
            if exc.status == 400 and "primarytype" in str(exc).lower().replace("_", "") and \
                    "primary_type" in body:
                body.pop("primary_type")
                return self.client.create("dns/auth_zone", body)
            raise

    def _ensure_assignment(self, zone: dict[str, Any], assignment: dict[str, Any], res: ApplyResult,
                           dry_run: bool) -> None:
        if self.dns_host:
            have = [h.get("host") if isinstance(h, dict) else h for h in zone.get("internal_secondaries") or []]
            if self.dns_host not in have:
                res.notes.append(f"{zone.get('fqdn')}: assigning {self.dns_host}")
                if not dry_run:
                    keep = [{"host": h} for h in have if h]
                    self.client.patch(zone["id"], {"internal_secondaries": keep + assignment["internal_secondaries"]})
        elif self.z.nsg:
            want = assignment["nsgs"][0]
            if want not in (zone.get("nsgs") or []):
                res.notes.append(f"{zone.get('fqdn')}: assigning name server group {self.z.nsg}")
                if not dry_run:
                    self.client.patch(zone["id"], {"nsgs": list(zone.get("nsgs") or []) + [want]})

    def _create_record(self, zone_id: str, rec: RecordSpec) -> None:
        body: dict[str, Any] = {"name_in_zone": rec.name, "zone": zone_id, "type": rec.type,
                                "rdata": rec.rdata, "tags": self._tags()}
        if rec.ttl is not None:
            body["ttl"] = rec.ttl
        if rec.comment:
            body["comment"] = rec.comment
        self.client.create("dns/record", body)

    # ------------------------------------------------------------------ status / destroy
    def status(self) -> list[dict[str, Any]]:
        view_id = self._view_id()
        out = []
        for spec in self.specs:
            zone = self._find_zone(spec.fqdn, view_id)
            row: dict[str, Any] = {"zone": spec.fqdn, "exists": zone is not None, "managed": None,
                                   "id": None, "records_found": 0, "records_expected": len(spec.records),
                                   "assigned": None}
            if zone:
                row.update(managed=self._is_ours(zone), id=zone["id"],
                           assigned=[h.get("host") if isinstance(h, dict) else h
                                     for h in zone.get("internal_secondaries") or []] or zone.get("nsgs"))
                row["records_found"] = sum(1 for r in spec.records if self._find_records(zone["id"], r))
            out.append(row)
        return out

    def destroy(self, dry_run: bool = False) -> dict[str, list[str]]:
        view_id = self._view_id()
        done: dict[str, list[str]] = {"zones_deleted": [], "records_deleted": [], "absent": [], "errors": []}
        for spec in self.specs:
            zone = self._find_zone(spec.fqdn, view_id)
            if zone is None:
                done["absent"].append(spec.fqdn)
                continue
            if not self._is_ours(zone):
                raise DdiApiError(f"zone {spec.fqdn} was not created by this tool; refusing to delete it")
            recs = self.client.list("dns/record",
                                    f'zone=="{_q(zone["id"])}" and tags.{TAG_KEY}=="{_q(self.z.managed_tag)}"')
            for r in recs:
                label = f"{r.get('name_in_zone') or r.get('absolute_name_spec')} {r.get('type')}"
                if not dry_run:
                    try:
                        self.client.delete(r["id"])
                    except DdiApiError as exc:
                        done["errors"].append(f"{label}: {exc}")
                        continue
                done["records_deleted"].append(label)
            if not dry_run:
                try:
                    self.client.delete(zone["id"])
                except DdiApiError as exc:
                    done["errors"].append(f"{spec.fqdn}: {exc}")
                    continue
            done["zones_deleted"].append(spec.fqdn)
        return done

    # ------------------------------------------------------------------ authoritative check
    def _expectations(self) -> list[VerifyRow]:
        rows: list[VerifyRow] = []
        for spec in self.specs:
            for rec in spec.records:
                rows.append(VerifyRow(spec.fqdn, spec.absolute(rec), rec.type, "answer"))
            for neg in self.z.negative_names:
                rows.append(VerifyRow(spec.fqdn, f"{neg}.{spec.fqdn.rstrip('.')}", "A", "nxdomain"))
        return rows

    def verify(self, server: str, port: int = 53, wait: float | None = None, timeout: float = 2.0,
               interval: float = 3.0) -> list[VerifyRow]:
        """Ask ``server`` directly. A record passes when it answers NOERROR with data and the AA
        (authoritative) flag; a negative name passes on NXDOMAIN with AA. Polls up to ``wait`` seconds
        because the zone takes a little while to reach the DNS server."""
        deadline = self._clock() + (self.z.wait_seconds if wait is None else wait)
        rows = self._expectations()
        while True:
            for row in rows:
                if row.ok:
                    continue
                r = dnswire.resolve(server, port, row.name, row.type, timeout)
                row.rcode, row.aa, row.answers = r.rcode_name, r.aa, r.ancount
                if row.expect == "answer":
                    row.ok = r.ok and r.rcode == 0 and bool(r.ancount) and bool(r.aa)
                else:
                    row.ok = r.ok and r.rcode == 3 and bool(r.aa)
            if all(r.ok for r in rows) or self._clock() >= deadline:
                return rows
            self._sleep(interval)

    # ------------------------------------------------------------------ internal-domain queries
    def query_as_assets(self, assets: list[Asset], settings: DNSRunSettings,
                        generator: DNSTrafficGenerator | None = None
                        ) -> tuple[list[dict[str, Any]], RunSummary]:
        """Send each zone record (and the negative names) once as each asset, one IP per asset."""
        gen = generator or DNSTrafficGenerator(self.cfg)
        started = utcnow_iso()
        rows: list[dict[str, Any]] = []
        by_domain: dict[str, int] = {}
        by_asset: dict[str, int] = {}
        by_qtype: dict[str, int] = {}
        rcodes: dict[str, int] = {}
        answered = failed = 0
        used: list[Asset] = []
        for asset in assets:
            streams = expand_ip_streams([asset])
            if not streams:
                continue
            chosen = streams[0]
            used.append(chosen)
            for exp in self._expectations():
                res = gen.send_one(chosen, exp.name, exp.type, settings)
                by_domain[exp.name] = by_domain.get(exp.name, 0) + 1
                by_asset[asset.asset_id] = by_asset.get(asset.asset_id, 0) + 1
                by_qtype[exp.type] = by_qtype.get(exp.type, 0) + 1
                if res.ok:
                    answered += 1
                    rcodes[res.rcode_name] = rcodes.get(res.rcode_name, 0) + 1
                else:
                    failed += 1
                rows.append({"asset": asset.asset_id, "ip": chosen.ip, "name": exp.name, "type": exp.type,
                             "expect": exp.expect, "rcode": res.rcode_name if res.ok else f"FAIL({res.error})",
                             "aa": res.aa, "answers": res.ancount, "ms": round(res.latency_ms, 1)})
        summary = RunSummary(
            kind="dns", label="zone-test", started=started, finished=utcnow_iso(),
            assets=[{"asset_id": a.asset_id, "hostname": a.hostname, "ip": a.ip, "mac": a.mac} for a in used],
            total=len(rows), answered=answered, failed=failed, rcodes=rcodes, by_qtype=by_qtype,
            by_domain=by_domain, by_asset=by_asset, dns_server=settings.server,
            source_mode=settings.source_mode, dry_run=settings.dry_run,
            notes=["internal-domain queries for zones this tool created; if the DNS server is "
                   "authoritative they are answered locally"])
        return rows, summary
