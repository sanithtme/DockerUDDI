"""Normalise Asset Insights ``POST /api/v1/assets/search`` records into ``Asset``.

Record shape (internal "Asset Inventory Public API" design doc, section 4.1.1)::

    {"id": "asset-1", "name": "HOST1", "vendor": "Dell", "os": {"name","type","version"},
     "ip_addresses": ["192.168.1.10"], "mac_addresses": ["AA:BB:CC:DD:EE:FF"],
     "type": [{"id": "server", "label": "Server"}], "category": {"id": "devices", ...},
     "providers": [{"id": "crowdstrike", "label": "CrowdStrike"}], "tags": [], "source": "...",
     "first_seen": ..., "last_seen": ..., "deleted_at": null}

Only fields that are present are used; absent fields are normal ("applicable but not
collected", per the doc), never an error.
"""
from __future__ import annotations

import hashlib
import ipaddress
from typing import Any, Iterable

from demo_core.config import IPSelectionConfig
from demo_core.models import Asset, normalize_mac, utcnow_iso, validate_ip


def _ref_id(value: Any) -> str | None:
    """Reference items are ``{"id","label"}`` objects; tolerate plain strings."""
    if isinstance(value, dict):
        value = value.get("id") or value.get("label")
    return str(value) if value not in (None, "") else None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


class IPPolicy:
    """Decides which valid addresses may be used to generate traffic."""

    def __init__(self, cfg: IPSelectionConfig | None = None):
        cfg = cfg or IPSelectionConfig()
        self.private_only = cfg.private_only
        self.include = [ipaddress.ip_network(c, strict=False) for c in cfg.include_cidrs]
        self.exclude = [ipaddress.ip_network(c, strict=False) for c in cfg.exclude_cidrs]

    def reason_rejected(self, ip: str) -> str | None:
        addr = ipaddress.ip_address(ip)
        if any(addr in n for n in self.exclude if n.version == addr.version):
            return "excluded by ip_selection.exclude_cidrs"
        if self.include:
            if not any(addr in n for n in self.include if n.version == addr.version):
                return "outside ip_selection.include_cidrs"
        elif self.private_only and not addr.is_private:
            return "public address (ip_selection.private_only)"
        return None


def normalize_asset(raw: dict[str, Any], default_source: str = "third-party",
                    policy: IPPolicy | None = None) -> Asset | None:
    """Normalise one record. Returns ``None`` only if no identity can be derived."""
    policy = policy or IPPolicy()
    errors: list[str] = []
    excluded: list[str] = []

    ips: list[str] = []
    for item in _as_list(raw.get("ip_addresses")):
        try:
            ip = validate_ip(item)
        except ValueError as exc:
            errors.append(f"ip: {exc}")
            continue
        why = policy.reason_rejected(ip)
        if why:
            excluded.append(f"{ip} ({why})")
        elif ip not in ips:
            ips.append(ip)
    ips.sort(key=lambda s: (ipaddress.ip_address(s).version, ipaddress.ip_address(s)))
    ipv4 = next((i for i in ips if ":" not in i), None)
    ipv6 = next((i for i in ips if ":" in i), None)

    macs: list[str] = []
    for item in _as_list(raw.get("mac_addresses")):
        try:
            mac = normalize_mac(item)
        except ValueError as exc:
            errors.append(f"mac: {exc}")
            continue
        if mac not in macs:
            macs.append(mac)

    name = raw.get("name")
    hostname = str(name).strip().lower() if name else None

    asset_id = raw.get("id")
    if asset_id in (None, ""):
        basis = (macs[0] if macs else None) or ipv4 or ipv6 or hostname
        if basis is None:
            return None
        asset_id = "derived-" + hashlib.sha1(basis.encode()).hexdigest()[:10]
        errors.append("id: not supplied by the API, derived from address/hostname")

    types = [t for t in (_ref_id(x) for x in _as_list(raw.get("type"))) if t]
    device_type = (types[0] if types else None) or (str(raw["display_type"]).lower()
                                                    if raw.get("display_type") else None)
    os_val = raw.get("os")
    os_name = os_val.get("name") if isinstance(os_val, dict) else (str(os_val) if os_val else None)
    providers = [p for p in (_ref_id(x) for x in _as_list(raw.get("providers"))) if p]
    tags = [str(t) for t in _as_list(raw.get("tags"))]

    metadata: dict[str, Any] = {k: raw[k] for k in
                                ("category", "display_type", "managed", "location", "last_sync",
                                 "dhcp_fingerprint", "cidrs", "deleted_at") if raw.get(k) is not None}
    if isinstance(os_val, dict) and os_val.get("type"):
        metadata["os_type"] = os_val["type"]
    if excluded:
        metadata["excluded_ips"] = excluded
    now = utcnow_iso()
    return Asset(
        asset_id=str(asset_id).strip(), hostname=hostname, ip=ipv4 or ipv6, ipv4=ipv4, ipv6=ipv6,
        mac=macs[0] if macs else None, ips=ips, macs=macs, device_type=device_type,
        vendor=raw.get("vendor"), os=os_name, source=default_source,
        discovery_source=",".join(providers) or raw.get("source"), tags=tags, metadata=metadata,
        validation_errors=errors, first_seen=raw.get("first_seen") or now,
        last_seen=raw.get("last_seen") or now,
    )


# --------------------------------------------------------------------------- dedupe
def _merge(a: Asset, b: Asset) -> Asset:
    """Merge two records for the same device. ``b`` (later in the feed) wins on conflicts."""
    out = Asset.from_dict(a.to_dict())
    for fname in ("hostname", "ip", "ipv4", "ipv6", "mac", "device_type", "vendor", "os",
                  "discovery_source"):
        bv = getattr(b, fname)
        if bv:
            setattr(out, fname, bv)
    out.ips = sorted(set(a.ips) | set(b.ips))
    out.macs = sorted(set(a.macs) | set(b.macs))
    out.tags = sorted(set(a.tags) | set(b.tags))
    out.metadata = {**a.metadata, **b.metadata}
    out.validation_errors = sorted(set(a.validation_errors) | set(b.validation_errors))
    out.first_seen = min(filter(None, [a.first_seen, b.first_seen]), default=None)
    out.last_seen = max(filter(None, [a.last_seen, b.last_seen]), default=None)
    out.asset_id = min(a.asset_id, b.asset_id)
    return out


def dedupe_assets(assets: Iterable[Asset], by: Iterable[str] = ("asset_id",)) -> list[Asset]:
    """Collapse records describing the same device (union-find, so chains merge).

    ``by`` may contain ``asset_id``, ``mac``, ``ip``. The API already de-duplicates across
    providers, so only ``asset_id`` is on by default. ``mac``/``ip`` are opt-in: DHCP reuse and
    shared addresses can legitimately map different assets to one value.
    """
    keys = [k for k in by if k in ("asset_id", "mac", "ip")]
    items = list(assets)
    parent = list(range(len(items)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    seen: dict[tuple[str, str], int] = {}
    for idx, asset in enumerate(items):
        for key in keys:
            val = getattr(asset, key)
            if not val:
                continue
            token = (key, val)
            if token in seen:
                parent[find(idx)] = find(seen[token])
            else:
                seen[token] = idx

    groups: dict[int, list[int]] = {}
    for idx in range(len(items)):
        groups.setdefault(find(idx), []).append(idx)

    merged: list[Asset] = []
    for members in groups.values():
        acc = items[members[0]]
        for m in members[1:]:
            acc = _merge(acc, items[m])
        merged.append(acc)
    merged.sort(key=lambda a: a.asset_id)
    return merged
