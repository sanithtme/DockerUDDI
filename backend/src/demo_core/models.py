"""Internal asset model plus IP / MAC validation and normalisation."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_MAC_HEX = re.compile(r"^[0-9a-f]{12}$")


def normalize_mac(value: Any) -> str:
    """Return ``aa:bb:cc:dd:ee:ff`` or raise ``ValueError``.

    Accepts ``:``, ``-``, ``.`` separated or bare hex. Rejects all-zero, broadcast and
    multicast addresses because a DHCP client cannot legitimately use them.
    """
    if value is None:
        raise ValueError("empty MAC address")
    compact = re.sub(r"[:\-.\s]", "", str(value).strip().lower())
    if not _MAC_HEX.match(compact):
        raise ValueError(f"invalid MAC address {value!r}")
    if compact == "0" * 12:
        raise ValueError("all-zero MAC address")
    if compact == "f" * 12:
        raise ValueError("broadcast MAC address")
    if int(compact[0:2], 16) & 1:
        raise ValueError(f"multicast MAC address {value!r}")
    return ":".join(compact[i : i + 2] for i in range(0, 12, 2))


def validate_ip(value: Any, version: int | None = None) -> str:
    """Return the canonical text form of a usable unicast IP or raise ``ValueError``."""
    if value is None or str(value).strip() == "":
        raise ValueError("empty IP address")
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        raise ValueError(f"invalid IP address {value!r}") from None
    if version is not None and ip.version != version:
        raise ValueError(f"{value!r} is IPv{ip.version}, expected IPv{version}")
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local:
        raise ValueError(f"{value!r} is not a usable unicast address")
    if ip.version == 4 and ip.is_reserved:
        raise ValueError(f"{value!r} is a reserved IPv4 address")
    return str(ip)


@dataclass
class Asset:
    """Normalised asset. ``ip`` is the primary address used for traffic (IPv4 preferred)."""

    asset_id: str
    hostname: str | None = None
    ip: str | None = None
    ipv4: str | None = None
    ipv6: str | None = None
    mac: str | None = None
    ips: list[str] = field(default_factory=list)  # every validated, policy-selected address
    macs: list[str] = field(default_factory=list)  # every validated MAC
    device_type: str | None = None
    vendor: str | None = None
    os: str | None = None
    source: str = "third-party"
    discovery_source: str | None = None
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    validation_errors: list[str] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None

    @property
    def dns_eligible(self) -> bool:
        """True when a validated IP exists, i.e. DNS traffic may be generated."""
        return bool(self.ip)

    @property
    def dhcp_eligible(self) -> bool:
        """True when a validated MAC exists, i.e. DHCP activity may be generated."""
        return bool(self.mac)

    def to_core_dict(self) -> dict[str, Any]:
        """The minimal normalised shape from the project brief."""
        return {
            "asset_id": self.asset_id,
            "hostname": self.hostname,
            "ip": self.ip,
            "mac": self.mac,
            "device_type": self.device_type,
            "source": self.source,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "hostname": self.hostname,
            "ip": self.ip,
            "ipv4": self.ipv4,
            "ipv6": self.ipv6,
            "mac": self.mac,
            "ips": list(self.ips),
            "macs": list(self.macs),
            "device_type": self.device_type,
            "vendor": self.vendor,
            "os": self.os,
            "source": self.source,
            "discovery_source": self.discovery_source,
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
            "validation_errors": list(self.validation_errors),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Asset":
        known = {k: data[k] for k in cls.__dataclass_fields__ if k in data}
        known["ips"] = list(known.get("ips") or [])
        known["macs"] = list(known.get("macs") or [])
        known["tags"] = list(known.get("tags") or [])
        known["metadata"] = dict(known.get("metadata") or {})
        known["validation_errors"] = list(known.get("validation_errors") or [])
        return cls(**known)
