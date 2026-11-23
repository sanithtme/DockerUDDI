"""Domain entries and selectors.

Threat-related domains are NEVER hard-coded in this project. They must be supplied via the
``threat_defense.domains`` config list for the demo tenant.
"""
from __future__ import annotations

import ipaddress
import random
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Iterable

from demo_core.errors import ConfigError
from demo_core.models import Asset

_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
_HOSTNAME = re.compile(rf"^(?:{_LABEL}\.)+{_LABEL}\.?$", re.IGNORECASE)
PLACEHOLDER_MARKER = "replace-me"


@dataclass(frozen=True)
class DomainEntry:
    name: str
    category: str = "default"
    expected_action: str | None = None  # presenter-facing label from config, not verified here
    note: str | None = None


def parse_domain_entries(raw: Iterable[Any], where: str, allow_placeholder: bool = False) -> list[DomainEntry]:
    entries: list[DomainEntry] = []
    for i, item in enumerate(raw or []):
        if isinstance(item, str):
            name, category, action, note = item, "default", None, None
        elif isinstance(item, dict):
            unknown = set(item) - {"name", "category", "expected_action", "note"}
            if unknown:
                raise ConfigError(f"{where}[{i}]: unknown key(s) {sorted(unknown)}")
            name = item.get("name")
            category = item.get("category", "default")
            action, note = item.get("expected_action"), item.get("note")
        else:
            raise ConfigError(f"{where}[{i}]: expected string or mapping")
        if not isinstance(name, str) or not name.strip():
            raise ConfigError(f"{where}[{i}]: missing domain name")
        name = name.strip().lower().rstrip(".")
        try:
            ipaddress.ip_address(name)
            raise ConfigError(f"{where}[{i}]: {name!r} is an IP literal, not a domain")
        except ValueError:
            pass
        if not _HOSTNAME.match(name):
            raise ConfigError(f"{where}[{i}]: {name!r} is not a valid domain name")
        if PLACEHOLDER_MARKER in name and not allow_placeholder:
            raise ConfigError(
                f"{where}[{i}]: {name!r} is still a placeholder. Replace it with a domain that is "
                "explicitly approved for your Threat Defense demo tenant."
            )
        entries.append(DomainEntry(name, str(category).lower(), action, note))
    return entries


class DomainSelector(ABC):
    @abstractmethod
    def pick(self, rng: random.Random, asset: Asset) -> tuple[str, str]:
        """Return ``(domain, category)``."""

    @abstractmethod
    def describe(self) -> list[DomainEntry]:
        """All entries this selector may return (for reports)."""


class StaticDomainSelector(DomainSelector):
    def __init__(self, entries: list[DomainEntry]):
        if not entries:
            raise ConfigError("domain selector needs at least one domain")
        self.entries = entries

    def pick(self, rng: random.Random, asset: Asset) -> tuple[str, str]:
        e = rng.choice(self.entries)
        return e.name, e.category

    def describe(self) -> list[DomainEntry]:
        return list(self.entries)


class WeightedSelector(DomainSelector):
    def __init__(self, parts: list[tuple[float, DomainSelector]]):
        parts = [(w, s) for w, s in parts if w > 0]
        if not parts:
            raise ConfigError("weighted selector needs at least one part with weight > 0")
        self.parts = parts
        self._weights = [w for w, _ in parts]

    def pick(self, rng: random.Random, asset: Asset) -> tuple[str, str]:
        sel = rng.choices([s for _, s in self.parts], weights=self._weights, k=1)[0]
        return sel.pick(rng, asset)

    def describe(self) -> list[DomainEntry]:
        out: list[DomainEntry] = []
        for _, s in self.parts:
            out.extend(s.describe())
        return out


def load_domain_file(path: str) -> list[DomainEntry]:
    """Load domains from a JSON list or {"domains": [...]} file."""
    import json
    from pathlib import Path
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot load dns.domains_file {path!r}: {exc}") from None
    if isinstance(raw, dict):
        raw = raw.get("domains", [])
    if not isinstance(raw, list):
        raise ConfigError("dns.domains_file must be a JSON list or an object with a 'domains' list")
    return parse_domain_entries(raw, "dns.domains_file")


class AssetMappedDomainSelector(DomainSelector):
    """Stable per-asset domain assignment; cycles when assets outnumber domains."""
    def __init__(self, entries: list[DomainEntry]):
        if not entries:
            raise ConfigError("domain selector needs at least one domain")
        self.entries = entries
        self._index: dict[str, int] = {}

    def pick(self, rng: random.Random, asset: Asset) -> tuple[str, str]:
        if asset.asset_id not in self._index:
            self._index[asset.asset_id] = len(self._index) % len(self.entries)
        e = self.entries[self._index[asset.asset_id]]
        return e.name, e.category

    def describe(self) -> list[DomainEntry]:
        return list(self.entries)
