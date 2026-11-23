"""Fetch active threat domains from the Infoblox portal's TIDE and keep a reviewable snapshot.

* DNS-only use: the fetched names are only ever *queried* through your demo resolver, so that
  Threat Defense on that resolver observes them. Nothing is connected to or downloaded.
* Opt-in: ``threat_defense.tide.enabled`` must be true for scenarios to use the snapshot.
* Reviewable: ``demo td fetch`` writes ``state/tide_domains.json``; you can read/edit it before
  running scenarios. Scenarios never call TIDE themselves.
* A domain being in TIDE does not guarantee your policy blocks it: which feeds your policy
  enables decides that. Security Activity in the portal shows what actually happened.

Contract (internal "TIDENG APIs", "Infoblox Threat Defense - TIDE" and API getting-started docs):
``{"threat": [{"id", "type": "HOST", "host", "domain", "class", "property", "profile",
"threat_level", "detected", "expiration", ...}]}``; throttling 12,000 req/h and 5 req/s on
``/tide/api/data/threats``.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from demo_core.config import Config
from demo_core.errors import AssetSourceError, ConfigError
from demo_core.models import utcnow_iso

from .domains import DomainEntry, parse_domain_entries

log = logging.getLogger(__name__)


@dataclass
class TideResult:
    domains: list[DomainEntry]
    raw_count: int = 0
    skipped_invalid: int = 0
    duplicates: int = 0
    by_class: dict[str, int] = field(default_factory=dict)
    fetched_at: str = ""
    url: str = ""
    notes: dict[str, str] = field(default_factory=dict)  # domain -> "class/property level N"


def snapshot_path(cfg: Config) -> Path:
    return Path(cfg.reporting.state_dir) / "tide_domains.json"


class TideClient:
    def __init__(self, cfg: Config, sleep: Callable[[float], None] = time.sleep):
        self.cfg, self.t = cfg, cfg.threat_defense.tide
        self._sleep = sleep
        base = self.t.base_url or cfg.asset_source.base_url
        if not base.startswith(("http://", "https://")):
            raise ConfigError("set threat_defense.tide.base_url (or asset_source.base_url) to your "
                              "portal URL, e.g. https://<your-tenant>.<domain>")
        self.base = base.rstrip("/")
        self._ssl = ssl._create_unverified_context() if (  # noqa: SLF001 - explicit opt-out
            base.startswith("https") and not self.t.verify_tls) else None

    def url(self, limit: int | None = None) -> str:
        params: list[tuple[str, Any]] = [("type", "host"), ("rlimit", limit or self.t.limit),
                                         ("data_format", "json")]
        if self.t.classes:
            params.append(("class", ",".join(self.t.classes)))
        params += [("property", p) for p in self.t.properties]
        if self.t.profile:
            params.append(("profile", self.t.profile))
        return f"{self.base}/{self.t.path.lstrip('/')}?" + urllib.parse.urlencode(params, safe=",")

    def _get(self, url: str) -> dict[str, Any]:
        key = os.environ.get(self.t.api_key_env)
        if not key:
            raise AssetSourceError(f"environment variable {self.t.api_key_env} is not set")
        headers = {"Authorization": f"Token {key}", "Accept": "application/json",
                   "User-Agent": "asset-insights-ddi-demo/0.3"}
        last = "unknown error"
        for attempt in range(1, self.t.max_attempts + 1):
            req = urllib.request.Request(url, headers=headers)
            wait = None
            try:
                with urllib.request.urlopen(req, timeout=self.t.timeout, context=self._ssl) as resp:
                    return json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403):
                    raise AssetSourceError(
                        f"HTTP {exc.code} from TIDE. Check the API key; the TIDE Active Indicators "
                        "tool needs an entitlement (Advanced tier) and API access.") from exc
                if exc.code not in (429, 500, 502, 503, 504):
                    raise AssetSourceError(f"HTTP {exc.code} from TIDE ({url.split('?')[0]})") from exc
                last = f"HTTP {exc.code}"
                ra = exc.headers.get("Retry-After") if exc.headers else None
                wait = float(ra) if ra and ra.replace(".", "", 1).isdigit() else None
            except (urllib.error.URLError, socket.timeout, ConnectionError, TimeoutError) as exc:
                last = str(getattr(exc, "reason", exc))
            except json.JSONDecodeError as exc:
                raise AssetSourceError(f"TIDE returned non-JSON: {exc}") from exc
            if attempt == self.t.max_attempts:
                break
            delay = wait if wait is not None else min(30.0, 1.0 * 2 ** (attempt - 1))
            log.warning("TIDE GET failed (%s); retry %d in %.1fs", last, attempt, delay)
            self._sleep(delay)
        raise AssetSourceError(f"TIDE: giving up after {self.t.max_attempts} attempts ({last})")

    def fetch(self, limit: int | None = None) -> TideResult:
        url = self.url(limit)
        doc = self._get(url)
        rows = doc.get("threat")
        if not isinstance(rows, list):
            raise AssetSourceError(f"unexpected TIDE response (keys: {sorted(doc)}); expected 'threat' list")
        res = TideResult(domains=[], raw_count=len(rows), fetched_at=utcnow_iso(), url=url)
        seen: set[str] = set()
        classes: Counter[str] = Counter()
        for row in rows:
            name = (row.get("host") or row.get("domain")) if isinstance(row, dict) else None
            try:
                entry = parse_domain_entries([name], "tide")[0]
            except (ConfigError, IndexError):
                res.skipped_invalid += 1
                continue
            if entry.name in seen:
                res.duplicates += 1
                continue
            seen.add(entry.name)
            cls, prop = row.get("class") or "-", row.get("property") or "-"
            classes[str(cls)] += 1
            note = f"TIDE {cls}/{prop}" + (f" level {row['threat_level']}" if "threat_level" in row else "")
            res.notes[entry.name] = note
            res.domains.append(DomainEntry(entry.name, self.t.category.lower(), None, note))
        res.by_class = dict(classes)
        return res


def save_snapshot(cfg: Config, res: TideResult) -> Path:
    path = snapshot_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "fetched_at": res.fetched_at, "source": res.url.split("?")[0], "query": res.url.split("?", 1)[-1],
        "domains": [{"name": d.name, "category": d.category, "note": d.note} for d in res.domains],
    }, indent=2), encoding="utf-8")
    return path


def load_snapshot(cfg: Config) -> list[DomainEntry]:
    path = snapshot_path(cfg)
    if not path.exists():
        raise ConfigError(f"threat_defense.tide.enabled is true but {path} does not exist. "
                          "Run 'demo td fetch' first.")
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))["domains"]
    except (OSError, ValueError, KeyError) as exc:
        raise ConfigError(f"{path} is unreadable ({exc}); re-run 'demo td fetch'") from exc
    return parse_domain_entries(
        [{"name": r["name"], "category": r.get("category", "blocked"), "note": r.get("note")} for r in rows],
        str(path))
