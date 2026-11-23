"""Client for the Infoblox Universal Asset Insights public API.

Request  : ``POST {base_url}/api/v1/assets/search``
Auth     : ``Authorization: token <API key>`` (key read from an environment variable)
Body     : ``{"filter"?, "category"?, "fields"?, "page_size", "page_token"?, "sync": {"mode": "FULL"}}``
Response : ``{"data": [asset...], "pagination": {"page_size","returned","snapshot_at",
             "next_page_token"}}``; keep calling with ``page_token`` until it is null.
Errors   : ``{"error": {"status","code","message","details":[...],"request_id"}}``;
           429 carries ``RateLimit-Reset`` (epoch seconds).

Sources (internal): "Asset Inventory Public API" design doc (sections 4.1.1, 4.7, 4.8) and the
Service Graph Connector for Universal Asset Insights guides (API key header, tenant base URL).
The design doc lists ``Bearer <JWT>``; the connector guides use ``token <API key>``. Use
``asset_source.auth_scheme`` to switch, and confirm with ``demo discover --probe``.
"""
from __future__ import annotations

import json
import logging
import os
import random
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

from demo_core.config import AssetSourceConfig
from demo_core.errors import AssetSourceError
from demo_core.models import Asset

from .normalize import IPPolicy, _as_list, _ref_id, dedupe_assets, normalize_asset

log = logging.getLogger(__name__)


@dataclass
class DiscoveryResult:
    assets: list[Asset]
    raw_count: int = 0
    pages: int = 0
    duplicates_merged: int = 0
    skipped_deleted: int = 0
    skipped_provider: int = 0
    skipped_unidentifiable: int = 0
    invalid_ip: int = 0
    invalid_mac: int = 0
    retries: int = 0
    snapshot_at: str | None = None
    truncated: bool = False  # stopped at asset_source.max_assets
    warnings: list[str] = field(default_factory=list)

    @property
    def dns_eligible(self) -> int:
        return sum(1 for a in self.assets if a.dns_eligible)

    @property
    def dhcp_eligible(self) -> int:
        return sum(1 for a in self.assets if a.dhcp_eligible)

    @property
    def ip_count(self) -> int:
        """Distinct usable IPs across all assets."""
        return len({ip for a in self.assets for ip in (a.ips or ([a.ip] if a.ip else []))})

    @property
    def ip_total(self) -> int:
        """IP entries before de-duplication (an address shared by several assets counts each time)."""
        return sum(len(a.ips or ([a.ip] if a.ip else [])) for a in self.assets)


def _error_text(body: bytes) -> str:
    """Render the documented error envelope compactly; fall back to raw text."""
    try:
        err = json.loads(body).get("error", {})
        parts = [f"{err.get('code', '')}: {err.get('message', '')}".strip(": ")]
        for d in err.get("details") or []:
            parts.append(f"{d.get('field', '')} {d.get('code', '')} {d.get('message', '')}".strip())
        if err.get("request_id"):
            parts.append(f"request_id={err['request_id']}")
        return "; ".join(p for p in parts if p)
    except (ValueError, AttributeError):
        return body[:200].decode("utf-8", "replace")


class AssetInsightsClient:
    def __init__(self, cfg: AssetSourceConfig, sleep: Callable[[float], None] = time.sleep,
                 rng: random.Random | None = None, now: Callable[[], float] = time.time):
        if not cfg.base_url:
            raise AssetSourceError(
                "asset_source.base_url is empty. Set it to your Infoblox tenant URL "
                "(for example https://<your-tenant>.<domain>).")
        parsed = urllib.parse.urlparse(cfg.base_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise AssetSourceError(f"asset_source.base_url {cfg.base_url!r} is not a valid http(s) URL")
        self.cfg, self._sleep, self._now = cfg, sleep, now
        self._rng = rng or random.Random()
        self.retries = 0
        self._policy = IPPolicy(cfg.ip_selection)
        self._providers = {p.strip().lower() for p in cfg.providers if p.strip()}
        self._ssl: ssl.SSLContext | None = None
        if parsed.scheme == "https" and not cfg.verify_tls:
            log.warning("TLS verification disabled for the Asset Insights API (verify_tls=false)")
            self._ssl = ssl._create_unverified_context()  # noqa: SLF001 - explicit opt-out
        self.url = cfg.base_url.rstrip("/") + "/" + cfg.search_path.lstrip("/")

    # ------------------------------------------------------------------ HTTP
    def _headers(self) -> dict[str, str]:
        key = os.environ.get(self.cfg.api_key_env)
        if not key:
            raise AssetSourceError(
                f"environment variable {self.cfg.api_key_env} is not set. Export your Infoblox API "
                "key (portal: Profile > User API Keys, or a service-user key) before running.")
        headers = {"Authorization": f"{self.cfg.auth_scheme} {key}".strip(),
                   "Content-Type": "application/json", "Accept": "application/json",
                   "User-Agent": "asset-insights-ddi-demo/0.2.0"}
        if self.cfg.client_id:
            headers["X-Client-Id"] = self.cfg.client_id
        return headers

    def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        retry = self.cfg.retry
        payload = json.dumps(body).encode()
        last = "unknown error"
        for attempt in range(1, retry.max_attempts + 1):
            req = urllib.request.Request(self.url, data=payload, headers=self._headers(), method="POST")
            wait: float | None = None
            try:
                with urllib.request.urlopen(req, timeout=retry.timeout, context=self._ssl) as resp:
                    raw = resp.read()
                try:
                    return json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise AssetSourceError(f"{self.url}: response is not JSON: {exc}") from exc
            except urllib.error.HTTPError as exc:
                text = _error_text(exc.read() if exc.fp else b"")
                if exc.code in (401, 403):
                    raise AssetSourceError(
                        f"HTTP {exc.code} from {self.url} ({text or 'no detail'}). Check the API key, "
                        "that it has Asset Insights read permission (other Universal DDI API access "
                        "does not imply it), and auth_scheme (token vs Bearer).") from exc
                if exc.code == 404:
                    raise AssetSourceError(
                        f"HTTP 404 from {self.url}. Check base_url (tenant URL) and search_path.") from exc
                if exc.code not in retry.retry_statuses:
                    raise AssetSourceError(f"HTTP {exc.code} from {self.url}: {text}") from exc
                last = f"HTTP {exc.code} {text}".strip()
                wait = self._retry_wait(exc.headers)
            except (urllib.error.URLError, socket.timeout, ConnectionError, TimeoutError) as exc:
                last = str(getattr(exc, "reason", exc))
            if attempt == retry.max_attempts:
                break
            self.retries += 1
            delay = wait if wait is not None else min(
                retry.backoff_max, retry.backoff_base * 2 ** (attempt - 1)) * self._rng.uniform(0.5, 1.0)
            delay = min(delay, retry.backoff_max)
            log.warning("POST %s failed (%s); retry %d/%d in %.1fs", self.url, last, attempt,
                        retry.max_attempts - 1, delay)
            self._sleep(delay)
        raise AssetSourceError(f"{self.url}: giving up after {retry.max_attempts} attempts ({last})")

    def _retry_wait(self, headers: Any) -> float | None:
        """Honour Retry-After (seconds) or RateLimit-Reset (epoch seconds) on 429/503."""
        if not headers:
            return None
        ra = headers.get("Retry-After")
        if ra and ra.replace(".", "", 1).isdigit():
            return float(ra)
        reset = headers.get("RateLimit-Reset")
        if reset and reset.isdigit():
            return max(0.0, float(reset) - self._now())
        return None

    # ------------------------------------------------------------------ request/paging
    def request_body(self, page_token: str | None = None, page_size: int | None = None) -> dict[str, Any]:
        c = self.cfg
        body: dict[str, Any] = {"page_size": page_size or c.page_size}
        if c.filter:
            body["filter"] = c.filter
        if c.category:
            body["category"] = c.category
        if c.fields:
            body["fields"] = list(c.fields)
        if c.sync_mode:
            body["sync"] = {"mode": c.sync_mode}
        if page_token:
            body["page_token"] = page_token
        return body

    def fetch_pages(self) -> Iterator[dict[str, Any]]:
        """Yield each raw response page until ``next_page_token`` is null."""
        token: str | None = None
        seen: set[str] = set()
        for _ in range(self.cfg.max_pages):
            page = self._post(self.request_body(token))
            if not isinstance(page.get("data"), list):
                raise AssetSourceError(
                    f"unexpected response from {self.url}: no 'data' list (keys: {sorted(page)}). "
                    "Is search_path the Asset Insights search endpoint?")
            yield page
            token = (page.get("pagination") or {}).get("next_page_token")
            if not token:
                return
            if token in seen:
                raise AssetSourceError("pagination loop: server repeated a next_page_token")
            seen.add(token)
        raise AssetSourceError(f"stopped after asset_source.max_pages={self.cfg.max_pages}")

    # ------------------------------------------------------------------ discovery
    def discover(self) -> DiscoveryResult:
        result = DiscoveryResult(assets=[])
        self.retries = 0
        normalised: list[Asset] = []
        for page in self.fetch_pages():
            result.pages += 1
            result.snapshot_at = result.snapshot_at or (page.get("pagination") or {}).get("snapshot_at")
            for raw in page["data"]:
                if not isinstance(raw, dict):
                    continue
                result.raw_count += 1
                if raw.get("deleted_at"):  # deleted after the snapshot; not a live asset
                    result.skipped_deleted += 1
                    continue
                if self._providers:
                    seen = {str(v).lower() for item in _as_list(raw.get("providers"))
                            for v in ((item.get("id"), item.get("label")) if isinstance(item, dict)
                                      else (item,)) if v}
                    if not seen & self._providers:
                        result.skipped_provider += 1
                        continue
                asset = normalize_asset(raw, self.cfg.default_source, self._policy)
                if asset is None:
                    result.skipped_unidentifiable += 1
                    continue
                result.invalid_ip += sum(1 for e in asset.validation_errors if e.startswith("ip:"))
                result.invalid_mac += sum(1 for e in asset.validation_errors if e.startswith("mac:"))
                normalised.append(asset)
                if self.cfg.max_assets and len(normalised) >= self.cfg.max_assets:
                    result.truncated = True
                    break
            if result.truncated:
                result.warnings.append(f"stopped at asset_source.max_assets={self.cfg.max_assets}; "
                                       "more assets exist")
                break
        deduped = dedupe_assets(normalised, self.cfg.dedupe_by)
        result.duplicates_merged = len(normalised) - len(deduped)
        result.assets, result.retries = deduped, self.retries
        for a in deduped:
            if a.validation_errors:
                result.warnings.append(f"{a.asset_id}: " + "; ".join(a.validation_errors))
        return result

    def probe(self) -> dict[str, Any]:
        """One tiny request to validate URL, key, scheme and response shape."""
        page = self._post(self.request_body(page_size=1))
        rows = page.get("data") or []
        return {"url": self.url, "ok": True, "returned": len(rows),
                "pagination": page.get("pagination"),
                "record_keys": sorted(rows[0]) if rows and isinstance(rows[0], dict) else [],
                "sample": rows[0] if rows else None}
