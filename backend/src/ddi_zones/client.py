"""Small REST client for the Universal DDI API (dns/auth_zone, dns/record, dns/view, ...).

Base path ``/api/ddi/v1`` and ``Authorization: Token <key>`` are from internal KB articles. Error
bodies are ``{"error":[{"message": ...}]}`` (list form) or ``{"error":{"code","message"}}``.
Resource ids are full names such as ``dns/auth_zone/<uuid>`` and are addressed as
``/api/ddi/v1/<id>``.
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
from typing import Any, Callable

from demo_core.config import Config
from demo_core.errors import DemoError

log = logging.getLogger(__name__)
API_PREFIX = "/api/ddi/v1"


class DdiApiError(DemoError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def _error_text(body: bytes) -> str:
    try:
        err = json.loads(body).get("error")
    except (ValueError, AttributeError):
        return body[:200].decode("utf-8", "replace")
    if isinstance(err, list):
        return "; ".join(str(e.get("message", e)) if isinstance(e, dict) else str(e) for e in err)
    if isinstance(err, dict):
        return f"{err.get('code', '')}: {err.get('message', '')}".strip(": ")
    return str(err or body[:200])


class DdiClient:
    def __init__(self, cfg: Config, sleep: Callable[[float], None] = time.sleep, section: str = "zones"):
        z = getattr(cfg, section)  # "zones" or "ipam": both carry base_url/api_key_env/timeout/...
        base = z.base_url or cfg.asset_source.base_url
        if not base.startswith(("http://", "https://")):
            raise DdiApiError(f"set {section}.base_url (or asset_source.base_url) to your portal URL")
        self.base, self.z, self._sleep = base.rstrip("/"), z, sleep
        self._ssl = ssl._create_unverified_context() if (  # noqa: SLF001 - explicit opt-out
            base.startswith("https") and not z.verify_tls) else None

    def _headers(self) -> dict[str, str]:
        key = os.environ.get(self.z.api_key_env)
        if not key:
            raise DdiApiError(f"environment variable {self.z.api_key_env} is not set")
        return {"Authorization": f"Token {key}", "Content-Type": "application/json",
                "Accept": "application/json", "User-Agent": "asset-insights-ddi-demo/0.4"}

    def request(self, method: str, path: str, params: dict[str, Any] | None = None,
                body: dict[str, Any] | None = None) -> dict[str, Any]:
        path = path.lstrip("/")
        url = f"{self.base}{API_PREFIX}/{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        last = "unknown error"
        for attempt in range(1, self.z.max_attempts + 1):
            req = urllib.request.Request(url, data=data, headers=self._headers(), method=method)
            wait = None
            try:
                with urllib.request.urlopen(req, timeout=self.z.timeout, context=self._ssl) as resp:
                    raw = resp.read()
                return json.loads(raw) if raw.strip() else {}
            except urllib.error.HTTPError as exc:
                text = _error_text(exc.read() if exc.fp else b"")
                if exc.code in (401, 403):
                    raise DdiApiError(
                        f"HTTP {exc.code} on {method} {path} ({text or 'no detail'}). The API key needs a "
                        "DNS role (DDI DNS Operator or Manager); an Asset Insights-only key will not do.",
                        exc.code) from exc
                if exc.code not in (429, 500, 502, 503, 504):
                    raise DdiApiError(f"HTTP {exc.code} on {method} {path}: {text}", exc.code) from exc
                last = f"HTTP {exc.code} {text}".strip()
                ra = exc.headers.get("Retry-After") if exc.headers else None
                wait = float(ra) if ra and ra.replace(".", "", 1).isdigit() else None
            except (urllib.error.URLError, socket.timeout, ConnectionError, TimeoutError) as exc:
                last = str(getattr(exc, "reason", exc))
            except json.JSONDecodeError as exc:
                raise DdiApiError(f"non-JSON response from {method} {path}: {exc}") from exc
            if attempt == self.z.max_attempts:
                break
            self._sleep(wait if wait is not None else min(30.0, 1.0 * 2 ** (attempt - 1)))
        raise DdiApiError(f"{method} {path}: giving up after {self.z.max_attempts} attempts ({last})")

    # -- helpers
    def list(self, path: str, filter_expr: str | None = None, limit: int = 1000) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"_limit": limit}
        if filter_expr:
            params["_filter"] = filter_expr
        return list(self.request("GET", path, params).get("results") or [])

    def create(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        resp = self.request("POST", path, body=body)
        return resp.get("result", resp)

    def patch(self, resource_id: str, body: dict[str, Any]) -> dict[str, Any]:
        resp = self.request("PATCH", resource_id, body=body)
        return resp.get("result", resp)

    def delete(self, resource_id: str) -> None:
        self.request("DELETE", resource_id)
