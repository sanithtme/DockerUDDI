"""Test-only fake of the Asset Insights public API (NOT shipped as a product feature).

Implements the documented contract: POST /api/v1/assets/search, `Authorization: token <key>`,
cursor pagination via pagination.next_page_token, the error envelope, and RateLimit-Reset on 429.
The real mock Asset Insights API lives in another repo; this only exists so unit tests are hermetic.
"""
from __future__ import annotations

import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

API_KEY = "test-key"


def ref(i, label=None):
    return {"id": i, "label": label or i.title()}


def build_records(count=12, extras=True):
    rows = []
    for i in range(1, count + 1):
        rows.append({
            "id": f"asset-{i:03d}", "name": f"Demo-Device-{i:03d}",
            "ip_addresses": [f"10.20.30.{100 + i}"], "mac_addresses": [f"02:00:00:00:00:{i:02X}"],
            "type": [ref("workstation")], "category": ref("devices"), "vendor": "Dell",
            "os": {"name": "Windows 11", "type": "Windows", "version": "11"},
            "providers": [ref("thirdparty-demo", "Third Party Demo")], "tags": ["demo"],
            "source": "thirdparty-demo", "first_seen": "2026-01-01T00:00:00Z",
            "last_seen": "2026-11-01T00:00:00Z", "deleted_at": None})
    if extras:
        rows += [
            # several addresses incl. a public one; dash-separated MAC
            {"id": "asset-multi", "name": "multi-nic", "ip_addresses": ["10.20.40.5", "10.20.40.6",
             "54.201.88.12"], "mac_addresses": ["7c-1e-52-59-f5-40"], "type": [ref("server")],
             "providers": [ref("AWS", "Amazon Web Services")]},
            # invalid IP + invalid MAC but one good IP
            {"id": "asset-bad", "name": "bad-data", "ip_addresses": ["999.1.1.1", "10.20.50.9"],
             "mac_addresses": ["not-a-mac"]},
            # deleted after the snapshot
            {"id": "asset-deleted", "name": "gone", "ip_addresses": ["10.20.70.1"],
             "mac_addresses": ["02:00:00:00:0F:0F"], "deleted_at": "2026-11-10T00:00:00Z"},
            # no MAC (DNS only)
            {"id": "asset-nomac", "name": "no-mac", "ip_addresses": ["10.20.60.1"]},
            # IPv6 only
            {"id": "asset-v6", "name": "v6-only", "ip_addresses": ["2001:db8::beef"],
             "mac_addresses": ["02:00:00:00:0F:01"]},
            # no addresses (DHCP only)
            {"id": "asset-noip", "name": "no-ip", "mac_addresses": ["02:00:00:00:0F:02"]},
        ]
    return rows


class FakeState:
    def __init__(self, records, key, fail_first, rate_limit_first, ratelimit_reset):
        self.records, self.key = records, key
        self.fail_first, self.rate_limit_first = fail_first, rate_limit_first
        self.ratelimit_reset = ratelimit_reset
        self.requests = []  # (path, headers, body)
        self.lock = threading.Lock()


def start_fake_api(count=12, extras=True, key=API_KEY, fail_first=0, rate_limit_first=0,
                   ratelimit_reset=None, records=None):
    state = FakeState(records if records is not None else build_records(count, extras), key,
                      fail_first, rate_limit_first, ratelimit_reset)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, headers=None):
            raw = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def _err(self, status, code, message, headers=None):
            self._send(status, {"error": {"status": status, "code": code, "message": message,
                                          "request_id": "req_test"}}, headers)

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            with state.lock:
                state.requests.append((self.path, dict(self.headers), body))
                n = len(state.requests)
            if self.path != "/api/v1/assets/search":
                return self._err(404, "NOT_FOUND", "no such route")
            if self.headers.get("Authorization") != f"token {state.key}":
                return self._err(401, "UNAUTHORIZED", "Missing/invalid token")
            if n <= state.rate_limit_first:
                reset = state.ratelimit_reset if state.ratelimit_reset is not None else int(time.time()) + 1
                return self._err(429, "TOO_MANY_REQUESTS", "slow down", {"RateLimit-Reset": str(reset)})
            if n <= state.fail_first:
                return self._err(503, "INTERNAL_ERROR", "boom", {"Retry-After": "0"})
            size = int(body.get("page_size", 100))
            if not 1 <= size <= 1000:
                return self._err(400, "VALIDATION_ERROR", "bad page_size")
            start = 0
            if body.get("page_token"):
                start = json.loads(base64.urlsafe_b64decode(body["page_token"]))["o"]
            chunk = state.records[start:start + size]
            nxt = start + size
            token = base64.urlsafe_b64encode(json.dumps({"o": nxt}).encode()).decode() \
                if nxt < len(state.records) else None
            self._send(200, {"data": chunk, "pagination": {
                "page_size": size, "returned": len(chunk), "snapshot_at": "2026-11-11T10:00:00Z",
                "next_page_token": token}})

    server = ThreadingHTTPServer(("127.0.0.1", 0), H)
    server.state = state
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"
