"""Test-only fake of GET /tide/api/data/threats/state (documented TIDE contract)."""
from __future__ import annotations

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEY = "tide-key"


def rows():
    def r(host, cls="APT", prop="APT_MalwareC2", level=100):
        return {"id": f"id-{host}", "type": "HOST", "host": host, "domain": host, "class": cls,
                "property": prop, "profile": "IID", "threat_level": level}
    return [r("tide-demo-1.test"), r("tide-demo-2.test", "Bot", "Bot_Generic", 80),
            r("tide-demo-3.test", "Phishing", "Phishing_Generic", 60),
            r("tide-demo-1.test"),            # duplicate
            r("10.9.9.9"),                    # IP literal: rejected
            r("not a domain"),                # invalid: rejected
            {"id": "x", "type": "HOST"}]      # no host at all


def start_fake_tide(key=KEY, status=None):
    log = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            u = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(u.query)
            log.append((u.path, q, dict(self.headers)))
            if status:
                self.send_response(status)
                self.end_headers()
                return
            if u.path != "/tide/api/data/threats/state":
                self.send_response(404)
                self.end_headers()
                return
            if self.headers.get("Authorization") != f"Token {key}":
                self.send_response(401)
                self.end_headers()
                return
            data = rows()
            if "class" in q:
                wanted = set(q["class"][0].split(","))
                data = [d for d in data if d.get("class") in wanted]
            data = data[: int(q.get("rlimit", ["100"])[0])]
            raw = json.dumps({"threat": data, "record_count": len(data)}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), H)
    server.log = log
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"
