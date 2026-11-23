"""Test-only fake of the Universal DDI DNS config/data API (NOT shipped as a product feature).

Implements the documented calls this tool uses: GET/POST/PATCH/DELETE under /api/ddi/v1/ for
dns/auth_zone, dns/record, dns/view, dns/host, dns/auth_nsg; `Authorization: Token <key>`;
`_filter` with `field=="value"` terms joined by `and` (dotted fields such as tags.ManagedBy);
list bodies {"results": [...]}, create/patch bodies {"result": {...}}; list-style error bodies.
"""
from __future__ import annotations

import json
import re
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEY = "ddi-key"
_TERM = re.compile(r"""^\(?\s*([\w.]+)\s*==\s*(["'])(.*)\2\s*\)?$""")


def _get(obj, dotted):
    for part in dotted.split("."):
        obj = obj.get(part) if isinstance(obj, dict) else None
    return obj


def match(obj, expr):
    if not expr:
        return True
    for term in re.split(r"\s+and\s+", expr.strip()):
        m = _TERM.match(term.strip())
        if not m:
            raise ValueError(f"unsupported filter term {term!r}")
        field, value = m.group(1), m.group(3)
        have = _get(obj, field)
        if field == "fqdn":
            ok = str(have).rstrip(".") == value.rstrip(".")
        else:
            ok = str(have) == value
        if not ok:
            return False
    return True


class FakeDdi:
    def __init__(self, key=KEY, reject_primary_type=False):
        self.key, self.reject_primary_type = key, reject_primary_type
        self.views = [{"id": "dns/view/v-default", "name": "default"}, {"id": "dns/view/v-lab", "name": "lab"}]
        self.hosts = [{"id": "dns/host/970601", "name": "niosx-test", "address": "172.31.37.228"}]
        self.nsgs = [{"id": "dns/auth_nsg/n1", "name": "demo-nsg"}]
        self.zones, self.records = {}, {}
        # IPAM / DHCP (documented: ipam/ip_space, ipam/subnet, ipam/range, dhcp/host, dhcp/lease)
        self.spaces, self.subnets, self.ranges = {}, {}, {}
        self.dhcp_hosts = [{"id": "dhcp/host/4569789", "name": "niosx-test", "address": "172.31.37.228"}]
        self.leases = [{"id": "dhcp/lease/1", "address": "172.31.47.101", "hwaddr": "AA:BB:CC:DD:EE:01",
                        "hostname": "demo-1", "state": "used"},
                       {"id": "dhcp/lease/2", "address": "172.31.47.102", "hwaddr": "aa:bb:cc:dd:ee:02",
                        "hostname": "demo-2", "state": "used"}]
        self.nios_space_names = set()  # ip spaces reported as provider_type "nios"
        self.ignore_dhcp_host = False  # emulate UDDIST-3407: dhcp_host accepted but not recorded
        self.host_space = {}  # a DHCP host serves ONE ip space, fixed by its first subnet
        self.log, self.listeners = [], []
        self.lock = threading.Lock()

    def notify(self, kind, obj, zone=None):
        for fn in self.listeners:
            fn(kind, obj, zone)

    def seed_zone(self, fqdn, tags=None, hosts=None):
        zid = f"dns/auth_zone/{uuid.uuid4()}"
        self.zones[zid] = {"id": zid, "fqdn": fqdn if fqdn.endswith(".") else fqdn + ".",
                           "view": "dns/view/v-default", "tags": tags,
                           "internal_secondaries": [{"host": h} for h in hosts or []], "nsgs": []}
        return self.zones[zid]


def start_fake_ddi(**kw):
    state = FakeDdi(**kw)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body):
            raw = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _err(self, code, msg):
            self._send(code, {"error": [{"message": msg}]})

        def _route(self, method):
            import urllib.parse
            u = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(u.query)
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length)) if length else {}
            with state.lock:
                state.log.append((method, u.path, q, body))
            if self.headers.get("Authorization") != f"Token {state.key}":
                return self._err(401, "unauthorized")
            if not u.path.startswith("/api/ddi/v1/"):
                return self._err(404, "not found")
            parts = u.path[len("/api/ddi/v1/"):].split("/")
            kind = "/".join(parts[:2])
            rid = "/".join(parts[:3]) if len(parts) > 2 else None
            tables = {"dns/view": state.views, "dns/host": state.hosts, "dns/auth_nsg": state.nsgs}
            try:
                if method == "GET" and rid is None:
                    flt = (q.get("_filter") or [""])[0]
                    if kind in tables:
                        rows = tables[kind]
                    elif kind == "dns/auth_zone":
                        rows = list(state.zones.values())
                    elif kind == "dns/record":
                        rows = list(state.records.values())
                    elif kind == "dhcp/host":
                        rows = state.dhcp_hosts
                    elif kind == "dhcp/lease":
                        rows = state.leases
                    elif kind == "ipam/ip_space":
                        rows = list(state.spaces.values())
                    elif kind == "ipam/subnet":
                        rows = list(state.subnets.values())
                    elif kind == "ipam/range":
                        rows = list(state.ranges.values())
                    else:
                        return self._err(404, "unknown resource")
                    return self._send(200, {"results": [r for r in rows if match(r, flt)]})
            except ValueError as exc:
                return self._err(400, str(exc))

            if kind == "dns/auth_zone":
                if method == "POST":
                    if state.reject_primary_type and "primary_type" in body:
                        return self._err(400, "The 'PrimaryType' field is read-only and cannot be provided.")
                    fq = body["fqdn"] if body["fqdn"].endswith(".") else body["fqdn"] + "."
                    if any(z["fqdn"] == fq for z in state.zones.values()):
                        return self._err(409, "zone exists")
                    zid = f"dns/auth_zone/{uuid.uuid4()}"
                    zone = {"id": zid, "fqdn": fq, "view": body.get("view", "dns/view/v-default"),
                            "tags": body.get("tags"), "comment": body.get("comment", ""),
                            "internal_secondaries": body.get("internal_secondaries", []),
                            "nsgs": body.get("nsgs", []), "primary_type": body.get("primary_type", "cloud")}
                    state.zones[zid] = zone
                    state.notify("zone_created", zone)
                    return self._send(200, {"result": zone})
                if rid in state.zones and method == "PATCH":
                    state.zones[rid].update(body)
                    return self._send(200, {"result": state.zones[rid]})
                if rid in state.zones and method == "DELETE":
                    zone = state.zones.pop(rid)
                    for k in [k for k, r in state.records.items() if r["zone"] == rid]:
                        state.records.pop(k)
                    state.notify("zone_deleted", zone)
                    return self._send(200, {})
                return self._err(404, "zone not found")
            if kind == "dns/record":
                if method == "POST":
                    zone = state.zones.get(body.get("zone"))
                    if not zone:
                        return self._err(400, "zone not found")
                    if body.get("type") == "MX" and set(body.get("rdata", {})) != {"preference", "exchange"}:
                        return self._err(400, "bad MX rdata")
                    rid2 = f"dns/record/{uuid.uuid4()}"
                    rec = {"id": rid2, "zone": zone["id"], "name_in_zone": body["name_in_zone"],
                           "type": body["type"], "rdata": body["rdata"], "ttl": body.get("ttl", 28800),
                           "tags": body.get("tags"),
                           "absolute_name_spec": f"{body['name_in_zone']}.{zone['fqdn']}"}
                    state.records[rid2] = rec
                    state.notify("record_created", rec, zone)
                    return self._send(200, {"result": rec})
                if rid in state.records and method == "PATCH":
                    state.records[rid].update(body)
                    return self._send(200, {"result": state.records[rid]})
                if rid in state.records and method == "DELETE":
                    state.records.pop(rid)
                    return self._send(200, {})
                return self._err(404, "record not found")
            if kind == "ipam/ip_space":
                if method == "POST":
                    if any(sp["name"] == body.get("name") for sp in state.spaces.values()):
                        return self._err(409, "ip space exists")
                    sid = f"ipam/ip_space/{uuid.uuid4()}"
                    state.spaces[sid] = {"id": sid, "name": body["name"], "tags": body.get("tags"),
                                         "provider_type": "nios" if body["name"] in state.nios_space_names
                                         else "ubiquity"}
                    return self._send(200, {"result": state.spaces[sid]})
                if rid in state.spaces and method == "DELETE":
                    if any(sn["space"] == rid for sn in state.subnets.values()):
                        return self._err(400, "ip space is not empty")
                    state.spaces.pop(rid)
                    return self._send(200, {})
                return self._err(404, "ip space not found")
            if kind == "ipam/subnet":
                if method == "POST":
                    space = state.spaces.get(body.get("space"))
                    if not space:
                        return self._err(400, "ip space not found")
                    host = body.get("dhcp_host", "")
                    if host and not state.ignore_dhcp_host and space["provider_type"] != "nios":
                        if state.host_space.get(host, space["id"]) != space["id"]:
                            return self._err(400, "The DHCP host is assigned to a different IP space")
                        state.host_space[host] = space["id"]
                    sid = f"ipam/subnet/{uuid.uuid4()}"
                    ignored = state.ignore_dhcp_host or space["provider_type"] == "nios"
                    state.subnets[sid] = {"id": sid, "space": space["id"], "address": body["address"],
                                          "cidr": body["cidr"], "name": body.get("name", ""),
                                          "tags": body.get("tags"), "dhcp_host": "" if ignored else host,
                                          "provider_type": space["provider_type"]}
                    return self._send(200, {"result": state.subnets[sid]})
                if rid in state.subnets and method == "PATCH":
                    state.subnets[rid].update(body)
                    return self._send(200, {"result": state.subnets[rid]})
                if rid in state.subnets and method == "DELETE":
                    state.subnets.pop(rid)
                    return self._send(200, {})
                return self._err(404, "subnet not found")
            if kind == "ipam/range":
                if method == "POST":
                    import ipaddress as ipa
                    inside = [sn for sn in state.subnets.values() if sn["space"] == body.get("space")
                              and ipa.ip_address(body["start"]) in ipa.ip_network(f"{sn['address']}/{sn['cidr']}")]
                    if not inside:
                        return self._err(400, "range is not inside a subnet of this ip space")
                    rid2 = f"ipam/range/{uuid.uuid4()}"
                    state.ranges[rid2] = {"id": rid2, "space": body["space"], "start": body["start"],
                                          "end": body["end"], "name": body.get("name", ""),
                                          "tags": body.get("tags"), "dhcp_host": inside[0]["dhcp_host"],
                                          "inheritance_parent": inside[0]["id"]}
                    return self._send(200, {"result": state.ranges[rid2]})
                if rid in state.ranges and method == "DELETE":
                    state.ranges.pop(rid)
                    return self._send(200, {})
                return self._err(404, "range not found")
            return self._err(404, "unknown resource")

        def do_GET(self):
            self._route("GET")

        def do_POST(self):
            self._route("POST")

        def do_PATCH(self):
            self._route("PATCH")

        def do_DELETE(self):
            self._route("DELETE")

    server = ThreadingHTTPServer(("127.0.0.1", 0), H)
    server.state = state
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"
