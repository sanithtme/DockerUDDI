"""Create, inspect and remove the DHCP network (IP space, subnet, range) used for the lease demo.

Safety model (same as zones)
----------------------------
* Everything this tool creates carries ``ManagedBy=<ipam.managed_tag>``. Only tagged objects are
  ever modified or deleted; an existing subnet/range/space without the tag is never touched.
* Subnets must be private address space and ranges must sit inside their subnet (and be modest
  in size), so a typo cannot create a DHCP scope on a public network.
* The IP space is only deleted if this tool created it and nothing else is left in it.

Rules from the documentation that shape the behaviour
-----------------------------------------------------
* A DHCP host's IP space is fixed by the first subnet/range assigned to it; later assignments must
  use the same space (Universal DDI "Creating HA Groups" / DHCP docs). Use ``ipam.create_ip_space:
  false`` and name the existing space if your host already serves one.
* On a NIOS-federated IP space ``dhcp_host`` is accepted but silently ignored (UDDIST-3407): the
  tool checks the response echoes the host and rolls the subnet back with a clear error if not.
* A range inherits the serving host from its parent subnet, so only the subnet carries ``dhcp_host``.
"""
from __future__ import annotations

import ipaddress
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from demo_core.config import Config
from demo_core.errors import ConfigError

from .client import DdiApiError, DdiClient
from .manager import TAG_KEY, _q

MAX_RANGE_SIZE = 4096


@dataclass(frozen=True)
class RangeSpec:
    start: str
    end: str
    name: str


@dataclass(frozen=True)
class SubnetSpec:
    address: str
    cidr: int
    name: str
    ranges: tuple[RangeSpec, ...]

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(f"{self.address}/{self.cidr}")


def parse_ipam_specs(cfg: Config) -> list[SubnetSpec]:
    specs: list[SubnetSpec] = []
    for i, raw in enumerate(cfg.ipam.subnets):
        where = f"ipam.subnets[{i}]"
        if not isinstance(raw, dict):
            raise ConfigError(f"{where}: expected a mapping")
        bad = set(raw) - {"address", "cidr", "name", "ranges"}
        if bad:
            raise ConfigError(f"{where}: unknown key(s) {sorted(bad)}")
        try:
            net = ipaddress.ip_network(f"{raw['address']}/{raw['cidr']}", strict=True)
        except (KeyError, ValueError) as exc:
            raise ConfigError(f"{where}: needs a valid 'address' and 'cidr' ({exc})") from None
        if net.version != 4:
            raise ConfigError(f"{where}: only IPv4 subnets are supported")
        if not net.is_private:
            raise ConfigError(f"{where}: {net} is not private address space. A DHCP scope on a public "
                              "network is refused; use RFC 1918 addresses.")
        if net.prefixlen < 16:
            raise ConfigError(f"{where}: {net} is larger than /16; use a smaller demo subnet")
        ranges: list[RangeSpec] = []
        for j, r in enumerate(raw.get("ranges") or []):
            rw = f"{where}.ranges[{j}]"
            bad = set(r) - {"start", "end", "name"} if isinstance(r, dict) else {"?"}
            if bad or not isinstance(r, dict) or "start" not in r or "end" not in r:
                raise ConfigError(f"{rw}: needs 'start' and 'end' (and optionally 'name')")
            try:
                a, b = ipaddress.ip_address(r["start"]), ipaddress.ip_address(r["end"])
            except ValueError as exc:
                raise ConfigError(f"{rw}: {exc}") from None
            if a not in net or b not in net or int(b) < int(a):
                raise ConfigError(f"{rw}: {a}-{b} must be an ordered range inside {net}")
            if int(b) - int(a) + 1 > MAX_RANGE_SIZE:
                raise ConfigError(f"{rw}: range larger than {MAX_RANGE_SIZE} addresses")
            ranges.append(RangeSpec(str(a), str(b), str(r.get("name") or f"demo-range-{j + 1}")))
        specs.append(SubnetSpec(str(net.network_address), net.prefixlen,
                                str(raw.get("name") or f"demo-subnet-{i + 1}"), tuple(ranges)))
    return specs


@dataclass
class IpamApplyResult:
    dry_run: bool = False
    space: str = ""
    space_created: bool = False
    subnets_created: list[str] = field(default_factory=list)
    subnets_existing: list[str] = field(default_factory=list)
    ranges_created: list[str] = field(default_factory=list)
    ranges_existing: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class IpamManager:
    def __init__(self, cfg: Config, client: DdiClient | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.cfg, self.z = cfg, cfg.ipam
        self.specs = parse_ipam_specs(cfg)
        if not self.specs:
            raise ConfigError("no subnets configured: add entries under ipam.subnets")
        self.client = client or DdiClient(cfg, section="ipam")
        self._sleep = sleep
        self.dhcp_host = self._resolve_dhcp_host()

    def _tags(self) -> dict[str, str]:
        return {TAG_KEY: self.z.managed_tag}

    def _ours(self, obj: dict[str, Any]) -> bool:
        return (obj.get("tags") or {}).get(TAG_KEY) == self.z.managed_tag

    # ------------------------------------------------------------------ lookups
    def _resolve_dhcp_host(self) -> str:
        """Return an explicit DHCP host id or resolve dhcp.server to exactly one dhcp/host object."""
        if self.z.dhcp_host:
            return self.z.dhcp_host
        server = self.cfg.dhcp.server
        if not server:
            raise ConfigError("set dhcp.server (recommended) or ipam.dhcp_host before provisioning IPAM; use demo ipam hosts for diagnostics")
        rows = self.client.list("dhcp/host")
        matches = [r for r in rows if str(r.get("address") or "").strip() == str(server).strip()]
        if not matches:
            raise DdiApiError(
                f"no DHCP host has address {server!r}. Set dhcp.server to the NIOS-X DHCP address, "
                "or set ipam.dhcp_host explicitly; 'demo ipam hosts' can be used for diagnostics.")
        if len(matches) > 1:
            ids = ", ".join(str(r.get("id")) for r in matches)
            raise DdiApiError(
                f"multiple DHCP hosts have address {server!r}: {ids}. Set ipam.dhcp_host explicitly.")
        host_id = str(matches[0].get("id") or "")
        if not host_id.startswith("dhcp/host/"):
            raise DdiApiError(f"DHCP host matched {server!r} but returned invalid id {host_id!r}")
        return host_id

    def _find_space(self) -> dict[str, Any] | None:
        rows = self.client.list("ipam/ip_space", f'name=="{_q(self.z.ip_space)}"')
        return next((r for r in rows if r.get("name") == self.z.ip_space), None)

    def _find_subnet(self, spec: SubnetSpec, space_id: str) -> dict[str, Any] | None:
        rows = self.client.list("ipam/subnet", f'address=="{spec.address}" and space=="{_q(space_id)}"')
        return next((r for r in rows if str(r.get("cidr")) == str(spec.cidr)), None)

    def _find_range(self, rng: RangeSpec, space_id: str) -> dict[str, Any] | None:
        rows = self.client.list("ipam/range", f'start=="{rng.start}" and space=="{_q(space_id)}"')
        return next((r for r in rows if r.get("end") == rng.end), None)

    # ------------------------------------------------------------------ apply
    def apply(self, dry_run: bool = False) -> IpamApplyResult:
        res = IpamApplyResult(dry_run=dry_run, space=self.z.ip_space)
        space = self._find_space()
        if space is None:
            if not self.z.create_ip_space:
                raise DdiApiError(
                    f"IP space {self.z.ip_space!r} not found and ipam.create_ip_space is false. A DHCP "
                    "host serves one IP space (fixed by its first subnet): name the existing one, or "
                    "allow creation.")
            res.space_created = True
            space_id = "ipam/ip_space/<new>"
            if not dry_run:
                space = self.client.create("ipam/ip_space", {"name": self.z.ip_space, "tags": self._tags()})
                space_id = space["id"]
        else:
            space_id = space["id"]
            if (space.get("provider_type") or "").lower() == "nios":
                raise DdiApiError(
                    f"IP space {self.z.ip_space!r} is NIOS-federated: dhcp_host is ignored there "
                    "(UDDIST-3407). Use a native Universal DDI IP space for NIOS-X servers.")
        for spec in self.specs:
            subnet = None if space is None else self._find_subnet(spec, space_id)
            label = f"{spec.address}/{spec.cidr}"
            if subnet is None:
                res.subnets_created.append(label)
                if not dry_run:
                    subnet = self._create_subnet(spec, space_id)
            else:
                if not self._ours(subnet):
                    raise DdiApiError(f"subnet {label} already exists in {self.z.ip_space!r} and was not "
                                      f"created by this tool (no {TAG_KEY}={self.z.managed_tag} tag). "
                                      "Refusing to modify it.")
                res.subnets_existing.append(label)
                if subnet.get("dhcp_host") != self.dhcp_host:
                    res.notes.append(f"{label}: assigning {self.dhcp_host}")
                    if not dry_run:
                        self.client.patch(subnet["id"], {"dhcp_host": self.dhcp_host})
            for rng in spec.ranges:
                rl = f"{rng.start}-{rng.end}"
                found = None if (space is None or subnet is None) else self._find_range(rng, space_id)
                if found is None:
                    res.ranges_created.append(rl)
                    if not dry_run:
                        self.client.create("ipam/range", {"space": space_id, "start": rng.start,
                                                          "end": rng.end, "name": rng.name,
                                                          "tags": self._tags()})
                elif self._ours(found):
                    res.ranges_existing.append(rl)
                else:
                    res.notes.append(f"{rl}: a range exists that is not managed by this tool; left untouched")
        if not dry_run and (res.subnets_created or res.ranges_created):
            res.notes.append(f"allow about {self.z.wait_seconds:.0f}s for the DHCP config to reach the host "
                             "before requesting leases")
        return res

    def _create_subnet(self, spec: SubnetSpec, space_id: str) -> dict[str, Any]:
        body = {"space": space_id, "address": spec.address, "cidr": spec.cidr, "name": spec.name,
                "dhcp_host": self.dhcp_host, "tags": self._tags()}
        subnet = self.client.create("ipam/subnet", body)
        if subnet.get("dhcp_host") != self.dhcp_host:
            try:  # leave nothing behind that claims a server which will not serve it
                self.client.delete(subnet["id"])
            except DdiApiError:
                pass
            raise DdiApiError(
                f"the API accepted subnet {spec.address}/{spec.cidr} but did not record dhcp_host "
                f"{self.dhcp_host} (response: {subnet.get('dhcp_host')!r}). This happens on NIOS-federated "
                "IP spaces, where dhcp_host is ignored (UDDIST-3407). The subnet was removed again.")
        return subnet

    # ------------------------------------------------------------------ status / destroy
    def status(self) -> list[dict[str, Any]]:
        space = self._find_space()
        out = []
        for spec in self.specs:
            row: dict[str, Any] = {"subnet": f"{spec.address}/{spec.cidr}", "space": self.z.ip_space,
                                   "exists": False, "managed": None, "dhcp_host": None,
                                   "ranges_found": 0, "ranges_expected": len(spec.ranges)}
            subnet = self._find_subnet(spec, space["id"]) if space else None
            if subnet:
                row.update(exists=True, managed=self._ours(subnet), dhcp_host=subnet.get("dhcp_host"))
                row["ranges_found"] = sum(1 for r in spec.ranges if self._find_range(r, space["id"]))
            out.append(row)
        return out

    def destroy(self, dry_run: bool = False) -> dict[str, list[str]]:
        done: dict[str, list[str]] = {"ranges_deleted": [], "subnets_deleted": [], "space_deleted": [],
                                      "absent": [], "errors": []}
        space = self._find_space()
        if space is None:
            done["absent"].append(self.z.ip_space)
            return done
        sid = space["id"]
        for spec in self.specs:
            subnet = self._find_subnet(spec, sid)
            label = f"{spec.address}/{spec.cidr}"
            if subnet is None:
                done["absent"].append(label)
                continue
            if not self._ours(subnet):
                raise DdiApiError(f"subnet {label} was not created by this tool; refusing to delete it")
            all_ranges = self.client.list("ipam/range", f'space=="{_q(sid)}"')
            inside = []
            for r in all_ranges:
                try:
                    if ipaddress.ip_address(r.get("start", "")) in spec.network:
                        inside.append(r)
                except ValueError:
                    continue
            foreign = [r for r in inside if not self._ours(r)]
            if foreign:  # deleting the subnet could take someone else's ranges with it
                done["errors"].append(
                    f"{label}: contains {len(foreign)} range(s) not created by this tool "
                    f"({', '.join(str(r.get('start')) + '-' + str(r.get('end')) for r in foreign)}); "
                    "left the subnet and its ranges in place")
                continue
            for r in inside:
                if not dry_run:
                    try:
                        self.client.delete(r["id"])
                    except DdiApiError as exc:
                        done["errors"].append(f"{r.get('start')}-{r.get('end')}: {exc}")
                        continue
                done["ranges_deleted"].append(f"{r.get('start')}-{r.get('end')}")
            if not dry_run:
                try:
                    self.client.delete(subnet["id"])
                except DdiApiError as exc:
                    done["errors"].append(f"{label}: {exc}")
                    continue
            done["subnets_deleted"].append(label)
        if self._ours(space) and not dry_run and not done["errors"]:
            if not self.client.list("ipam/subnet", f'space=="{_q(sid)}"'):
                try:
                    self.client.delete(sid)
                    done["space_deleted"].append(self.z.ip_space)
                except DdiApiError as exc:
                    done["errors"].append(f"ip space {self.z.ip_space}: {exc}")
        elif self._ours(space) and dry_run:
            done["space_deleted"].append(self.z.ip_space + " (if empty afterwards)")
        return done

    # ------------------------------------------------------------------ read-only helpers
    def hosts(self) -> list[dict[str, Any]]:
        return self.client.list("dhcp/host")

    def leases(self, mac: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        """Read leases back. Field names are not verified, so --mac is a case-insensitive substring
        match over the whole record."""
        rows = self.client.list("dhcp/lease", limit=limit)
        if mac:
            needle = mac.lower()
            rows = [r for r in rows if needle in json.dumps(r).lower()]
        return rows
