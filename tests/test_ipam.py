import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout

import yaml
from helpers import ApiCase, TmpCase, make_asset, make_cfg

from asset_store import JSONAssetStore
from demo_cli.main import main
from demo_core.errors import ConfigError
from ddi_zones import DdiApiError, IpamManager, parse_ipam_specs
from fake_ddi_api import KEY, start_fake_ddi
from orchestrator import DemoOptions, DemoOrchestrator

HOST = "dhcp/host/4569789"
SUBNET = {"address": "172.31.32.0", "cidr": 20, "name": "vpc-demo",
          "ranges": [{"start": "172.31.47.100", "end": "172.31.47.120", "name": "demo-range"}]}


def ipam_cfg(url, **over):
    z = {"base_url": url, "dhcp_host": HOST, "wait_seconds": 0, "subnets": [SUBNET]}
    z.update(over)
    return z


class IpamCase(TmpCase):
    def setUp(self):
        super().setUp()
        os.environ["INFOBLOX_API_KEY"] = KEY
        self.addCleanup(os.environ.pop, "INFOBLOX_API_KEY", None)
        self.api, self.url = start_fake_ddi()
        self.addCleanup(lambda: (self.api.shutdown(), self.api.server_close()))
        self.state = self.api.state

    def cfg(self, **over):
        return make_cfg(self.tmp, ipam=ipam_cfg(self.url, **over))

    def writes(self):
        return [(m, p) for m, p, _q, _b in self.state.log if m != "GET"]


class Specs(unittest.TestCase):
    def cfg(self, subnets):
        return make_cfg("/tmp", ipam={"subnets": subnets})

    def test_valid(self):
        s = parse_ipam_specs(self.cfg([SUBNET]))[0]
        self.assertEqual((s.address, s.cidr, s.ranges[0].start), ("172.31.32.0", 20, "172.31.47.100"))

    def test_guards(self):
        cases = [({"address": "8.8.8.0", "cidr": 24}, "not private"),
                 ({"address": "10.0.0.0", "cidr": 8}, "larger than /16"),
                 ({"address": "10.0.0.1", "cidr": 24}, "valid"),  # host bits set
                 ({"address": "10.1.0.0", "cidr": 24, "ranges": [{"start": "10.2.0.1", "end": "10.2.0.9"}]}, "inside"),
                 ({"address": "10.1.0.0", "cidr": 24, "ranges": [{"start": "10.1.0.9", "end": "10.1.0.1"}]}, "ordered"),
                 ({"address": "10.1.0.0", "cidr": 16, "ranges": [{"start": "10.1.0.1", "end": "10.1.200.1"}]}, "larger than"),
                 ({"address": "10.1.0.0", "cidr": 24, "oops": 1}, "unknown key"),
                 ({"address": "10.1.0.0", "cidr": 24, "ranges": [{"start": "10.1.0.1"}]}, "needs 'start' and 'end'")]
        for sub, msg in cases:
            with self.assertRaisesRegex(ConfigError, msg):
                parse_ipam_specs(self.cfg([sub]))

    def test_config_level_checks(self):
        with self.assertRaisesRegex(ConfigError, "dhcp/host/"):
            make_cfg("/tmp", ipam={"dhcp_host": "dns/host/1"})
        with self.assertRaisesRegex(ConfigError, "ipam.dhcp_host"):
            make_cfg("/tmp", ipam={"enabled": True, "subnets": [SUBNET]})
        with self.assertRaisesRegex(ConfigError, "subnets is empty"):
            make_cfg("/tmp", ipam={"enabled": True, "dhcp_host": HOST})


class Apply(IpamCase):
    def test_creates_space_subnet_range_with_documented_bodies(self):
        res = IpamManager(self.cfg()).apply()
        self.assertEqual((res.space_created, res.subnets_created, res.ranges_created),
                         (True, ["172.31.32.0/20"], ["172.31.47.100-172.31.47.120"]))
        posts = {p.rsplit("/", 1)[-1]: b for m, p, _q, b in self.state.log if m == "POST"}
        tags = {"ManagedBy": "asset-insights-ddi-demo"}
        self.assertEqual(posts["ip_space"], {"name": "asset-insights-ddi-demo", "tags": tags})
        space_id = next(iter(self.state.spaces))
        self.assertEqual(posts["subnet"], {"space": space_id, "address": "172.31.32.0", "cidr": 20,
                                           "name": "vpc-demo", "dhcp_host": HOST, "tags": tags})
        self.assertEqual(posts["range"], {"space": space_id, "start": "172.31.47.100", "end": "172.31.47.120",
                                          "name": "demo-range", "tags": tags})  # host comes from the subnet
        self.assertEqual(next(iter(self.state.ranges.values()))["dhcp_host"], HOST)
        self.assertTrue(any("allow about" in n for n in res.notes))

    def test_idempotent(self):
        mgr = IpamManager(self.cfg())
        mgr.apply()
        before = len(self.writes())
        res = mgr.apply()
        self.assertEqual((res.space_created, res.subnets_created, res.ranges_created), (False, [], []))
        self.assertEqual((len(res.subnets_existing), len(res.ranges_existing)), (1, 1))
        self.assertEqual(len(self.writes()), before)

    def test_dry_run_reads_only(self):
        res = IpamManager(self.cfg()).apply(dry_run=True)
        self.assertEqual((res.dry_run, res.space_created, len(res.ranges_created)), (True, True, 1))
        self.assertEqual(self.writes(), [])

    def test_requires_a_serving_host(self):
        with self.assertRaisesRegex(ConfigError, "ipam.dhcp_host.*demo ipam hosts"):
            IpamManager(self.cfg(dhcp_host=None)).apply()
        self.assertEqual(self.writes(), [])

    def test_existing_space_must_exist_when_creation_is_off(self):
        with self.assertRaisesRegex(DdiApiError, "serves one IP space"):
            IpamManager(self.cfg(create_ip_space=False)).apply()
        self.assertEqual(self.writes(), [])

    def test_uses_an_existing_space_without_creating_it(self):
        self.state.spaces["ipam/ip_space/x"] = {"id": "ipam/ip_space/x", "name": "default", "tags": None,
                                                "provider_type": "ubiquity"}
        IpamManager(self.cfg(ip_space="default", create_ip_space=False)).apply()
        self.assertEqual(len(self.state.spaces), 1)
        self.assertEqual(next(iter(self.state.subnets.values()))["space"], "ipam/ip_space/x")

    def test_foreign_subnet_is_never_touched(self):
        IpamManager(self.cfg()).apply()
        for sn in self.state.subnets.values():
            sn["tags"] = None
        with self.assertRaisesRegex(DdiApiError, "not created by this tool"):
            IpamManager(self.cfg()).apply()

    def test_nios_federated_space_is_refused_up_front(self):
        self.state.nios_space_names.add("fed-space")
        self.state.spaces["ipam/ip_space/f"] = {"id": "ipam/ip_space/f", "name": "fed-space", "tags": None,
                                                "provider_type": "nios"}
        with self.assertRaisesRegex(DdiApiError, "NIOS-federated.*UDDIST-3407"):
            IpamManager(self.cfg(ip_space="fed-space", create_ip_space=False)).apply()
        self.assertEqual(self.writes(), [])

    def test_silently_ignored_dhcp_host_is_detected_and_rolled_back(self):
        self.state.ignore_dhcp_host = True
        with self.assertRaisesRegex(DdiApiError, "did not record dhcp_host.*removed again"):
            IpamManager(self.cfg()).apply()
        self.assertEqual(self.state.subnets, {})

    def test_host_already_serving_another_space_gives_the_apis_message(self):
        self.state.host_space[HOST] = "ipam/ip_space/other"
        with self.assertRaisesRegex(DdiApiError, "different IP space"):
            IpamManager(self.cfg()).apply()

    def test_existing_subnet_gets_the_host_reassigned(self):
        mgr = IpamManager(self.cfg())
        mgr.apply()
        next(iter(self.state.subnets.values()))["dhcp_host"] = "dhcp/host/other"
        res = mgr.apply()
        self.assertTrue(any("assigning" in n for n in res.notes))
        self.assertEqual(next(iter(self.state.subnets.values()))["dhcp_host"], HOST)

    def test_permission_error_is_actionable(self):
        os.environ["INFOBLOX_API_KEY"] = "wrong"
        with self.assertRaisesRegex(DdiApiError, "HTTP 401"):
            IpamManager(self.cfg()).apply()


class StatusDestroyRead(IpamCase):
    def test_status(self):
        mgr = IpamManager(self.cfg())
        self.assertEqual(mgr.status()[0]["exists"], False)
        mgr.apply()
        row = mgr.status()[0]
        self.assertEqual((row["exists"], row["managed"], row["dhcp_host"], row["ranges_found"]), (True, True, HOST, 1))

    def test_destroy_removes_ranges_subnets_and_our_space(self):
        mgr = IpamManager(self.cfg())
        mgr.apply()
        done = mgr.destroy()
        self.assertEqual((done["ranges_deleted"], done["subnets_deleted"], done["space_deleted"], done["errors"]),
                         (["172.31.47.100-172.31.47.120"], ["172.31.32.0/20"], ["asset-insights-ddi-demo"], []))
        self.assertEqual((self.state.spaces, self.state.subnets, self.state.ranges), ({}, {}, {}))
        self.assertEqual(mgr.destroy()["absent"], ["asset-insights-ddi-demo"])

    def test_destroy_keeps_a_space_it_did_not_create(self):
        self.state.spaces["ipam/ip_space/x"] = {"id": "ipam/ip_space/x", "name": "default", "tags": None,
                                                "provider_type": "ubiquity"}
        mgr = IpamManager(self.cfg(ip_space="default", create_ip_space=False))
        mgr.apply()
        mgr.destroy()
        self.assertEqual((len(self.state.subnets), len(self.state.spaces)), (0, 1))

    def test_destroy_refuses_to_delete_a_subnet_holding_someone_elses_range(self):
        mgr = IpamManager(self.cfg())
        mgr.apply()
        self.state.ranges["ipam/range/theirs"] = {"id": "ipam/range/theirs", "space": next(iter(self.state.spaces)),
                                                  "start": "172.31.47.200", "end": "172.31.47.210", "tags": None}
        done = mgr.destroy()
        self.assertEqual(done["subnets_deleted"], [])
        self.assertTrue(any("not created by this tool" in e for e in done["errors"]))
        self.assertEqual(len(self.state.subnets), 1)                # nothing deleted at all
        self.assertEqual(len(self.state.ranges), 2)
        self.assertEqual(done["space_deleted"], [])

    def test_destroy_refuses_foreign_subnets(self):
        mgr = IpamManager(self.cfg())
        mgr.apply()
        for sn in self.state.subnets.values():
            sn["tags"] = None
        with self.assertRaisesRegex(DdiApiError, "refusing to delete"):
            mgr.destroy()

    def test_destroy_dry_run_writes_nothing(self):
        mgr = IpamManager(self.cfg())
        mgr.apply()
        n = len(self.writes())
        done = mgr.destroy(dry_run=True)
        self.assertEqual(done["subnets_deleted"], ["172.31.32.0/20"])
        self.assertEqual(len(self.writes()), n)

    def test_hosts_and_lease_readback(self):
        mgr = IpamManager(self.cfg())
        self.assertEqual(mgr.hosts()[0]["id"], HOST)
        self.assertEqual(len(mgr.leases()), 2)
        mine = mgr.leases(mac="aa:bb:cc:dd:ee:01")
        self.assertEqual([r["hostname"] for r in mine], ["demo-1"])  # case-insensitive MAC match
        self.assertEqual(mgr.leases(mac="de:ad:be:ef:00:00"), [])
        self.assertTrue(any(p.endswith("/dhcp/lease") for m, p, _q, _b in self.state.log))


class CLI(IpamCase):
    def setUp(self):
        super().setUp()
        raw = {"infrastructure": {"type": "mock"}, "store": {"path": str(self.tmp / "a.json")},
               "reporting": {"output_dir": str(self.tmp / "r"), "state_dir": str(self.tmp / "s")},
               "ipam": ipam_cfg(self.url)}
        (self.tmp / "c.yaml").write_text(yaml.safe_dump(raw))

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["-c", str(self.tmp / "c.yaml"), *argv])
        return code, out.getvalue(), err.getvalue()

    def test_lifecycle(self):
        code, out, _ = self.cli("ipam", "hosts")
        self.assertIn("dhcp/host/4569789", out)
        self.assertIn("differs from the dns/host id", out)
        code, out, _ = self.cli("ipam", "apply", "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("PLAN (dry run", out)
        self.assertEqual(self.state.spaces, {})
        code, out, _ = self.cli("ipam", "apply")
        self.assertEqual(code, 0)
        self.assertIn("1 to create/created", out)
        self.assertEqual(self.cli("ipam", "status")[0], 0)
        code, out, _ = self.cli("ipam", "leases", "--mac", "aa:bb:cc:dd:ee:02")
        self.assertEqual(code, 0)
        self.assertIn("demo-2", out)
        self.assertEqual(self.cli("ipam", "leases", "--mac", "00:00:00:00:00:00")[0], 3)
        self.assertEqual(self.cli("ipam", "destroy", "--dry-run")[0], 0)
        self.assertEqual(len(self.state.subnets), 1)
        code, out, _ = self.cli("ipam", "destroy", "--yes")
        self.assertEqual((code, self.state.subnets, self.state.spaces), (0, {}, {}))
        self.assertEqual(self.cli("ipam", "status")[0], 3)

    def test_destroy_prompt_cancels(self):
        self.cli("ipam", "apply")
        import builtins
        orig = builtins.input
        builtins.input = lambda *_: "no"
        try:
            code, out, _ = self.cli("ipam", "destroy")
        finally:
            builtins.input = orig
        self.assertIn("cancelled", out)
        self.assertEqual(len(self.state.subnets), 1)

    def test_error_exit_code(self):
        self.state.ignore_dhcp_host = True
        code, _, err = self.cli("ipam", "apply")
        self.assertEqual(code, 1)
        self.assertIn("did not record dhcp_host", err)


class Orchestrated(ApiCase):
    def test_run_demo_creates_the_dhcp_network_before_the_dhcp_step(self):
        os.environ["INFOBLOX_API_KEY"] = "test-key"
        ddi, url = start_fake_ddi(key="test-key")
        self.addCleanup(lambda: (ddi.shutdown(), ddi.server_close()))
        cfg = self.cfg(ipam=ipam_cfg(url, enabled=True))
        summary = DemoOrchestrator(cfg, emit=lambda *_: None).run(
            DemoOptions(duration=1, skip_td=True, skip_dns=True, limit=3))
        names = [s["name"].split(". ", 1)[1] for s in summary["steps"]]
        self.assertLess(names.index("DHCP network: create subnet/range and assign the server"),
                        names.index("DHCP activity"))
        st = {n: s for n, s in zip(names, summary["steps"])}
        self.assertEqual(st["DHCP network: create subnet/range and assign the server"]["status"], "ok")
        self.assertEqual((len(ddi.state.subnets), len(ddi.state.ranges)), (1, 1))

    def test_skip_flag_and_failure_isolation(self):
        os.environ["INFOBLOX_API_KEY"] = "test-key"
        ddi, url = start_fake_ddi(key="other")  # key rejected
        self.addCleanup(lambda: (ddi.shutdown(), ddi.server_close()))
        cfg = self.cfg(ipam=ipam_cfg(url, enabled=True))
        quiet = DemoOrchestrator(cfg, emit=lambda *_: None).run(
            DemoOptions(duration=1, skip_td=True, skip_dns=True, skip_ipam=True, limit=2))
        self.assertFalse(any("DHCP network" in s["name"] for s in quiet["steps"]))
        failed = DemoOrchestrator(cfg, emit=lambda *_: None).run(
            DemoOptions(duration=1, skip_td=True, skip_dns=True, limit=2))
        st = {s["name"].split(". ", 1)[1]: s for s in failed["steps"]}
        self.assertEqual(st["DHCP network: create subnet/range and assign the server"]["status"], "failed")
        self.assertEqual(st["DHCP activity"]["status"], "ok")  # the run carries on


if __name__ == "__main__":
    unittest.main()

class AutoResolveDhcpHost(IpamCase):
    def test_resolves_dhcp_host_from_dhcp_server(self):
        cfg = make_cfg(self.tmp, dhcp={"server": "172.31.37.228"},
                       ipam=ipam_cfg(self.url, dhcp_host=None))
        mgr = IpamManager(cfg)
        self.assertEqual(mgr.dhcp_host, "dhcp/host/4569789")
        mgr.apply()
        subnet = next(iter(self.state.subnets.values()))
        self.assertEqual(subnet["dhcp_host"], "dhcp/host/4569789")
