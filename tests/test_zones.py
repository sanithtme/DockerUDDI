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
from ddi_zones import DdiApiError, ZoneManager, parse_zone_specs
from fake_ddi_api import KEY, start_fake_ddi
from generators.dns import DNSRunSettings
from orchestrator import DemoOptions, DemoOrchestrator
from providers import MockProvider

ZONE = {"fqdn": "demo.internal.", "comment": "test zone", "records": [
    {"name": "host1", "type": "A", "rdata": {"address": "10.99.0.10"}, "ttl": 300},
    {"name": "mail-test", "type": "MX", "rdata": {"preference": 10, "exchange": "mail.demo.internal."}}]}


def zones_cfg(url, **over):
    z = {"base_url": url, "dns_host": "dns/host/970601", "zones": [ZONE], "wait_seconds": 0}
    z.update(over)
    return z


class DdiCase(TmpCase):
    def setUp(self):
        super().setUp()
        os.environ["INFOBLOX_API_KEY"] = KEY
        self.addCleanup(os.environ.pop, "INFOBLOX_API_KEY", None)
        self.api, self.url = start_fake_ddi()
        self.addCleanup(lambda: (self.api.shutdown(), self.api.server_close()))
        self.state = self.api.state

    def cfg(self, **over):
        return make_cfg(self.tmp, zones=zones_cfg(self.url, **over))

    def writes(self):
        return [(m, p) for m, p, _q, _b in self.state.log if m != "GET"]


class Specs(unittest.TestCase):
    def cfg(self, zones):
        return make_cfg("/tmp", zones={"zones": zones})

    def test_valid(self):
        specs = parse_zone_specs(self.cfg([ZONE]))
        self.assertEqual(specs[0].fqdn, "demo.internal.")
        self.assertEqual(specs[0].absolute(specs[0].records[0]), "host1.demo.internal")

    def test_real_domains_are_refused(self):
        for bad in ("example.com.", "google.com", "corp.local", "demo.org"):
            with self.assertRaisesRegex(ConfigError, "allowed suffix"):
                parse_zone_specs(self.cfg([{"fqdn": bad, "records": []}]))

    def test_suffix_list_can_be_extended_deliberately(self):
        cfg = make_cfg("/tmp", zones={"allowed_suffixes": [".lab.corp."], "zones": [{"fqdn": "a.lab.corp"}]})
        self.assertEqual(parse_zone_specs(cfg)[0].fqdn, "a.lab.corp.")

    def test_record_validation(self):
        base = {"fqdn": "demo.internal."}
        cases = [({"name": "@", "type": "A", "rdata": {"address": "1.1.1.1"}}, "apex"),
                 ({"name": "x", "type": "HINFO", "rdata": {"a": 1}}, "not in"),
                 ({"name": "x", "type": "A"}, "rdata"),
                 ({"name": "bad name", "type": "A", "rdata": {"address": "1.1.1.1"}}, "relative name"),
                 ({"name": "x", "type": "A", "rdata": {"address": "1.1.1.1"}, "foo": 1}, "unknown key")]
        for rec, msg in cases:
            with self.assertRaisesRegex(ConfigError, msg):
                parse_zone_specs(self.cfg([{**base, "records": [rec]}]))
        with self.assertRaisesRegex(ConfigError, "unknown key"):
            parse_zone_specs(self.cfg([{**base, "oops": 1}]))

    def test_config_level_checks(self):
        with self.assertRaisesRegex(ConfigError, "dns.server, zones.dns_host, or zones.nsg"):
            make_cfg("/tmp", zones={"enabled": True, "zones": [ZONE]})
        with self.assertRaisesRegex(ConfigError, "dns/host/"):
            make_cfg("/tmp", zones={"dns_host": "970601"})
        with self.assertRaisesRegex(ConfigError, "not both"):
            make_cfg("/tmp", zones={"dns_host": "dns/host/1", "nsg": "x"})


class Apply(DdiCase):
    def test_creates_zone_and_records_with_documented_bodies(self):
        res = ZoneManager(self.cfg()).apply()
        self.assertEqual((res.zones_created, len(res.records_created)), (["demo.internal."], 2))
        zone = next(iter(self.state.zones.values()))
        self.assertEqual(zone["tags"], {"ManagedBy": "asset-insights-ddi-demo"})
        self.assertEqual(zone["internal_secondaries"], [{"host": "dns/host/970601"}])
        zone_post = next(b for m, p, _q, b in self.state.log if m == "POST" and p.endswith("auth_zone"))
        self.assertEqual((zone_post["fqdn"], zone_post["primary_type"]), ("demo.internal.", "cloud"))
        self.assertNotIn("view", zone_post)  # default view
        recs = [b for m, p, _q, b in self.state.log if m == "POST" and p.endswith("/dns/record")]
        a = next(r for r in recs if r["type"] == "A")
        self.assertEqual((a["name_in_zone"], a["rdata"], a["ttl"], a["zone"]),
                         ("host1", {"address": "10.99.0.10"}, 300, zone["id"]))
        self.assertEqual(a["tags"], {"ManagedBy": "asset-insights-ddi-demo"})
        mx = next(r for r in recs if r["type"] == "MX")
        self.assertEqual(mx["rdata"], {"preference": 10, "exchange": "mail.demo.internal."})

    def test_idempotent_second_run_writes_nothing(self):
        mgr = ZoneManager(self.cfg())
        mgr.apply()
        before = len(self.writes())
        res = mgr.apply()
        self.assertEqual((res.zones_created, res.records_created, len(res.records_unchanged)), ([], [], 2))
        self.assertEqual(len(self.writes()), before)

    def test_changed_rdata_is_patched(self):
        ZoneManager(self.cfg()).apply()
        changed = dict(ZONE, records=[dict(ZONE["records"][0], rdata={"address": "10.99.0.77"}), ZONE["records"][1]])
        res = ZoneManager(make_cfg(self.tmp, zones=zones_cfg(self.url, zones=[changed]))).apply()
        self.assertEqual(res.records_updated, ["host1.demo.internal A"])
        self.assertEqual(self.writes()[-1][0], "PATCH")
        rec = next(r for r in self.state.records.values() if r["type"] == "A")
        self.assertEqual(rec["rdata"], {"address": "10.99.0.77"})

    def test_refuses_to_create_a_zone_no_server_will_serve(self):
        cfg = make_cfg(self.tmp, zones=zones_cfg(self.url, dns_host=None))
        with self.assertRaisesRegex(ConfigError, "dns.server.*zones.dns_host"):
            ZoneManager(cfg).apply()
        self.assertEqual(self.writes(), [])

    def test_dry_run_reads_but_never_writes(self):
        res = ZoneManager(self.cfg()).apply(dry_run=True)
        self.assertEqual((res.dry_run, len(res.records_created)), (True, 2))
        self.assertEqual(self.writes(), [])

    def test_foreign_zone_is_never_touched(self):
        self.state.seed_zone("demo.internal.", tags=None)
        with self.assertRaisesRegex(DdiApiError, "not created by this tool"):
            ZoneManager(self.cfg()).apply()
        self.assertEqual(self.writes(), [])
        self.state.zones.clear()
        self.state.seed_zone("demo.internal.", tags={"ManagedBy": "someone-else"})
        with self.assertRaisesRegex(DdiApiError, "not created by this tool"):
            ZoneManager(self.cfg()).apply()

    def test_untagged_record_with_different_data_is_left_alone(self):
        zone = self.state.seed_zone("demo.internal.", tags={"ManagedBy": "asset-insights-ddi-demo"})
        self.state.records["dns/record/x"] = {"id": "dns/record/x", "zone": zone["id"], "name_in_zone": "host1",
                                              "type": "A", "rdata": {"address": "1.2.3.4"}, "tags": None}
        res = ZoneManager(self.cfg()).apply()
        self.assertTrue(any("not managed by this tool" in n for n in res.notes))
        self.assertEqual(self.state.records["dns/record/x"]["rdata"], {"address": "1.2.3.4"})

    def test_primary_type_read_only_environment_is_handled(self):
        self.api.shutdown(); self.api.server_close()
        self.api, self.url = start_fake_ddi(reject_primary_type=True)
        self.state = self.api.state
        ZoneManager(self.cfg()).apply()
        posts = [b for m, p, _q, b in self.state.log if m == "POST" and p.endswith("auth_zone")]
        self.assertEqual(len(posts), 2)
        self.assertIn("primary_type", posts[0])
        self.assertNotIn("primary_type", posts[1])
        self.assertEqual(len(self.state.zones), 1)

    def test_existing_zone_gets_server_assignment_added_keeping_others(self):
        self.state.seed_zone("demo.internal.", tags={"ManagedBy": "asset-insights-ddi-demo"}, hosts=["dns/host/111"])
        ZoneManager(self.cfg()).apply()
        zone = next(iter(self.state.zones.values()))
        self.assertEqual([h["host"] for h in zone["internal_secondaries"]], ["dns/host/111", "dns/host/970601"])

    def test_nsg_and_view_lookups(self):
        cfg = make_cfg(self.tmp, zones=zones_cfg(self.url, dns_host=None, nsg="demo-nsg", view="lab"))
        ZoneManager(cfg).apply()
        zone = next(iter(self.state.zones.values()))
        self.assertEqual((zone["nsgs"], zone["view"]), (["dns/auth_nsg/n1"], "dns/view/v-lab"))
        missing = make_cfg(self.tmp, zones=zones_cfg(self.url, view="nope"))
        with self.assertRaisesRegex(DdiApiError, "view 'nope' not found"):
            ZoneManager(missing).apply()

    def test_permission_error_explains_the_role(self):
        os.environ["INFOBLOX_API_KEY"] = "wrong"
        with self.assertRaisesRegex(DdiApiError, "HTTP 401.*DDI DNS Operator"):
            ZoneManager(self.cfg()).apply()
        os.environ.pop("INFOBLOX_API_KEY")
        with self.assertRaisesRegex(DdiApiError, "INFOBLOX_API_KEY is not set"):
            ZoneManager(self.cfg()).apply()

    def test_filters_use_the_documented_forms(self):
        ZoneManager(self.cfg()).apply()
        filters = [q["_filter"][0] for m, p, q, _b in self.state.log if m == "GET" and "_filter" in q]
        self.assertIn('fqdn=="demo.internal"', filters)
        self.assertTrue(any(f.startswith('name_in_zone=="host1" and zone=="dns/auth_zone/') and
                            f.endswith('and type=="A"') for f in filters))


class StatusDestroy(DdiCase):
    def test_status(self):
        mgr = ZoneManager(self.cfg())
        self.assertEqual(mgr.status()[0]["exists"], False)
        mgr.apply()
        row = mgr.status()[0]
        self.assertEqual((row["exists"], row["managed"], row["records_found"], row["records_expected"]),
                         (True, True, 2, 2))
        self.assertEqual(row["assigned"], ["dns/host/970601"])

    def test_destroy_removes_only_tagged_objects_then_the_zone(self):
        mgr = ZoneManager(self.cfg())
        mgr.apply()
        zone = next(iter(self.state.zones.values()))
        self.state.records["dns/record/theirs"] = {"id": "dns/record/theirs", "zone": zone["id"],
                                                   "name_in_zone": "keep", "type": "A", "rdata": {}, "tags": None}
        done = mgr.destroy()
        self.assertEqual((len(done["records_deleted"]), done["zones_deleted"], done["errors"]),
                         (2, ["demo.internal."], []))
        self.assertEqual(self.state.zones, {})
        deletes = [p for m, p, _q, _b in self.state.log if m == "DELETE"]
        self.assertEqual(sum("/dns/record/" in p for p in deletes), 2)
        self.assertFalse(any("theirs" in p for p in deletes))  # untagged record never targeted individually

    def test_destroy_refuses_foreign_zone_and_dry_run_writes_nothing(self):
        self.state.seed_zone("demo.internal.", tags=None)
        with self.assertRaisesRegex(DdiApiError, "refusing to delete"):
            ZoneManager(self.cfg()).destroy()
        self.assertEqual(len(self.state.zones), 1)
        self.state.zones.clear()
        mgr = ZoneManager(self.cfg())
        mgr.apply()
        self.assertEqual(mgr.destroy(dry_run=True)["zones_deleted"], ["demo.internal."])
        self.assertEqual(len(self.state.zones), 1)
        self.assertEqual(ZoneManager(self.cfg()).destroy()["absent"], [])
        mgr.destroy()
        self.assertEqual(mgr.destroy()["absent"], ["demo.internal."])


class Verify(DdiCase):
    def setUp(self):
        super().setUp()
        self.cfg_ = self.cfg(negative_names=["does-not-exist"])
        self.prov = MockProvider(self.cfg_)
        self.prov.start()
        self.addCleanup(self.prov.stop)
        self.ep = self.prov.dns_endpoint()

        def mirror(kind, obj, zone=None):  # emulate the DDI service pushing config to the DNS server
            srv = self.prov.server
            if kind == "zone_created":
                srv.add_zone(obj["fqdn"])
            elif kind == "record_created":
                srv.add_record(zone["fqdn"], f"{obj['name_in_zone']}.{zone['fqdn'].rstrip('.')}", obj["type"])
            elif kind == "zone_deleted":
                srv.remove_zone(obj["fqdn"])
        self.mirror = mirror

    def test_not_authoritative_until_the_server_serves_the_zone(self):
        mgr = ZoneManager(self.cfg_)
        mgr.apply()  # server not told yet
        rows = mgr.verify(self.ep.host, self.ep.port, wait=0, timeout=0.5)
        self.assertFalse(any(r.ok for r in rows))
        self.assertTrue(all(r.aa is False for r in rows))

    def test_authoritative_answers_and_negative_nxdomain(self):
        self.state.listeners.append(self.mirror)
        mgr = ZoneManager(self.cfg_)
        mgr.apply()
        rows = mgr.verify(self.ep.host, self.ep.port, wait=0, timeout=0.5)
        self.assertTrue(all(r.ok for r in rows), [r.__dict__ for r in rows])
        by = {(r.name, r.type): r for r in rows}
        self.assertEqual((by["host1.demo.internal", "A"].rcode, by["host1.demo.internal", "A"].aa,
                          by["host1.demo.internal", "A"].answers), ("NOERROR", True, 1))
        self.assertEqual(by["mail-test.demo.internal", "MX"].answers, 1)
        neg = by["does-not-exist.demo.internal", "A"]
        self.assertEqual((neg.rcode, neg.aa, neg.expect), ("NXDOMAIN", True, "nxdomain"))

    def test_waits_for_propagation(self):
        def propagate(_seconds):  # the zone reaches the DNS server while we wait
            for z in self.state.zones.values():
                self.mirror("zone_created", z)
            for r in self.state.records.values():
                self.mirror("record_created", r, self.state.zones[r["zone"]])

        mgr = ZoneManager(self.cfg_, sleep=propagate)
        mgr.apply()
        rows = mgr.verify(self.ep.host, self.ep.port, wait=5, timeout=0.5, interval=0.01)
        self.assertTrue(all(r.ok for r in rows), [r.__dict__ for r in rows])

    def test_query_as_assets_sends_each_record_once_per_device_with_identity(self):
        self.state.listeners.append(self.mirror)
        mgr = ZoneManager(self.cfg_)
        mgr.apply()
        st = DNSRunSettings.from_config(self.cfg_, server=self.ep.host, port=self.ep.port, source_mode="edns",
                                        timeout=1.0)
        assets = [make_asset(1), make_asset(2), make_asset(3, ip=None, ipv4=None)]
        rows, summary = mgr.query_as_assets(assets, st)
        self.assertEqual(len(rows), 2 * 3)  # 2 devices x (2 records + 1 negative)
        self.assertEqual(self.prov.server.total, 6)
        self.assertEqual(sum(1 for r in rows if r["aa"]), 6)
        self.assertEqual((summary.label, summary.total, summary.failed), ("zone-test", 6, 0))
        self.assertEqual(summary.rcodes, {"NOERROR": 4, "NXDOMAIN": 2})
        self.assertEqual(self.prov.server.by_edns[(65523, "0a141e65")], 3)  # device 1's IP on its 3 queries
        self.assertEqual(self.prov.server.by_edns[(65523, "0a141e66")], 3)


class CLI(DdiCase):
    def setUp(self):
        super().setUp()
        raw = {"infrastructure": {"type": "mock"}, "store": {"path": str(self.tmp / "a.json")},
               "reporting": {"output_dir": str(self.tmp / "r"), "state_dir": str(self.tmp / "s")},
               "zones": zones_cfg(self.url)}
        (self.tmp / "c.yaml").write_text(yaml.safe_dump(raw))
        JSONAssetStore(self.tmp / "a.json").upsert_many([make_asset(1), make_asset(2)])

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["-c", str(self.tmp / "c.yaml"), *argv])
        return code, out.getvalue(), err.getvalue()

    def test_full_lifecycle(self):
        code, out, _ = self.cli("zones", "apply", "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("PLAN (dry run", out)
        self.assertEqual(self.state.zones, {})
        code, out, _ = self.cli("zones", "apply")
        self.assertEqual(code, 0)
        self.assertIn("2 created", out)
        self.assertEqual(self.cli("zones", "status")[0], 0)
        code, out, _ = self.cli("zones", "verify", "--wait", "0")
        self.assertEqual(code, 0)  # mock infra emulates serving the configured zones
        self.assertIn("mock DNS: zones are emulated", out)
        code, out, _ = self.cli("zones", "test", "--limit", "2", "--source-mode", "edns")
        self.assertEqual(code, 0)
        self.assertIn("6 queries from 2 device(s)", out)
        self.assertIn("6 answered authoritatively", out)
        code, out, _ = self.cli("zones", "destroy", "--dry-run")
        self.assertIn("PLAN (dry run)", out)
        self.assertEqual(len(self.state.zones), 1)
        code, out, _ = self.cli("zones", "destroy", "--yes")
        self.assertEqual((code, self.state.zones), (0, {}))
        self.assertEqual(self.cli("zones", "status")[0], 3)  # zone gone

    def test_hosts_lists_dns_host_ids(self):
        code, out, _ = self.cli("zones", "hosts")
        self.assertEqual(code, 0)
        self.assertIn("dns/host/970601", out)
        self.assertIn("NOT the on-prem host id", out)

    def test_zone_test_is_recorded_for_the_checklist(self):
        self.cli("zones", "apply")
        self.cli("zones", "test", "--limit", "1")
        code, out, _ = self.cli("verify")
        self.assertIn("zone-test", out)
        self.assertIn("host1.demo.internal", out)

    def test_destroy_prompt_cancels_unless_confirmed(self):
        self.cli("zones", "apply")
        import builtins
        orig = builtins.input
        builtins.input = lambda *_: "no"
        try:
            code, out, _ = self.cli("zones", "destroy")
        finally:
            builtins.input = orig
        self.assertIn("cancelled", out)
        self.assertEqual(len(self.state.zones), 1)

    def test_errors_exit_codes(self):
        self.state.seed_zone("demo.internal.", tags=None)
        code, _, err = self.cli("zones", "apply")
        self.assertEqual(code, 1)
        self.assertIn("not created by this tool", err)


class Orchestrated(ApiCase):
    def test_run_demo_creates_zones_verifies_and_queries_them(self):
        os.environ["INFOBLOX_API_KEY"] = "test-key"  # both fakes accept it below
        ddi, url = start_fake_ddi(key="test-key")
        self.addCleanup(lambda: (ddi.shutdown(), ddi.server_close()))
        cfg = self.cfg(zones=zones_cfg(url, enabled=True, query_devices=2))
        lines = []
        summary = DemoOrchestrator(cfg, emit=lines.append).run(
            DemoOptions(duration=1, rate=1, skip_dhcp=True, skip_td=True))
        st = {s["name"].split(". ", 1)[1]: s for s in summary["steps"]}
        zs = st["Test zones: create and verify the server is authoritative"]
        self.assertEqual(zs["status"], "ok", zs["detail"])
        self.assertIn("authoritatively for every record", zs["detail"])
        iq = st["Internal-domain queries (server acts as authoritative)"]
        self.assertEqual(iq["status"], "ok", iq["detail"])
        self.assertIn("answered authoritatively", iq["detail"])
        self.assertEqual(len(ddi.state.zones), 1)
        self.assertEqual(len(ddi.state.records), 2)

    def test_skip_zones_flag_and_disabled_by_default(self):
        os.environ["INFOBLOX_API_KEY"] = "test-key"
        ddi, url = start_fake_ddi(key="test-key")
        self.addCleanup(lambda: (ddi.shutdown(), ddi.server_close()))
        cfg = self.cfg(zones=zones_cfg(url, enabled=True))
        summary = DemoOrchestrator(cfg, emit=lambda *_: None).run(
            DemoOptions(duration=1, skip_dhcp=True, skip_td=True, skip_zones=True))
        self.assertFalse(any("zones" in s["name"].lower() for s in summary["steps"]))
        self.assertEqual(ddi.state.zones, {})
        plain = DemoOrchestrator(self.cfg(), emit=lambda *_: None).run(
            DemoOptions(duration=1, skip_dhcp=True, skip_td=True))
        self.assertFalse(any("zones" in s["name"].lower() for s in plain["steps"]))

    def test_zone_failure_is_reported_and_the_run_continues(self):
        os.environ["INFOBLOX_API_KEY"] = "test-key"
        ddi, url = start_fake_ddi(key="other-key")  # API key rejected
        self.addCleanup(lambda: (ddi.shutdown(), ddi.server_close()))
        cfg = self.cfg(zones=zones_cfg(url, enabled=True))
        summary = DemoOrchestrator(cfg, emit=lambda *_: None).run(
            DemoOptions(duration=1, skip_dhcp=True, skip_td=True))
        st = {s["name"].split(". ", 1)[1]: s for s in summary["steps"]}
        self.assertEqual(st["Test zones: create and verify the server is authoritative"]["status"], "failed")
        self.assertEqual(st["Internal-domain queries (server acts as authoritative)"]["status"], "skipped")
        self.assertEqual(st["Normal DNS activity"]["status"], "ok")


if __name__ == "__main__":
    unittest.main()

class AutoResolveDnsHost(DdiCase):
    def test_resolves_dns_host_from_dns_server(self):
        cfg = make_cfg(self.tmp, dns={"server": "172.31.37.228"},
                       zones=zones_cfg(self.url, dns_host=None))
        res = ZoneManager(cfg).apply()
        self.assertEqual(res.zones_created, ["demo.internal."])
        zone = next(iter(self.state.zones.values()))
        self.assertEqual(zone["internal_secondaries"], [{"host": "dns/host/970601"}])

    def test_missing_dns_host_match_fails_without_guessing(self):
        cfg = make_cfg(self.tmp, dns={"server": "172.31.37.229"},
                       zones=zones_cfg(self.url, dns_host=None))
        with self.assertRaisesRegex(DdiApiError, "no DNS host has address"):
            ZoneManager(cfg)
