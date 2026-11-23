import json
import os
import unittest
from dataclasses import replace

from helpers import TmpCase, make_asset, make_cfg

from demo_core.errors import AssetSourceError, ConfigError
from fake_tide_api import KEY, start_fake_tide
from generators.dns import DNSRunSettings
from generators.threat_defense import ThreatDefenseGenerator, load_threat_domains
from generators.tide import TideClient, load_snapshot, save_snapshot, snapshot_path
from providers import MockProvider


class TideCase(TmpCase):
    def setUp(self):
        super().setUp()
        os.environ["INFOBLOX_API_KEY"] = KEY
        self.addCleanup(os.environ.pop, "INFOBLOX_API_KEY", None)
        self.server, self.url = start_fake_tide()
        self.addCleanup(lambda: (self.server.shutdown(), self.server.server_close()))

    def cfg(self, tide=None, domains=None, **kw):
        td = {"domains": [] if domains is None else domains,
              "enabled_scenarios": ["blocked-domain", "mixed-workload", "normal-dns"],
              "tide": {"base_url": self.url, **(tide or {})}}
        return make_cfg(self.tmp, threat_defense=td, **kw)


class Fetch(TideCase):
    def test_request_matches_documented_contract(self):
        cfg = self.cfg(tide={"limit": 50, "classes": ["APT", "Bot"], "properties": ["A", "B"],
                             "profile": "IID"})
        TideClient(cfg).fetch()
        path, q, headers = self.server.log[0]
        self.assertEqual(path, "/tide/api/data/threats/state")
        self.assertEqual(headers["Authorization"], f"Token {KEY}")
        self.assertEqual((q["type"], q["rlimit"], q["data_format"]), (["host"], ["50"], ["json"]))
        self.assertEqual(q["class"], ["APT,Bot"])
        self.assertEqual(q["property"], ["A", "B"])
        self.assertEqual(q["profile"], ["IID"])

    def test_valid_distinct_domains_only(self):
        res = TideClient(self.cfg()).fetch()
        self.assertEqual([d.name for d in res.domains],
                         ["tide-demo-1.test", "tide-demo-2.test", "tide-demo-3.test"])
        self.assertEqual((res.raw_count, res.duplicates, res.skipped_invalid), (7, 1, 3))
        self.assertEqual(res.by_class, {"APT": 1, "Bot": 1, "Phishing": 1})
        self.assertEqual(res.domains[0].note, "TIDE APT/APT_MalwareC2 level 100")
        self.assertTrue(all(d.category == "blocked" for d in res.domains))

    def test_category_and_limit(self):
        res = TideClient(self.cfg(tide={"category": "Suspicious"})).fetch(limit=2)
        self.assertEqual({d.category for d in res.domains}, {"suspicious"})
        self.assertEqual(res.raw_count, 2)

    def test_class_filter(self):
        res = TideClient(self.cfg(tide={"classes": ["Bot"]})).fetch()
        self.assertEqual([d.name for d in res.domains], ["tide-demo-2.test"])

    def test_errors_are_actionable(self):
        os.environ["INFOBLOX_API_KEY"] = "wrong"
        with self.assertRaisesRegex(AssetSourceError, "HTTP 401.*entitlement"):
            TideClient(self.cfg()).fetch()
        os.environ.pop("INFOBLOX_API_KEY")
        with self.assertRaisesRegex(AssetSourceError, "INFOBLOX_API_KEY is not set"):
            TideClient(self.cfg()).fetch()
        with self.assertRaisesRegex(ConfigError, "base_url"):
            TideClient(make_cfg(self.tmp, asset_source={"base_url": "nope"}))

    def test_retries_then_gives_up(self):
        srv, url = start_fake_tide(status=503)
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close()))
        sleeps = []
        with self.assertRaisesRegex(AssetSourceError, "giving up after 4 attempts"):
            TideClient(self.cfg(tide={"base_url": url}), sleep=sleeps.append).fetch()
        self.assertEqual(len(sleeps), 3)

    def test_falls_back_to_asset_source_base_url(self):
        cfg = make_cfg(self.tmp, asset_source={"base_url": self.url},
                       threat_defense={"tide": {}, "enabled_scenarios": []})
        self.assertEqual(len(TideClient(cfg).fetch().domains), 3)


class SnapshotAndScenarios(TideCase):
    def test_snapshot_roundtrip_is_reviewable_json(self):
        cfg = self.cfg(tide={"enabled": True})
        path = save_snapshot(cfg, TideClient(cfg).fetch())
        self.assertEqual(path, snapshot_path(cfg))
        doc = json.loads(path.read_text())
        self.assertEqual(len(doc["domains"]), 3)
        self.assertIn("rlimit=100", doc["query"])
        self.assertNotIn(KEY, path.read_text())  # the key is never persisted
        self.assertEqual([d.name for d in load_snapshot(cfg)][0], "tide-demo-1.test")

    def test_disabled_tide_is_ignored(self):
        cfg = self.cfg(domains=["configured-1.example.net"])
        self.assertEqual([d.name for d in load_threat_domains(cfg)], ["configured-1.example.net"])

    def test_enabled_without_snapshot_explains_what_to_do(self):
        with self.assertRaisesRegex(ConfigError, "demo td fetch"):
            load_threat_domains(self.cfg(tide={"enabled": True}))

    def test_corrupt_snapshot_is_reported(self):
        cfg = self.cfg(tide={"enabled": True})
        snapshot_path(cfg).parent.mkdir(parents=True, exist_ok=True)
        snapshot_path(cfg).write_text("{oops")
        with self.assertRaisesRegex(ConfigError, "unreadable"):
            load_threat_domains(cfg)

    def test_merge_configured_wins_and_deduplicates(self):
        cfg = self.cfg(tide={"enabled": True}, domains=[{"name": "tide-demo-1.test", "category": "suspicious"}])
        save_snapshot(cfg, TideClient(cfg).fetch())
        got = {d.name: d.category for d in load_threat_domains(cfg)}
        self.assertEqual(got, {"tide-demo-1.test": "suspicious", "tide-demo-2.test": "blocked",
                               "tide-demo-3.test": "blocked"})

    def test_empty_everything_mentions_both_options(self):
        with self.assertRaisesRegex(ConfigError, "(?s)NO threat domains by design.*tide.enabled"):
            load_threat_domains(self.cfg())

    def test_scenario_queries_tide_domains_through_the_resolver_only(self):
        cfg = self.cfg(tide={"enabled": True})
        save_snapshot(cfg, TideClient(cfg).fetch())
        calls_to_tide = len(self.server.log)
        prov = MockProvider(cfg)
        prov.start()
        self.addCleanup(prov.stop)
        ep = prov.dns_endpoint()
        st = DNSRunSettings.from_config(cfg, server=ep.host, port=ep.port, query_types=["A"], duration=1)
        s = ThreatDefenseGenerator(cfg).run("blocked-domain", [make_asset(1), make_asset(2)], st)
        self.assertEqual(set(s.by_domain), {"tide-demo-1.test", "tide-demo-2.test", "tide-demo-3.test"})
        self.assertEqual(prov.server.total, s.total)
        self.assertEqual(len(self.server.log), calls_to_tide)  # scenarios never call TIDE themselves

    def test_suspicious_category_feeds_suspicious_scenario(self):
        cfg = self.cfg(tide={"enabled": True, "category": "suspicious"})
        cfg.threat_defense.enabled_scenarios.append("suspicious-domain")
        save_snapshot(cfg, TideClient(cfg).fetch())
        sel = ThreatDefenseGenerator(cfg).build_selector(
            ThreatDefenseGenerator(cfg).resolve_scenario("suspicious-domain"))
        self.assertEqual({e.name for e in sel.describe()},
                         {"tide-demo-1.test", "tide-demo-2.test", "tide-demo-3.test"})

    def test_limit_validation(self):
        with self.assertRaisesRegex(ConfigError, "tide.limit"):
            self.cfg(tide={"limit": 5000})


class CLI(TideCase):
    def run_cli(self, *argv, tide=None):
        import io
        import yaml
        from contextlib import redirect_stderr, redirect_stdout
        from demo_cli.main import main
        raw = {"infrastructure": {"type": "mock"}, "asset_source": {"base_url": self.url},
               "reporting": {"output_dir": str(self.tmp / "r"), "state_dir": str(self.tmp / "s")},
               "threat_defense": {"tide": tide or {}, "enabled_scenarios": []}}
        f = self.tmp / "c.yaml"
        f.write_text(yaml.safe_dump(raw))
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["-c", str(f), *argv])
        return code, out.getvalue(), err.getvalue()

    def test_td_fetch_prints_summary_and_warns_when_disabled(self):
        code, out, _ = self.run_cli("td", "fetch")
        self.assertEqual(code, 0)
        for needle in ("3 distinct domain(s)", "tide-demo-1.test", "enabled is false", "snapshot:"):
            self.assertIn(needle, out)
        self.assertTrue((self.tmp / "s" / "tide_domains.json").exists())

    def test_td_fetch_enabled_has_no_warning_and_limit_flag(self):
        code, out, _ = self.run_cli("td", "fetch", "--limit", "1", "--show", tide={"enabled": True})
        self.assertEqual(code, 0)
        self.assertNotIn("will NOT use", out)
        self.assertIn("1 distinct domain(s)", out)

    def test_td_fetch_auth_failure_exit_code(self):
        os.environ["INFOBLOX_API_KEY"] = "nope"
        code, _, err = self.run_cli("td", "fetch")
        self.assertEqual(code, 1)
        self.assertIn("HTTP 401", err)


if __name__ == "__main__":
    unittest.main()
