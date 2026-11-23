import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from helpers import ApiCase, make_cfg

from demo_cli.main import main
from orchestrator import DemoOptions, DemoOrchestrator

ROOT = Path(__file__).resolve().parents[1]


class Orchestrator(ApiCase):
    def run_demo(self, cfg=None, **opts):
        lines = []
        summary = DemoOrchestrator(cfg or self.cfg(), emit=lines.append).run(DemoOptions(**opts))
        return summary, "\n".join(lines)

    def steps(self, summary):
        return {s["name"].split(". ", 1)[1]: s for s in summary["steps"]}

    def test_full_mock_demo(self):
        summary, log = self.run_demo(duration=1, rate=2)
        st = self.steps(summary)
        self.assertEqual(summary["status"], "warn")  # warn = bad IP/MAC in the data, as designed
        self.assertEqual(st["Infrastructure preflight"]["status"], "ok")
        self.assertEqual(st["Asset discovery"]["data"]["assets"], 17)
        self.assertEqual(st["DHCP activity"]["data"]["ok"], 30)  # 15 DHCP-eligible x (request, renew)
        self.assertGreater(st["Normal DNS activity"]["data"]["total"], 20)
        self.assertEqual(len(st["Threat Defense scenarios"]["data"]["scenarios"]), 4)
        report = next((self.tmp / "reports").glob("demo-*"))
        self.assertTrue((report / "summary.json").exists())
        self.assertIn("Portal verification checklist", (report / "verification.md").read_text())
        self.assertIn("blocked-domain", (report / "verification.md").read_text())

    def test_dry_run_sends_nothing(self):
        summary, _ = self.run_demo(dry_run=True, duration=30)
        self.assertEqual(self.steps(summary)["Normal DNS activity"]["data"]["dry_run"], True)

    def test_skips_and_limit(self):
        summary, _ = self.run_demo(skip_dhcp=True, skip_td=True, limit=3, duration=1)
        st = self.steps(summary)
        self.assertEqual(st["DHCP activity"]["status"], "skipped")
        self.assertEqual(st["Threat Defense scenarios"]["status"], "skipped")
        self.assertEqual(summary["assets"], 3)

    def test_default_scenarios_skip_gracefully_without_domains(self):
        cfg = self.cfg(threat_defense={"domains": [], "enabled_scenarios": ["blocked-domain"]})
        summary, _ = self.run_demo(cfg, duration=1)
        td = self.steps(summary)["Threat Defense scenarios"]
        self.assertEqual(td["status"], "warn")
        self.assertEqual(len(td["data"]["skipped"]), 1)

    def test_explicit_scenario_failure_is_a_failed_step(self):
        cfg = self.cfg(threat_defense={"domains": [], "enabled_scenarios": ["blocked-domain"]})
        summary, _ = self.run_demo(cfg, duration=1, scenarios=["blocked-domain"])
        self.assertEqual(self.steps(summary)["Threat Defense scenarios"]["status"], "failed")
        self.assertEqual(summary["status"], "failed")

    def test_preflight_failure_aborts_before_any_traffic(self):
        cfg = self.cfg(infrastructure={"type": "ova"},
                       dns={"server": "127.0.0.1", "port": 1, "timeout": 0.2})
        summary, log = self.run_demo(cfg)
        self.assertEqual(len(summary["steps"]), 1)
        self.assertIn("Aborted", log)
        self.assertEqual(summary["status"], "failed")

    def test_discovery_failure_is_reported_and_stops_the_run(self):
        os.environ["INFOBLOX_API_KEY"] = "wrong"
        summary, log = self.run_demo(duration=1)
        self.assertEqual(self.steps(summary)["Asset discovery"]["status"], "failed")
        self.assertIn("HTTP 401", self.steps(summary)["Asset discovery"]["detail"])
        self.assertEqual(summary["status"], "failed")
        self.assertNotIn("Normal DNS activity", self.steps(summary))

    def test_skip_discovery_uses_store_and_empty_store_aborts(self):
        summary, _ = self.run_demo(skip_discovery=True)
        self.assertEqual(summary["assets"], 0)
        self.assertNotIn("Normal DNS activity", self.steps(summary))


class CLI(ApiCase):
    def setUp(self):
        super().setUp()
        import yaml
        raw = yaml.safe_load((ROOT / "config" / "config.mock.yaml").read_text())
        raw["asset_source"]["base_url"] = self.url
        raw["store"]["path"] = str(self.tmp / "a.json")
        raw["reporting"] = {"output_dir": str(self.tmp / "r"), "state_dir": str(self.tmp / "s")}
        raw["dns"]["duration"] = 1
        raw["dhcp"]["dra"] = {"lease_dir": str(self.tmp / "dhcp")}
        self.cfgfile = self.tmp / "c.yaml"
        self.cfgfile.write_text(yaml.safe_dump(raw))

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["-c", str(self.cfgfile), *argv])
        return code, out.getvalue(), err.getvalue()

    def test_brief_command_flow(self):
        self.assertEqual(self.cli("discover")[0], 0)
        code, out, _ = self.cli("assets", "list")
        self.assertIn("demo-device-001", out)
        code, out, _ = self.cli("--json", "assets", "show", "asset-001")
        self.assertEqual(json.loads(out)["mac"], "02:00:00:00:00:01")
        code, out, _ = self.cli("dns", "run", "--asset", "asset-001")
        self.assertEqual(code, 0)
        self.assertIn("answered", out)
        for argv in (("dns", "run", "--all"), ("dns", "run", "--all", "--profile", "normal"),
                     ("dns", "run", "--all", "--profile", "security-demo"),
                     ("dhcp", "renew", "--asset", "asset-001"), ("dhcp", "renew", "--all"),
                     ("td", "run", "--scenario", "blocked-domain", "--all"), ("td", "scenarios"),
                     ("infra", "show"), ("infra", "check"), ("verify",)):
            if argv == ("dhcp", "renew", "--asset", "asset-001"):
                self.assertEqual(self.cli("dhcp", "renew", "--asset", "asset-001")[0], 3)  # no lease yet
                self.cli("dhcp", "request", "--all")  # mock leases persist across invocations
            code, out, err = self.cli(*argv)
            self.assertEqual(code, 0, f"{argv}: {out}{err}")

    def test_errors_have_exit_codes_and_messages(self):
        code, _, err = self.cli("dns", "run", "--all")  # empty store
        self.assertEqual(code, 1)
        self.assertIn("demo discover", err)
        self.cli("discover")
        code, _, err = self.cli("dns", "run", "--asset", "nope")
        self.assertEqual(code, 1)
        code, _, err = self.cli("td", "run", "--scenario", "ddos", "--all")
        self.assertEqual(code, 2)
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["-c", str(self.tmp / "missing.yaml"), "assets", "list"]), 2)

    def test_dry_run_and_domains_override(self):
        self.cli("discover")
        code, out, _ = self.cli("dns", "run", "--all", "--dry-run", "--domains", "a.example.com,b.example.com",
                                "--query-types", "A")
        self.assertEqual(code, 0)
        self.assertIn("DRY RUN", out)
        code, out, _ = self.cli("--json", "dhcp", "request", "--asset", "asset-001", "--dry-run")
        self.assertTrue(json.loads(out)[0]["ok"])

    def test_probe_stores_nothing(self):
        code, out, _ = self.cli("discover", "--probe")
        self.assertEqual(code, 0)
        self.assertIn("record keys", out)
        self.assertIn("ip_addresses", out)
        self.assertEqual(self.cli("assets", "list")[1].count("asset-"), 0)

    def test_discover_reports_asset_insights_numbers(self):
        code, out, _ = self.cli("discover")
        self.assertEqual(code, 0)
        for needle in ("17 asset(s), 17 distinct usable IP(s)", "1 deleted skipped", "DNS-eligible: 16"):
            self.assertIn(needle, out)

    def test_discover_without_api_key_is_a_clear_error(self):
        os.environ.pop("INFOBLOX_API_KEY")
        code, _, err = self.cli("discover")
        self.assertEqual(code, 1)
        self.assertIn("INFOBLOX_API_KEY is not set", err)

    def test_assets_import_offline(self):
        saved = self.tmp / "saved.json"
        from fake_asset_api import build_records
        saved.write_text(json.dumps({"data": build_records(3, extras=False)}))
        code, out, _ = self.cli("assets", "import", str(saved))
        self.assertEqual(code, 0)
        self.assertIn("imported 3 asset(s)", out)
        self.assertEqual(self.cli("dns", "run", "--all", "--dry-run")[0], 0)
        bad = self.tmp / "bad.json"
        bad.write_text("{not json")
        self.assertEqual(self.cli("assets", "import", str(bad))[0], 1)

    def test_assets_ips_lists_distinct_addresses_and_exports(self):
        self.cli("discover")
        out_file = self.tmp / "ips.txt"
        code, out, _ = self.cli("assets", "ips", "--show", "--export", str(out_file))
        self.assertEqual(code, 0)
        self.assertIn("17 distinct IP(s); 0 public", out)
        lines = out_file.read_text().split()
        self.assertEqual(len(lines), 17)
        self.assertEqual(len(set(lines)), 17)
        self.assertEqual(lines[0], "10.20.30.101")  # IPv4 sorted before IPv6
        self.assertEqual(lines[-1], "2001:db8::beef")

    def test_chunked_runs_cover_every_ip_exactly_once(self):
        import yaml
        raw = yaml.safe_load(self.cfgfile.read_text())
        raw["safety"] = {"max_assets_per_run": 5}  # the cap that chunking is meant to work within
        self.cfgfile.write_text(yaml.safe_dump(raw))
        self.cli("discover")
        code, _, err = self.cli("dns", "run", "--all", "--dry-run")
        self.assertEqual(code, 4)  # 17 IPs > cap of 5
        self.assertIn("max_assets_per_run", err)
        code, out, err = self.cli("--json", "dns", "run", "--all", "--dry-run", "--chunk-size", "5")
        self.assertEqual(code, 0)
        runs = json.loads(out)
        self.assertEqual([len(r["assets"]) for r in runs], [5, 5, 5, 2])
        ips = [a["ip"] for r in runs for a in r["assets"]]
        self.assertEqual((len(ips), len(set(ips))), (17, 17))
        self.assertIn("4 chunk(s) of <= 5", err)
        ledger = [e for e in (self.tmp / "s" / "run_ledger.jsonl").read_text().splitlines() if '"kind": "dns"' in e]
        self.assertEqual(len(ledger), 4)

    def test_chunked_threat_defense_scenario(self):
        self.cli("discover")
        code, out, _ = self.cli("--json", "td", "run", "--scenario", "blocked-domain", "--all",
                                "--dry-run", "--chunk-size", "8")
        self.assertEqual(code, 0)
        self.assertEqual([len(r["assets"]) for r in json.loads(out)], [8, 8, 1])

    def test_mock_server_command_is_gone(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["mock-server"])

    def test_infra_recommend_needs_no_config(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["infra", "recommend", "--needs-physical"])
        self.assertEqual(code, 0)
        self.assertIn("baremetal", out.getvalue())

    def test_run_demo_command(self):
        code, out, _ = self.cli("run-demo", "--duration", "1")
        self.assertEqual(code, 0)
        self.assertIn("Portal verification checklist", out)


if __name__ == "__main__":
    unittest.main()
