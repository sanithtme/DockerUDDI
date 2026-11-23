import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace

import yaml
from helpers import TmpCase, make_asset, make_cfg

from asset_store import JSONAssetStore
from demo_cli.main import main
from demo_core.errors import ConfigError, SafetyError
from generators.dns import DNSRunSettings, DNSTrafficGenerator
from providers import MockProvider


class SendOne(TmpCase):
    def setUp(self):
        super().setUp()
        self.cfg = make_cfg(self.tmp)
        self.prov = MockProvider(self.cfg)
        self.prov.start()
        self.addCleanup(self.prov.stop)
        ep = self.prov.dns_endpoint()
        self.st = DNSRunSettings.from_config(self.cfg, server=ep.host, port=ep.port)
        self.gen = DNSTrafficGenerator(self.cfg)

    def test_exactly_one_query_reaches_the_server(self):
        r = self.gen.send_one(make_asset(1), "www.example.org", "A", self.st)
        self.assertTrue(r.ok)
        self.assertEqual(self.prov.server.total, 1)
        self.assertEqual(dict(self.prov.server.by_name), {"www.example.org": 1})
        self.assertEqual(dict(self.prov.server.by_type), {"A": 1})
        self.assertEqual(dict(self.prov.server.by_edns), {})  # direct mode: no identity options

    def test_edns_mode_carries_that_devices_identity(self):
        self.gen.send_one(make_asset(1), "www.example.org", "TXT", replace(self.st, source_mode="edns"))
        self.assertEqual(self.prov.server.total, 1)
        self.assertEqual(dict(self.prov.server.by_edns),
                         {(65523, "0a141e65"): 1, (65524, "020000000001"): 1})

    def test_validation_and_guards(self):
        with self.assertRaisesRegex(ConfigError, "unsupported query type"):
            self.gen.send_one(make_asset(1), "a.example.org", "HINFO", self.st)
        with self.assertRaisesRegex(ConfigError, "no validated IP"):
            self.gen.send_one(make_asset(1, ip=None, ipv4=None), "a.example.org", "A", self.st)
        with self.assertRaisesRegex(SafetyError, "public"):
            self.gen.send_one(make_asset(1), "a.example.org", "A", replace(self.st, server="8.8.8.8"))
        self.assertEqual(self.prov.server.total, 0)

    def test_dry_run_sends_nothing(self):
        r = self.gen.send_one(make_asset(1), "a.example.org", "A", replace(self.st, dry_run=True))
        self.assertTrue(r.ok)
        self.assertEqual(self.prov.server.total, 0)


class CLI(TmpCase):
    def setUp(self):
        super().setUp()
        raw = {"infrastructure": {"type": "mock"}, "store": {"path": str(self.tmp / "a.json")},
               "reporting": {"output_dir": str(self.tmp / "r"), "state_dir": str(self.tmp / "s")}}
        (self.tmp / "c.yaml").write_text(yaml.safe_dump(raw))
        JSONAssetStore(self.tmp / "a.json").upsert_many([
            make_asset(1),
            make_asset(2, ips=["10.20.40.5", "10.20.40.6"], ip="10.20.40.5", ipv4="10.20.40.5"),
            make_asset(3, ip=None, ipv4=None)])

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["-c", str(self.tmp / "c.yaml"), *argv])
        return code, out.getvalue(), err.getvalue()

    def test_one_query_one_device(self):
        code, out, _ = self.cli("dns", "query", "--asset", "asset-001", "--name", "www.example.org")
        self.assertEqual(code, 0)
        for needle in ("demo-device-001 (10.20.30.101", "www.example.org A", "#1: NOERROR"):
            self.assertIn(needle, out)
        self.assertNotIn("#2", out)

    def test_edns_flag_shows_what_was_sent(self):
        code, out, _ = self.cli("dns", "query", "--asset", "asset-001", "--name", "www.example.org",
                                "--source-mode", "edns")
        self.assertEqual(code, 0)
        self.assertIn("EDNS options sent: 65523=ip 10.20.30.101, 65524=mac 02:00:00:00:00:01", out)

    def test_multi_ip_device_uses_first_ip_or_the_one_you_pick(self):
        _, out, _ = self.cli("dns", "query", "--asset", "asset-002", "--name", "a.example.org", "--dry-run")
        self.assertIn("(10.20.40.5,", out)
        self.assertIn("has 2 IPs; used 10.20.40.5", out)
        _, out, _ = self.cli("dns", "query", "--asset", "asset-002", "--name", "a.example.org",
                             "--ip", "10.20.40.6", "--dry-run")
        self.assertIn("(10.20.40.6,", out)
        self.assertNotIn("has 2 IPs", out)
        code, _, err = self.cli("dns", "query", "--asset", "asset-002", "--name", "a.example.org",
                                "--ip", "10.99.99.99")
        self.assertEqual(code, 1)
        self.assertIn("not one of asset-002's IPs", err)

    def test_count_and_ptr_auto(self):
        code, out, _ = self.cli("dns", "query", "--asset", "asset-001", "--name", "a.example.org",
                                "--count", "3", "--interval", "0")
        self.assertEqual((code, out.count("#")), (0, 3))
        code, out, _ = self.cli("dns", "query", "--asset", "asset-001", "--name", "auto", "--type", "PTR")
        self.assertIn("101.30.20.10.in-addr.arpa PTR", out)

    def test_errors(self):
        self.assertEqual(self.cli("dns", "query", "--asset", "nope", "--name", "a.example.org")[0], 1)
        code, _, err = self.cli("dns", "query", "--asset", "asset-003", "--name", "a.example.org")
        self.assertEqual(code, 1)
        self.assertIn("no validated IP", err)
        code, _, err = self.cli("dns", "query", "--asset", "asset-001", "--name", "10.1.1.1")
        self.assertEqual(code, 2)  # an IP literal is not a domain
        self.assertIn("IP literal", err)

    def test_recorded_for_the_checklist(self):
        self.cli("dns", "query", "--asset", "asset-001", "--name", "www.example.org")
        events = [json.loads(line) for line in (self.tmp / "s" / "run_ledger.jsonl").read_text().splitlines()]
        self.assertEqual((events[0]["label"], events[0]["total"], events[0]["by_domain"]),
                         ("single-query", 1, {"www.example.org": 1}))
        code, out, _ = self.cli("verify")
        self.assertEqual(code, 0)
        self.assertIn("single-query", out + "normal")  # run is part of the ledger the checklist reads


if __name__ == "__main__":
    unittest.main()


class RecordTypes(unittest.TestCase):
    def test_zone_testing_types_are_encoded_with_the_right_codes(self):
        from generators import dnswire
        codes = {"CNAME": 5, "MX": 15, "SRV": 33, "NS": 2, "SOA": 6, "CAA": 257}
        for name, code in codes.items():
            q = dnswire.build_query(1, "_sip._tcp.demo.internal", name)
            self.assertEqual(dnswire.parse_question(q)[:3], ("_sip._tcp.demo.internal", code, 1), name)
        self.assertEqual(dnswire.QTYPE_NAMES[33], "SRV")

    def test_default_traffic_mix_is_unchanged(self):
        from demo_core.config import config_from_dict
        cfg = config_from_dict({"infrastructure": {"type": "mock"}})
        self.assertEqual(cfg.dns.query_types, ["A", "AAAA", "PTR", "TXT"])

    def test_cli_and_server_handle_each_type(self):
        import yaml
        from providers import MockProvider
        from tempfile import TemporaryDirectory
        from pathlib import Path
        with TemporaryDirectory() as d:
            tmp = Path(d)
            raw = {"infrastructure": {"type": "mock"}, "store": {"path": str(tmp / "a.json")},
                   "reporting": {"output_dir": str(tmp / "r"), "state_dir": str(tmp / "s")}}
            (tmp / "c.yaml").write_text(yaml.safe_dump(raw))
            JSONAssetStore(tmp / "a.json").upsert_many([make_asset(1)])
            for t in ("CNAME", "MX", "SRV", "NS", "SOA", "CAA"):
                out = io.StringIO()
                with redirect_stdout(out), redirect_stderr(io.StringIO()):
                    code = main(["-c", str(tmp / "c.yaml"), "dns", "query", "--asset", "asset-001",
                                 "--name", "_sip._tcp.demo.internal", "--type", t])
                self.assertEqual(code, 0, t)
                self.assertIn(f"_sip._tcp.demo.internal {t}", out.getvalue())
                self.assertIn("NOERROR", out.getvalue())
