import unittest

from helpers import TmpCase, make_asset

from asset_store import JSONAssetStore
from demo_core.errors import DemoError
from orchestrator.services import select_assets


class Select(TmpCase):
    def setUp(self):
        super().setUp()
        self.store = JSONAssetStore(self.tmp / "a.json")
        self.store.upsert_many([
            make_asset(1, asset_id="a-noip", ip=None, ipv4=None),            # sorts first, unusable for DNS
            make_asset(2, asset_id="b-nomac", mac=None),                    # DNS only
            make_asset(3, asset_id="c-ok"), make_asset(4, asset_id="d-ok"),
            make_asset(5, asset_id="e-noip", ip=None, ipv4=None)])

    def ids(self, **kw):
        return [a.asset_id for a in select_assets(self.store, **kw)]

    def test_limit_counts_usable_assets_not_first_stored(self):
        self.assertEqual(self.ids(limit=2), ["a-noip", "b-nomac"])                    # old behaviour without require
        self.assertEqual(self.ids(limit=2, require="dns"), ["b-nomac", "c-ok"])
        self.assertEqual(self.ids(limit=2, require="dhcp"), ["a-noip", "c-ok"])  # a-noip has a MAC

    def test_require_filters_everything_when_no_limit(self):
        self.assertEqual(self.ids(require="dns"), ["b-nomac", "c-ok", "d-ok"])

    def test_any_keeps_assets_usable_for_either_kind(self):
        self.store.upsert_many([make_asset(6, asset_id="f-none", ip=None, ipv4=None, mac=None)])
        self.assertEqual(self.ids(require="any"), ["a-noip", "b-nomac", "c-ok", "d-ok", "e-noip"])

    def test_explicit_asset_is_never_filtered(self):
        self.assertEqual(self.ids(asset_id="a-noip", require="dns"), ["a-noip"])

    def test_nothing_usable_gives_actionable_error(self):
        self.store.clear()
        self.store.upsert_many([make_asset(1, ip=None, ipv4=None)])
        with self.assertRaisesRegex(DemoError, "private_only.*discover"):
            select_assets(self.store, require="dns")


if __name__ == "__main__":
    unittest.main()


class SummaryAndSynth(TmpCase):
    def setUp(self):
        super().setUp()
        import yaml
        raw = {"infrastructure": {"type": "mock"}, "store": {"path": str(self.tmp / "a.json")},
               "reporting": {"output_dir": str(self.tmp / "r"), "state_dir": str(self.tmp / "s")}}
        (self.tmp / "c.yaml").write_text(yaml.safe_dump(raw))
        JSONAssetStore(self.tmp / "a.json").upsert_many([
            make_asset(1, discovery_source="Tenable,Jamf Pro", device_type="laptop"),
            make_asset(2, discovery_source="AWS", device_type="server", ips=["10.0.0.1", "10.0.0.2"]),
            make_asset(3, discovery_source="Tenable", device_type="laptop", ip=None, ipv4=None)])

    def cli(self, *argv):
        import io
        from contextlib import redirect_stderr, redirect_stdout
        from demo_cli.main import main
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["-c", str(self.tmp / "c.yaml"), *argv])
        return code, out.getvalue(), err.getvalue()

    def test_summary_counts_sources_types_and_ips(self):
        import json
        code, out, _ = self.cli("--json", "assets", "summary")
        d = json.loads(out)
        self.assertEqual((code, d["assets"], d["with_ip"], d["with_mac"], d["distinct_ips"]), (0, 3, 2, 3, 3))
        self.assertEqual(d["by_source"], {"Tenable": 2, "Jamf Pro": 1, "AWS": 1})
        self.assertEqual(d["by_type"], {"laptop": 2, "server": 1})
        text = self.cli("assets", "summary")[1]
        self.assertIn("3 assets discovered", text)
        self.assertIn("Tenable", text)

    def test_synth_clients_are_valid_unique_and_excluded_from_the_summary(self):
        import json
        from demo_core.models import normalize_mac
        code, out, _ = self.cli("--json", "assets", "synth", "--count", "3")
        rows = json.loads(out)
        self.assertEqual((code, [r["asset_id"] for r in rows]), (0, ["demo-dhcp-001", "demo-dhcp-002", "demo-dhcp-003"]))
        macs = [r["mac"] for r in rows]
        self.assertEqual(len(set(macs)), 3)
        for m in macs:
            self.assertEqual(normalize_mac(m), m)  # a valid unicast MAC
            self.assertEqual(int(m[:2], 16) & 3, 2)  # locally administered, unicast
        d = json.loads(self.cli("--json", "assets", "summary")[1])
        self.assertEqual((d["assets"], d["synthetic"]), (3, 3))
        a = JSONAssetStore(self.tmp / "a.json").get("demo-dhcp-001")
        self.assertEqual((a.dhcp_eligible, a.dns_eligible, a.tags), (True, False, ["demo-synthetic"]))
        self.assertEqual(self.cli("--json", "assets", "synth", "--count", "3")[0], 0)  # idempotent
        self.assertEqual(len(JSONAssetStore(self.tmp / "a.json").list()), 6)

    def test_synth_clients_work_with_dhcp(self):
        self.cli("assets", "synth", "--count", "1")
        code, out, _ = self.cli("dhcp", "request", "--asset", "demo-dhcp-001")  # mock infra -> mock DHCP
        self.assertEqual(code, 0)
        self.assertIn("mock ACK", out)
