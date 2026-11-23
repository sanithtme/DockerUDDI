import unittest

from helpers import TmpCase, make_asset, make_cfg  # noqa: F401  (sets sys.path)

from asset_discovery.normalize import IPPolicy, dedupe_assets, normalize_asset
from demo_core.config import ConfigError, IPSelectionConfig, config_from_dict
from demo_core.models import normalize_mac, validate_ip


class MacIpValidation(unittest.TestCase):
    def test_mac_formats(self):
        for raw in ("02:00:00:00:00:01", "02-00-00-00-00-01", "0200.0000.0001", "020000000001",
                    "02:00:00:00:00:01 "):
            self.assertEqual(normalize_mac(raw), "02:00:00:00:00:01")

    def test_mac_rejections(self):
        for bad in (None, "", "zz:zz", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01",
                    "02:00:00:00:00"):
            with self.assertRaises(ValueError, msg=str(bad)):
                normalize_mac(bad)

    def test_ip_ok_and_canonical(self):
        self.assertEqual(validate_ip("10.20.30.101", 4), "10.20.30.101")
        self.assertEqual(validate_ip("2001:DB8:0:0:0:0:0:1", 6), "2001:db8::1")

    def test_ip_rejections(self):
        for bad, ver in (("999.1.1.1", None), ("", None), ("0.0.0.0", None), ("127.0.0.1", None),
                         ("224.0.0.1", None), ("169.254.1.1", None), ("fe80::1", None),
                         ("::1", None), ("10.0.0.1", 6), ("2001:db8::1", 4), ("240.0.0.1", None)):
            with self.assertRaises(ValueError, msg=bad):
                validate_ip(bad, ver)


class Normalize(unittest.TestCase):
    RAW = {"id": "asset-001", "name": "Demo-Device-001", "ip_addresses": ["10.20.30.101", "2001:db8::65"],
           "mac_addresses": ["02-00-00-00-00-01"], "type": [{"id": "Workstation", "label": "Workstation"}],
           "category": {"id": "devices", "label": "Devices"}, "vendor": "Dell",
           "os": {"name": "Windows 11", "type": "Windows", "version": "11"},
           "providers": [{"id": "crowdstrike", "label": "CrowdStrike"}], "tags": ["a"],
           "managed": True, "deleted_at": None}

    def test_full_record(self):
        a = normalize_asset(self.RAW)
        self.assertEqual(a.to_core_dict(), {"asset_id": "asset-001", "hostname": "demo-device-001",
                                            "ip": "10.20.30.101", "mac": "02:00:00:00:00:01",
                                            "device_type": "Workstation", "source": "third-party"})
        self.assertEqual(a.ips, ["10.20.30.101", "2001:db8::65"])
        self.assertEqual((a.ipv4, a.ipv6, a.os, a.discovery_source), ("10.20.30.101", "2001:db8::65",
                                                                      "Windows 11", "crowdstrike"))
        self.assertEqual(a.metadata["os_type"], "Windows")
        self.assertTrue(a.dns_eligible and a.dhcp_eligible)
        self.assertEqual(a.validation_errors, [])

    def test_invalid_values_flagged_valid_ones_kept(self):
        a = normalize_asset({"id": "x", "ip_addresses": ["999.1.1.1", "10.1.1.1"], "mac_addresses": ["nope"]})
        self.assertEqual((a.ip, a.ips, a.mac), ("10.1.1.1", ["10.1.1.1"], None))
        self.assertEqual(len(a.validation_errors), 2)
        self.assertTrue(a.dns_eligible and not a.dhcp_eligible)

    def test_public_ips_excluded_by_default(self):
        a = normalize_asset({"id": "c", "ip_addresses": ["10.0.1.5", "54.201.88.12"]})
        self.assertEqual(a.ips, ["10.0.1.5"])
        self.assertIn("54.201.88.12 (public address", a.metadata["excluded_ips"][0])
        only_public = normalize_asset({"id": "p", "ip_addresses": ["54.201.88.12"]})
        self.assertFalse(only_public.dns_eligible)

    def test_ip_policy_variants(self):
        raw = {"id": "c", "ip_addresses": ["10.0.1.5", "10.9.9.9", "54.201.88.12"]}
        pub = normalize_asset(raw, policy=IPPolicy(IPSelectionConfig(private_only=False)))
        self.assertEqual(len(pub.ips), 3)
        inc = normalize_asset(raw, policy=IPPolicy(IPSelectionConfig(include_cidrs=["10.0.1.0/24"])))
        self.assertEqual(inc.ips, ["10.0.1.5"])
        exc = normalize_asset(raw, policy=IPPolicy(IPSelectionConfig(exclude_cidrs=["10.9.9.0/24"])))
        self.assertEqual(exc.ips, ["10.0.1.5"])

    def test_ipv4_sorted_before_ipv6(self):
        a = normalize_asset({"id": "o", "ip_addresses": ["2001:db8::1", "10.0.0.9", "10.0.0.2"]})
        self.assertEqual(a.ips, ["10.0.0.2", "10.0.0.9", "2001:db8::1"])

    def test_absent_fields_are_not_errors(self):
        a = normalize_asset({"id": "min"})
        self.assertEqual((a.ips, a.macs, a.validation_errors), ([], [], []))
        self.assertFalse(a.dns_eligible or a.dhcp_eligible)

    def test_derived_id_and_unidentifiable(self):
        a = normalize_asset({"mac_addresses": ["02:00:00:00:00:09"]})
        self.assertTrue(a.asset_id.startswith("derived-"))
        self.assertIsNone(normalize_asset({"vendor": "x"}))

    def test_type_fallbacks(self):
        self.assertEqual(normalize_asset({"id": "t", "type": ["server"]}).device_type, "server")
        self.assertEqual(normalize_asset({"id": "t", "display_type": "Printer"}).device_type, "printer")


class Dedupe(unittest.TestCase):
    def test_by_asset_id(self):
        a, b = make_asset(1, tags=["x"]), make_asset(1, tags=["y"], hostname="renamed")
        out = dedupe_assets([a, b], ["asset_id"])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].tags, ["x", "y"])
        self.assertEqual(out[0].hostname, "renamed")

    def test_by_mac_across_ids_is_opt_in(self):
        a, b = make_asset(1), make_asset(1, asset_id="asset-001-dup")
        self.assertEqual(len(dedupe_assets([a, b])), 2)
        out = dedupe_assets([a, b], ["asset_id", "mac"])
        self.assertEqual([x.asset_id for x in out], ["asset-001"])

    def test_ip_dedupe_is_opt_in(self):
        a = make_asset(1, mac="02:00:00:00:00:01")
        b = make_asset(2, ip="10.20.30.101", ipv4="10.20.30.101", mac="02:00:00:00:00:02")
        self.assertEqual(len(dedupe_assets([a, b], ["asset_id", "mac"])), 2)
        self.assertEqual(len(dedupe_assets([a, b], ["asset_id", "mac", "ip"])), 1)

    def test_transitive_merge(self):
        a = make_asset(1, asset_id="a", mac="02:00:00:00:00:01", ip="10.0.0.1", ipv4="10.0.0.1")
        b = make_asset(2, asset_id="b", mac="02:00:00:00:00:01", ip="10.0.0.2", ipv4="10.0.0.2")
        c = make_asset(3, asset_id="b", mac="02:00:00:00:00:03")
        self.assertEqual(len(dedupe_assets([a, b, c], ["asset_id", "mac"])), 1)

    def test_distinct_assets_untouched(self):
        self.assertEqual(len(dedupe_assets([make_asset(i) for i in range(1, 6)])), 5)


class ConfigValidation(TmpCase):
    def test_unknown_key_rejected(self):
        with self.assertRaisesRegex(ConfigError, "unknown key"):
            config_from_dict({"dns": {"servr": "10.0.0.1"}, "infrastructure": {"type": "mock"}})

    def test_asset_source_validation(self):
        with self.assertRaises(ConfigError) as ctx:
            config_from_dict({"infrastructure": {"type": "mock"}, "asset_source": {
                "page_size": 5000, "category": "toasters", "ip_selection": {"include_cidrs": ["nope"]}}})
        msg = str(ctx.exception)
        for needle in ("page_size", "category", "include_cidrs"):
            self.assertIn(needle, msg)

    def test_bad_values_aggregated(self):
        with self.assertRaises(ConfigError) as ctx:
            config_from_dict({"infrastructure": {"type": "vmware"}, "dns": {"query_types": ["HINFO"]}})
        msg = str(ctx.exception)
        self.assertIn("infrastructure.type", msg)
        self.assertIn("dns.query_types", msg)

    def test_dns_server_required_unless_mock(self):
        with self.assertRaisesRegex(ConfigError, "dns.server is required"):
            config_from_dict({"infrastructure": {"type": "xaas"}})

    def test_env_interpolation(self):
        import os
        os.environ["DEMO_TEST_DNS"] = "10.1.2.3"
        self.addCleanup(os.environ.pop, "DEMO_TEST_DNS", None)
        cfg = config_from_dict({"infrastructure": {"type": "xaas"}, "dns": {"server": "${DEMO_TEST_DNS}"},
                                "dhcp": {"server": "${MISSING_VAR:-10.1.2.4}"}})
        self.assertEqual((cfg.dns.server, cfg.dhcp.server), ("10.1.2.3", "10.1.2.4"))

    def test_missing_env_var_is_an_error(self):
        with self.assertRaisesRegex(ConfigError, "NOPE_NOT_SET"):
            config_from_dict({"infrastructure": {"type": "mock"}, "dns": {"server": "${NOPE_NOT_SET}"}})

    def test_shipped_example_and_mock_configs_load(self):
        from pathlib import Path
        from demo_core.config import load_config
        root = Path(__file__).resolve().parents[1] / "config"
        self.assertEqual(load_config(root / "config.example.yaml").infrastructure.type, "xaas")
        self.assertEqual(load_config(root / "config.mock.yaml").infrastructure.type, "mock")


if __name__ == "__main__":
    unittest.main()
