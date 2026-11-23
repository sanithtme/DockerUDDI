import unittest
from dataclasses import replace

from helpers import TmpCase, make_asset, make_cfg

from demo_core.errors import ConfigError, SafetyError
from generators import dnswire
from generators.dns import DNSRunSettings, DNSTrafficGenerator, expand_ip_streams
from generators.domains import parse_domain_entries
from generators.threat_defense import ThreatDefenseGenerator
from providers import MockProvider


class Wire(unittest.TestCase):
    def test_query_roundtrip(self):
        q = dnswire.build_query(0x1234, "www.example.com", "AAAA")
        h = dnswire.parse_header(q)
        self.assertEqual((h.txid, h.qdcount, h.qr), (0x1234, 1, False))
        self.assertEqual(dnswire.parse_question(q)[:3], ("www.example.com", 28, 1))

    def test_response_rcodes(self):
        q = dnswire.build_query(1, "x.example.com", "A")
        self.assertEqual(dnswire.parse_header(dnswire.build_response(q, 3)).rcode, 3)
        ok = dnswire.parse_header(dnswire.build_response(q, 0))
        self.assertEqual((ok.rcode, ok.ancount, ok.qr), (0, 1, True))

    def test_bad_names(self):
        for bad in ("a" * 64 + ".com", "a..com", ("a" * 60 + ".") * 5 + "com"):
            with self.assertRaises(ValueError):
                dnswire.encode_name(bad)

    def test_reverse_name(self):
        self.assertEqual(dnswire.reverse_name("10.20.30.101"), "101.30.20.10.in-addr.arpa")


class Domains(unittest.TestCase):
    def test_forms_and_normalisation(self):
        e = parse_domain_entries(["A.Example.com.", {"name": "b.example.net", "category": "Blocked"}], "t")
        self.assertEqual([(x.name, x.category) for x in e], [("a.example.com", "default"),
                                                            ("b.example.net", "blocked")])

    def test_rejections(self):
        for bad in ("10.1.1.1", "nodots", "bad name.com", "replace-me-1.example", {"nme": "x.com"}, 5):
            with self.assertRaises(ConfigError, msg=str(bad)):
                parse_domain_entries([bad], "t")

    def test_placeholder_allowed_only_explicitly(self):
        self.assertEqual(len(parse_domain_entries(["replace-me-1.example"], "t", allow_placeholder=True)), 1)


class Generator(TmpCase):
    def setUp(self):
        super().setUp()
        self.cfg = make_cfg(self.tmp)
        self.prov = MockProvider(self.cfg)
        self.prov.start()
        self.addCleanup(self.prov.stop)
        ep = self.prov.dns_endpoint()
        self.settings = DNSRunSettings.from_config(self.cfg, server=ep.host, port=ep.port)
        self.assets = [make_asset(i) for i in range(1, 4)]

    def test_normal_profile_hits_mock_server(self):
        gen = DNSTrafficGenerator(self.cfg)
        s = gen.run(self.assets, gen.selector_for_profile("normal"), self.settings, "normal")
        self.assertTrue(11 <= s.total <= 14, s.total)  # 3 assets * 4 qps * 1 s, real-time pacing
        self.assertEqual((s.failed, s.answered), (0, s.total))
        self.assertEqual(self.prov.server.total, s.total)
        self.assertEqual(set(s.by_asset), {"asset-001", "asset-002", "asset-003"})
        self.assertTrue(set(s.by_qtype) <= {"A", "AAAA", "PTR", "TXT"})
        self.assertEqual(s.rcodes, {"NOERROR": s.total})

    def test_ptr_targets_asset_ip(self):
        gen = DNSTrafficGenerator(self.cfg)
        s = gen.run(self.assets, gen.selector_for_profile("normal"),
                    replace(self.settings, query_types=["PTR"], duration=1), "ptr")
        self.assertTrue(all(d.endswith(".in-addr.arpa") for d in s.by_domain))
        self.assertIn("101.30.20.10.in-addr.arpa", s.by_domain)

    def test_seed_makes_selection_reproducible(self):
        gen = DNSTrafficGenerator(self.cfg)
        run = lambda: gen.run(self.assets, gen.selector_for_profile("normal"),  # noqa: E731
                              replace(self.settings, dry_run=True), "n")
        self.assertEqual(run().by_domain, run().by_domain)

    def test_dry_run_sends_nothing_and_is_instant(self):
        gen = DNSTrafficGenerator(self.cfg)
        s = gen.run(self.assets, gen.selector_for_profile("normal"),
                    replace(self.settings, dry_run=True, duration=600), "n")
        self.assertEqual(self.prov.server.total, 0)
        self.assertGreater(s.total, 1000)

    def test_ineligible_and_duplicate_ip_assets(self):
        gen = DNSTrafficGenerator(self.cfg)
        bad = make_asset(9, ip=None, ipv4=None)
        dup = make_asset(10, ip="10.20.30.101", ipv4="10.20.30.101")
        s = gen.run(self.assets + [bad, dup], gen.selector_for_profile("normal"), self.settings, "n")
        self.assertEqual(len(s.assets), 3)
        self.assertTrue(any("no validated IP" in n for n in s.notes))
        self.assertTrue(any("duplicate address" in n for n in s.notes))

    def test_one_stream_per_ip_for_multi_address_assets(self):
        gen = DNSTrafficGenerator(self.cfg)
        multi = make_asset(5, ips=["10.20.40.5", "10.20.40.6"], ip="10.20.40.5", ipv4="10.20.40.5")
        s = gen.run([multi], gen.selector_for_profile("normal"),
                    replace(self.settings, query_types=["PTR"], duration=2), "ptr")
        self.assertEqual({a["ip"] for a in s.assets}, {"10.20.40.5", "10.20.40.6"})
        self.assertEqual(set(s.by_domain), {"5.40.20.10.in-addr.arpa", "6.40.20.10.in-addr.arpa"})
        self.assertEqual(set(s.by_asset), {"asset-005"})
        self.assertEqual(s.planned_qps, 2 * self.settings.rate_per_asset)

    def test_expand_ip_streams(self):
        a = make_asset(1, ips=["10.0.0.1", "10.0.0.2"], ip="10.0.0.1", ipv4="10.0.0.1")
        b = make_asset(2, ips=["10.0.0.2", "2001:db8::2"], ip="10.0.0.2", ipv4="10.0.0.2")
        out = expand_ip_streams([a, b, make_asset(3, ip=None, ipv4=None)])
        self.assertEqual([(x.asset_id, x.ip, x.ips) for x in out],
                         [("asset-001", "10.0.0.1", ["10.0.0.1"]), ("asset-001", "10.0.0.2", ["10.0.0.2"]),
                          ("asset-002", "2001:db8::2", ["2001:db8::2"])])
        self.assertEqual(out[2].ipv6, "2001:db8::2")

    def test_no_eligible_assets(self):
        gen = DNSTrafficGenerator(self.cfg)
        s = gen.run([make_asset(9, ip=None, ipv4=None)], gen.selector_for_profile("normal"), self.settings)
        self.assertEqual(s.total, 0)

    def test_qps_and_duration_are_clamped(self):
        cfg = make_cfg(self.tmp, safety={"max_total_qps": 5, "max_duration": 1})
        gen = DNSTrafficGenerator(cfg)
        st = replace(self.settings, max_total_qps=5, duration=60, dry_run=True)
        s = gen.run(self.assets, gen.selector_for_profile("normal"), st)
        self.assertEqual(s.planned_qps, 5)
        self.assertLessEqual(s.duration_s, 1.5)
        self.assertTrue(any("clamped" in n for n in s.notes))

    def test_unreachable_server_reports_failures_not_crash(self):
        gen = DNSTrafficGenerator(self.cfg)
        st = replace(self.settings, port=1, timeout=0.2, duration=1, rate_per_asset=1)
        s = gen.run(self.assets[:1], gen.selector_for_profile("normal"), st)
        self.assertEqual(s.answered, 0)
        self.assertGreater(s.failed, 0)

    def test_safety_refuses_public_and_unlisted_servers(self):
        gen = DNSTrafficGenerator(self.cfg)
        sel = gen.selector_for_profile("normal")
        with self.assertRaisesRegex(SafetyError, "public"):
            gen.run(self.assets, sel, replace(self.settings, server="8.8.8.8"))
        cfg = make_cfg(self.tmp, safety={"allowed_dns_servers": ["10.0.0.53"]})
        with self.assertRaisesRegex(SafetyError, "allowed_dns_servers"):
            DNSTrafficGenerator(cfg).run(self.assets, sel, self.settings)

    def test_bind_to_unowned_ip_falls_back_to_direct(self):
        gen = DNSTrafficGenerator(self.cfg)
        asset = make_asset(1, ip="203.0.113.77", ipv4="203.0.113.77")  # not ours -> bind fails
        st = replace(self.settings, source_mode="bind", bind_fallback="direct", duration=1, rate_per_asset=3)
        s = gen.run([asset], gen.selector_for_profile("normal"), st)
        self.assertEqual(s.failed, 0)
        st = replace(st, bind_fallback="skip")
        s = gen.run([asset], gen.selector_for_profile("normal"), st)
        self.assertEqual(s.answered, 0)

    def test_security_demo_needs_configured_domains(self):
        cfg = make_cfg(self.tmp, threat_defense={"domains": [], "enabled_scenarios": ["blocked-domain"]})
        with self.assertRaisesRegex(ConfigError, "NO threat domains by design"):
            DNSTrafficGenerator(cfg).selector_for_profile("security-demo")

    def test_security_demo_uses_configured_domains(self):
        gen = DNSTrafficGenerator(self.cfg)
        s = gen.run(self.assets, gen.selector_for_profile("security-demo"),
                    replace(self.settings, query_types=["A"]), "security-demo")
        self.assertEqual(set(s.by_domain), {"mock-blocked-1.test", "mock-suspicious-1.test"})


class ThreatDefense(TmpCase):
    def setUp(self):
        super().setUp()
        self.cfg = make_cfg(self.tmp)
        self.prov = MockProvider(self.cfg)
        self.prov.start()
        self.addCleanup(self.prov.stop)
        ep = self.prov.dns_endpoint()
        self.settings = DNSRunSettings.from_config(self.cfg, server=ep.host, port=ep.port,
                                                   query_types=["A"], duration=1)
        self.assets = [make_asset(i) for i in range(1, 4)]

    def run_s(self, name, cfg=None, **kw):
        td = ThreatDefenseGenerator(cfg or self.cfg)
        return td.run(name, self.assets, replace(self.settings, **kw))

    def test_blocked_domain_only_blocked_category(self):
        s = self.run_s("blocked-domain")
        self.assertEqual(set(s.by_domain), {"mock-blocked-1.test"})
        self.assertEqual(s.rcodes, {"NXDOMAIN": s.total})  # mock server NXDOMAINs it
        self.assertEqual(s.kind, "threat-defense")
        self.assertTrue(any("block" in n for n in s.notes))

    def test_suspicious_domain(self):
        self.assertEqual(set(self.run_s("suspicious-domain").by_domain), {"mock-suspicious-1.test"})

    def test_normal_dns_has_no_threat_domains(self):
        s = self.run_s("normal-dns")
        self.assertFalse(any(d.startswith("mock-") for d in s.by_domain))

    def test_high_volume_applies_multiplier(self):
        base = self.run_s("normal-dns").total
        self.assertGreater(self.run_s("high-volume-dns").total, base * 3)

    def test_mixed_workload_mix(self):
        s = self.run_s("mixed-workload", duration=3)
        threat = sum(n for d, n in s.by_domain.items() if d.startswith("mock-"))
        self.assertGreater(threat, 0)
        self.assertLess(threat, s.total * 0.5)

    def test_unknown_and_not_enabled_scenarios(self):
        with self.assertRaisesRegex(ConfigError, "unknown scenario"):
            self.run_s("ddos")
        cfg = make_cfg(self.tmp, threat_defense={"enabled_scenarios": ["normal-dns"],
                                                 "domains": self.cfg.threat_defense.domains})
        with self.assertRaisesRegex(SafetyError, "not enabled"):
            self.run_s("blocked-domain", cfg)

    def test_missing_category_gives_helpful_error(self):
        cfg = make_cfg(self.tmp, threat_defense={
            "domains": [{"name": "only-suspicious.example.net", "category": "suspicious"}],
            "enabled_scenarios": ["blocked-domain"]})
        with self.assertRaisesRegex(ConfigError, "categories \\['suspicious'\\]"):
            self.run_s("blocked-domain", cfg)

    def test_placeholder_domains_refused(self):
        cfg = make_cfg(self.tmp, threat_defense={
            "domains": ["replace-me-blocked-1.example"], "enabled_scenarios": ["blocked-domain"]})
        with self.assertRaisesRegex(ConfigError, "placeholder"):
            self.run_s("blocked-domain", cfg)

    def test_scenario_override_and_bad_override(self):
        cfg = make_cfg(self.tmp, threat_defense={
            "domains": self.cfg.threat_defense.domains, "enabled_scenarios": ["mixed-workload"],
            "scenarios": {"mixed-workload": {"threat_ratio": 0.0}}})
        s = self.run_s("mixed-workload", cfg)
        self.assertFalse(any(d.startswith("mock-") for d in s.by_domain))
        bad = make_cfg(self.tmp, threat_defense={"enabled_scenarios": [], "domains": [],
                                                 "scenarios": {"mixed-workload": {"threat_ratio": 2}}})
        with self.assertRaisesRegex(ConfigError, "threat_ratio"):
            ThreatDefenseGenerator(bad).scenarios()

    def test_custom_scenario_defined_in_config(self):
        cfg = make_cfg(self.tmp, threat_defense={
            "domains": self.cfg.threat_defense.domains, "enabled_scenarios": ["my-demo"],
            "scenarios": {"my-demo": {"threat_ratio": 1.0, "categories": ["suspicious"]}}})
        self.assertEqual(set(self.run_s("my-demo", cfg).by_domain), {"mock-suspicious-1.test"})


if __name__ == "__main__":
    unittest.main()
