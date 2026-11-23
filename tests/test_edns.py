import struct
import unittest
from dataclasses import replace

from helpers import TmpCase, make_asset, make_cfg

from demo_core.errors import ConfigError, SafetyError
from generators import dnswire
from generators.dns import DNSRunSettings, DNSTrafficGenerator, edns_options_for
from providers import MockProvider


class Wire(unittest.TestCase):
    def test_no_opt_record_by_default(self):
        q = dnswire.build_query(1, "a.example.com", "A")
        self.assertEqual(struct.unpack("!H", q[10:12])[0], 0)  # ARCOUNT
        self.assertEqual(dnswire.parse_edns_options(q), [])

    def test_options_roundtrip_and_layout(self):
        opts = [(65523, bytes([10, 20, 30, 101])), (65524, bytes.fromhex("020000000001"))]
        q = dnswire.build_query(7, "a.example.com", "TXT", edns_options=opts)
        self.assertEqual(struct.unpack("!H", q[10:12])[0], 1)
        self.assertEqual(dnswire.parse_edns_options(q), opts)
        # OPT RR: root name, TYPE 41, CLASS = payload size 1232, TTL 0
        _n, _t, _c, end = dnswire.parse_question(q)
        self.assertEqual(q[end:end + 11], b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 4 + 4 + 4 + 6))
        self.assertEqual(dnswire.parse_header(q).qdcount, 1)

    def test_empty_options_list_still_adds_opt(self):
        q = dnswire.build_query(1, "a.example.com", "A", edns_options=[])
        self.assertEqual(struct.unpack("!H", q[10:12])[0], 1)
        self.assertEqual(dnswire.parse_edns_options(q), [])

    def test_ipv6_option_data(self):
        a = make_asset(1, ip="2001:db8::5", ipv4=None, ipv6="2001:db8::5")
        s = DNSRunSettings(server="127.0.0.1")
        ip_opt = edns_options_for(a, s)[0]
        self.assertEqual((ip_opt[0], len(ip_opt[1])), (65523, 16))

    def test_mac_optional(self):
        s = DNSRunSettings(server="127.0.0.1", edns_send_mac=False)
        self.assertEqual(len(edns_options_for(make_asset(1), s)), 1)
        self.assertEqual(len(edns_options_for(make_asset(1, mac=None), replace(s, edns_send_mac=True))), 1)
        self.assertEqual(len(edns_options_for(make_asset(1), replace(s, edns_send_mac=True))), 2)


class Generator(TmpCase):
    def setUp(self):
        super().setUp()
        self.cfg = make_cfg(self.tmp, dns={"source_mode": "edns", "rate_per_asset": 4.0, "duration": 1,
                                           "concurrency": 4, "timeout": 1.0, "seed": 3})
        self.prov = MockProvider(self.cfg)
        self.prov.start()
        self.addCleanup(self.prov.stop)
        ep = self.prov.dns_endpoint()
        self.settings = DNSRunSettings.from_config(self.cfg, server=ep.host, port=ep.port)

    def test_server_receives_each_assets_ip_and_mac(self):
        gen = DNSTrafficGenerator(self.cfg)
        assets = [make_asset(1), make_asset(2)]
        s = gen.run(assets, gen.selector_for_profile("normal"), self.settings, "normal")
        self.assertEqual(s.failed, 0)
        seen = self.prov.server.by_edns
        self.assertGreater(seen[(65523, "0a141e65")], 0)   # 10.20.30.101
        self.assertGreater(seen[(65523, "0a141e66")], 0)   # 10.20.30.102
        self.assertGreater(seen[(65524, "020000000001")], 0)
        self.assertEqual(sum(v for (c, _), v in seen.items() if c == 65523), s.total)  # every query tagged
        self.assertTrue(any("source_mode=edns" in n for n in s.notes))

    def test_direct_mode_sends_no_edns(self):
        gen = DNSTrafficGenerator(self.cfg)
        s = gen.run([make_asset(1)], gen.selector_for_profile("normal"),
                    replace(self.settings, source_mode="direct"), "normal")
        self.assertGreater(s.total, 0)
        self.assertEqual(dict(self.prov.server.by_edns), {})

    def test_multi_ip_asset_tags_each_stream_with_its_own_ip(self):
        gen = DNSTrafficGenerator(self.cfg)
        a = make_asset(5, ips=["10.20.40.5", "10.20.40.6"], ip="10.20.40.5", ipv4="10.20.40.5")
        gen.run([a], gen.selector_for_profile("normal"), replace(self.settings, duration=2), "normal")
        tagged = {h for (c, h) in self.prov.server.by_edns if c == 65523}
        self.assertEqual(tagged, {"0a142805", "0a142806"})

    def test_refuses_public_target_unless_allowed(self):
        cfg = make_cfg(self.tmp, dns={"source_mode": "edns"},
                       safety={"allow_public_dns_server": True})
        gen = DNSTrafficGenerator(cfg)
        st = DNSRunSettings.from_config(cfg, server="52.119.41.100")
        with self.assertRaisesRegex(SafetyError, "NIOS / NIOS-X forwarder"):
            gen.run([make_asset(1)], gen.selector_for_profile("normal"), st, "normal")
        allowed = replace(st, edns_allow_public=True, dry_run=True)
        self.assertEqual(gen.run([make_asset(1)], gen.selector_for_profile("normal"), allowed).failed, 0)

    def test_config_validation(self):
        with self.assertRaisesRegex(ConfigError, "source_mode"):
            make_cfg(self.tmp, dns={"source_mode": "spoof"})
        with self.assertRaisesRegex(ConfigError, "ip_option"):
            make_cfg(self.tmp, dns={"edns": {"ip_option": 8}})  # 8 = ECS, not allowed here


class CLI(TmpCase):
    def test_source_mode_flag_reaches_the_generator(self):
        import io
        import json
        import yaml
        from contextlib import redirect_stderr, redirect_stdout
        from asset_store import JSONAssetStore
        from demo_cli.main import main
        raw = {"infrastructure": {"type": "mock"}, "dns": {"duration": 1, "rate_per_asset": 2},
               "store": {"path": str(self.tmp / "a.json")},
               "reporting": {"output_dir": str(self.tmp / "r"), "state_dir": str(self.tmp / "s")}}
        (self.tmp / "c.yaml").write_text(yaml.safe_dump(raw))
        JSONAssetStore(self.tmp / "a.json").upsert_many([make_asset(1)])
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            code = main(["-c", str(self.tmp / "c.yaml"), "--json", "dns", "run", "--all",
                         "--source-mode", "edns", "--dry-run"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["source_mode"], "edns")


if __name__ == "__main__":
    unittest.main()
