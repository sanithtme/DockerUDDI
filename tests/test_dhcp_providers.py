import subprocess
import unittest
from pathlib import Path

from helpers import TmpCase, make_asset, make_cfg

from demo_core.config import DraConfig
from demo_core.errors import ConfigError, NotVerifiedError, ProviderError
from generators.dhcp import (DRADHCPProvider, MockDHCPProvider, build_dhcp_provider,
                             run_dhcp_operation)
from providers import (BareMetalProvider, MockProvider, OVAProvider, XaaSProvider, build_provider,
                       recommend_infrastructure)
from verification import ApiPortalVerifier, ManualChecklistVerifier


class FakeRunner:
    """Records commands; optionally writes the '-o' lease file like dras would."""

    def __init__(self, stdout="Discoveries sent 1\nAcks Received 1\n", rc=0, lease_ip="10.20.30.55"):
        self.calls, self.stdout, self.rc, self.lease_ip = [], stdout, rc, lease_ip

    def __call__(self, cmd, timeout):
        self.calls.append(cmd)
        if "-o" in cmd and self.lease_ip and self.rc == 0:
            mac = cmd[cmd.index("-a") + 1]
            Path(cmd[cmd.index("-o") + 1]).write_text(f"{mac} {self.lease_ip}\n")
        return subprocess.CompletedProcess(cmd, self.rc, self.stdout, "")


class DRA(TmpCase):
    def provider(self, runner, **cfg):
        base = dict(use_sudo=False, lease_dir=str(self.tmp / "dhcp"), relay_agent_ip="10.20.30.1")
        base.update(cfg)
        return DRADHCPProvider("10.0.0.54", DraConfig(**base), runner=runner)

    def test_request_uses_documented_flags_and_captures_lease(self):
        r = FakeRunner()
        res = self.provider(r).request(make_asset(1))
        cmd = r.calls[0]
        self.assertEqual(cmd[:6], ["dras", "-i", "10.0.0.54", "-a", "02:00:00:00:00:01", "-c"])
        self.assertIn("10.20.30.1", cmd)
        self.assertEqual(cmd[cmd.index("-O") + 1], "12:" + b"demo-device-001".hex())
        self.assertTrue(res.ok)
        self.assertEqual(res.ip, "10.20.30.55")

    def test_renew_writes_documented_lease_file(self):
        r = FakeRunner()
        p = self.provider(r)
        a = make_asset(1)
        p.request(a)
        res = p.renew(a)
        cmd = r.calls[-1]
        self.assertEqual(cmd[:3], ["dras", "-i", "10.0.0.54"])
        self.assertEqual(cmd[cmd.index("-w") + 1], "renew")
        self.assertEqual(Path(cmd[cmd.index("-f") + 1]).read_text().strip(), "02:00:00:00:00:01 10.20.30.55")
        self.assertEqual((res.ok, res.ip), (True, "10.20.30.55"))

    def test_renew_without_known_ip_fails_cleanly(self):
        res = self.provider(FakeRunner()).renew(make_asset(1, ip=None, ipv4=None))
        self.assertFalse(res.ok)
        self.assertIn("no known lease IP", res.message)

    def test_discover_and_release_flags(self):
        r = FakeRunner()
        p = self.provider(r)
        p.discover(make_asset(1))
        self.assertIn("-p", r.calls[-1])
        res = p.release(make_asset(1))
        self.assertIn("-r", r.calls[-1])
        self.assertIn("standalone release", res.message)

    def test_sudo_relay_map_port_and_extra_args(self):
        r = FakeRunner()
        p = DRADHCPProvider("10.0.0.54", DraConfig(
            use_sudo=True, lease_dir=str(self.tmp / "d"), send_hostname=False, extra_args=["-R", "2"],
            relay_map=[{"cidr": "10.20.30.0/24", "relay": "10.20.30.254"}], relay_agent_ip="1.1.1.1"),
            port=6767, runner=r)
        p.request(make_asset(1))
        cmd = r.calls[0]
        self.assertEqual(cmd[:4], ["sudo", "-n", "dras", "-i"])
        self.assertEqual(cmd[cmd.index("-c") + 1], "10.20.30.254")  # relay_map beats default
        self.assertIn("-P", cmd)
        self.assertNotIn("-O", cmd)
        self.assertIn("-R", cmd)

    def test_failure_modes(self):
        a = make_asset(1)
        self.assertIn("no replies", self.provider(FakeRunner("no replies received\n")).request(a).message)
        res = self.provider(FakeRunner("sudo: a password is required", rc=1)).request(a)
        self.assertFalse(res.ok)
        self.assertIn("passwordless sudo", res.message)
        self.assertIn("no ACK", self.provider(FakeRunner("Acks Received 0\n")).request(a).message)

        def boom(cmd, timeout):
            raise subprocess.TimeoutExpired(cmd, timeout)
        self.assertIn("timed out", self.provider(boom).request(a).message)

    def test_dry_run_never_executes(self):
        r = FakeRunner()
        p = DRADHCPProvider("10.0.0.54", DraConfig(use_sudo=False, lease_dir=str(self.tmp / "d")),
                            dry_run=True, runner=r)
        res = p.request(make_asset(1))
        self.assertEqual((res.ok, res.dry_run, r.calls), (True, True, []))
        self.assertTrue(res.command)

    def test_ineligible_asset_is_skipped(self):
        r = FakeRunner()
        res = self.provider(r).perform("request", make_asset(1, mac=None))
        self.assertFalse(res.ok)
        self.assertEqual(r.calls, [])

    def test_bad_server_and_operation(self):
        with self.assertRaises(ConfigError):
            DRADHCPProvider("not-an-ip", DraConfig())
        with self.assertRaises(ConfigError):
            self.provider(FakeRunner()).perform("bind", make_asset(1))

    def test_factory_reports_missing_binary(self):
        cfg = make_cfg(self.tmp, infrastructure={"type": "xaas"}, dns={"server": "10.0.0.53"},
                       dhcp={"provider": "dra", "server": "10.0.0.54",
                             "dra": {"binary": "definitely-not-installed-dras"}})
        with self.assertRaisesRegex(ProviderError, "not found on PATH"):
            build_dhcp_provider(cfg)
        self.assertIsInstance(build_dhcp_provider(cfg, dry_run=True), DRADHCPProvider)


class MockDHCP(unittest.TestCase):
    def test_lifecycle(self):
        p, a = MockDHCPProvider(), make_asset(1)
        self.assertFalse(p.renew(a).ok)  # no lease yet
        self.assertEqual(p.request(a).ip, "10.20.30.101")
        self.assertTrue(p.renew(a).ok)
        self.assertTrue(p.release(a).ok)
        self.assertFalse(p.release(a).ok)

    def test_run_operation_delays_between_assets(self):
        sleeps = []
        res = run_dhcp_operation(MockDHCPProvider(), "request", [make_asset(i) for i in (1, 2, 3)],
                                 delay=0.5, sleep=sleeps.append)
        self.assertEqual((len(res), sleeps), (3, [0.5, 0.5]))


class Providers(TmpCase):
    def test_recommendation_order(self):
        self.assertEqual(recommend_infrastructure().type, "xaas")
        self.assertEqual(recommend_infrastructure().order, ["xaas", "ova", "baremetal"])
        self.assertEqual(recommend_infrastructure(needs_local_dns_dhcp=True).type, "ova")
        self.assertEqual(recommend_infrastructure(xaas_supports_required=False).type, "ova")
        self.assertEqual(recommend_infrastructure(needs_physical=True).type, "baremetal")

    def test_factory(self):
        for kind, cls, extra in (("xaas", XaaSProvider, {"dns": {"server": "10.0.0.53"}}),
                                 ("ova", OVAProvider, {"dns": {"server": "10.0.0.53"}}),
                                 ("baremetal", BareMetalProvider, {"dns": {"server": "10.0.0.53"}}),
                                 ("mock", MockProvider, {})):
            self.assertIsInstance(build_provider(make_cfg(self.tmp, infrastructure={"type": kind}, **extra)), cls)

    def test_xaas_checks_capabilities_and_ip(self):
        cfg = make_cfg(self.tmp, infrastructure={"type": "xaas", "xaas": {
            "capabilities": ["dns"], "cloud_service_ip": "10.9.9.9"}}, dns={"server": "10.0.0.53"})
        checks = {c.name: c for c in build_provider(cfg).preflight(probe_network=False)}
        self.assertEqual(checks["xaas.capability.dns"].status, "ok")
        self.assertEqual(checks["xaas.capability.dfp"].status, "warn")
        self.assertEqual(checks["xaas.cloud_service_ip"].status, "warn")
        self.assertEqual(build_provider(cfg).capabilities().threat_defense_dns_path, False)

    def test_preflight_dns_probe(self):
        cfg = make_cfg(self.tmp)
        p = MockProvider(cfg)
        p.start()
        self.addCleanup(p.stop)
        self.assertEqual({c.name: c.status for c in p.preflight()}["dns.reachable"], "ok")
        down = make_cfg(self.tmp, infrastructure={"type": "ova"}, dns={"server": "127.0.0.1", "port": 1,
                                                                       "timeout": 0.2})
        self.assertEqual({c.name: c.status for c in build_provider(down).preflight()}["dns.reachable"], "fail")

    def test_notes_exist_for_every_model(self):
        for kind, extra in (("xaas", 1), ("ova", 1), ("baremetal", 1), ("mock", 0)):
            cfg = make_cfg(self.tmp, infrastructure={"type": kind}, **({"dns": {"server": "10.0.0.53"}} if extra else {}))
            self.assertTrue(build_provider(cfg).deployment_notes())


class Verification(TmpCase):
    def test_api_verifier_is_explicit_stub(self):
        with self.assertRaisesRegex(NotVerifiedError, "NOT verified"):
            ApiPortalVerifier().verify(make_cfg(self.tmp), [], [])

    def test_checklist_content(self):
        cfg = make_cfg(self.tmp, infrastructure={"type": "xaas"}, dns={"server": "10.0.0.53"})
        events = [
            {"kind": "dns", "label": "normal", "dns_server": "10.0.0.53", "total": 10, "answered": 10,
             "failed": 0, "rcodes": {"NOERROR": 10}, "by_asset": {"asset-001": 10},
             "started": "2026-11-11T10:00:00Z", "finished": "2026-11-11T10:00:30Z"},
            {"kind": "threat-defense", "label": "blocked-domain", "total": 5, "by_asset": {"asset-001": 5},
             "by_domain": {"x.example.net": 4, "1.0.0.10.in-addr.arpa": 1}, "started": "2026-11-11T10:01:00Z",
             "finished": "2026-11-11T10:01:30Z", "notes": ["expected actions (from config, not verified by "
                                                         "this tool): x.example.net=block"]},
            {"kind": "dhcp", "asset_id": "asset-001", "operation": "renew", "ok": True,
             "timestamp": "2026-11-11T09:59:00Z"}]
        out = ManualChecklistVerifier().verify(cfg, [make_asset(1)], events)
        md = out["markdown"]
        self.assertEqual(out["window"], ["2026-11-11T09:54:00Z", "2026-11-11T10:06:30Z"])
        for needle in ("asset-001", "02:00:00:00:00:01", "x.example.net", "Security Activity",
                       "generator host IP", "renew"):
            self.assertIn(needle, md)
        self.assertNotIn("in-addr.arpa", md)
        self.assertNotIn("rehearsal", md)

    def test_empty_ledger(self):
        md = ManualChecklistVerifier().verify(make_cfg(self.tmp), [], [])["markdown"]
        self.assertIn("no activity recorded", md)
        self.assertIn("No Threat Defense scenarios were run", md)


if __name__ == "__main__":
    unittest.main()
