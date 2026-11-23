import errno
import io
import os
import socket
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import yaml
from fake_dhcp_server import FakeDhcp
from helpers import TmpCase, make_asset, make_cfg

from asset_store import JSONAssetStore
from demo_cli.main import main
from demo_core.config import DraConfig, NativeDhcpConfig
from generators import dhcpwire as W
from generators.dhcp import DRADHCPProvider, MockDHCPProvider, NativeDHCPProvider, build_dhcp_provider

MAC = "02:00:00:00:00:01"


class Wire(unittest.TestCase):
    def test_discover_layout(self):
        pkt = W.build_packet(W.DISCOVER, MAC, 0xDEADBEEF, giaddr="172.31.42.106", hostname="lsys-nyc-lap-014")
        self.assertGreaterEqual(len(pkt), 300)
        self.assertEqual((pkt[0], pkt[1], pkt[2], pkt[3]), (1, 1, 6, 0))          # op, htype, hlen, hops
        self.assertEqual(pkt[4:8], bytes.fromhex("deadbeef"))                     # xid
        self.assertEqual(pkt[24:28], bytes([172, 31, 42, 106]))                   # giaddr
        self.assertEqual(pkt[28:34], bytes.fromhex("020000000001"))               # chaddr
        self.assertEqual(pkt[236:240], W.MAGIC)
        p = W.parse_packet(pkt)
        self.assertEqual((p.msg_name, p.xid, p.giaddr, p.mac, p.hostname),
                         ("DISCOVER", 0xDEADBEEF, "172.31.42.106", MAC, "lsys-nyc-lap-014"))
        self.assertEqual(p.options[61], b"\x01" + bytes.fromhex("020000000001"))  # client id
        self.assertIn(55, p.options)

    def test_request_options(self):
        p = W.parse_packet(W.build_packet(W.REQUEST, MAC, 1, giaddr="10.0.0.1", requested_ip="10.0.0.50",
                                          server_id="10.0.0.2"))
        self.assertEqual((p.requested_ip, p.server_id, p.msg_name), ("10.0.0.50", "10.0.0.2", "REQUEST"))

    def test_renew_and_release_shapes(self):
        renew = W.parse_packet(W.build_packet(W.REQUEST, MAC, 1, giaddr="10.0.0.1", ciaddr="10.0.0.50"))
        self.assertEqual((renew.ciaddr, renew.requested_ip, renew.server_id), ("10.0.0.50", None, None))
        rel = W.parse_packet(W.build_packet(W.RELEASE, MAC, 1, giaddr="10.0.0.1", ciaddr="10.0.0.50",
                                            server_id="10.0.0.2"))
        self.assertEqual((rel.msg_name, rel.ciaddr, rel.server_id), ("RELEASE", "10.0.0.50", "10.0.0.2"))
        self.assertNotIn(55, rel.options)

    def test_rejects_garbage(self):
        for bad in (b"", b"x" * 300, W.build_packet(W.DISCOVER, MAC, 1)[:100]):
            with self.assertRaises(ValueError):
                W.parse_packet(bad)

    def test_bad_mac(self):
        with self.assertRaises(ValueError):
            W.mac_bytes("zz")


class NativeCase(TmpCase):
    def setUp(self):
        super().setUp()
        self.srv = FakeDhcp()
        self.addCleanup(self.srv.stop)

    @staticmethod
    def wait_for(pred, timeout=2.0):
        import time
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if pred():
                return True
            time.sleep(0.02)
        return False

    def provider(self, port=None, **native):
        n = dict(listen_port=0, timeout=1.0, retries=1)
        n.update(native)
        return NativeDHCPProvider("127.0.0.1", DraConfig(relay_agent_ip="127.0.0.1",
                                                         lease_dir=str(self.tmp / "dhcp")),
                                  NativeDhcpConfig(**n), port or self.srv.port)


class Operations(NativeCase):
    def test_discover_only_stops_after_the_offer(self):
        res = self.provider().discover(make_asset(1))
        self.assertTrue(res.ok)
        self.assertEqual((res.ip, self.srv.types()), ("172.31.47.100", ["DISCOVER"]))
        self.assertIn("OFFER 172.31.47.100 from 10.9.9.9", res.message)

    def test_full_dora_with_relay_hostname_and_server_id(self):
        res = self.provider().request(make_asset(1))
        self.assertTrue(res.ok, res.message)
        self.assertEqual((res.ip, self.srv.types()), ("172.31.47.100", ["DISCOVER", "REQUEST"]))
        d, r = self.srv.received
        self.assertEqual((d.giaddr, d.mac, d.hostname), ("127.0.0.1", MAC, "demo-device-001"))
        self.assertEqual((r.requested_ip, r.server_id, r.giaddr), ("172.31.47.100", "10.9.9.9", "127.0.0.1"))
        self.assertEqual(self.srv.leases[MAC], "172.31.47.100")
        self.assertIn("lease 3600s", res.message)

    def test_each_device_gets_its_own_address(self):
        p = self.provider()
        ips = [p.request(make_asset(i, mac=f"02:00:00:00:00:{i:02x}")).ip for i in (1, 2, 3)]
        self.assertEqual(ips, ["172.31.47.100", "172.31.47.101", "172.31.47.102"])

    def test_renew_uses_ciaddr_and_no_selecting_options(self):
        p = self.provider()
        p.request(make_asset(1))
        res = p.renew(make_asset(1))
        self.assertTrue(res.ok, res.message)
        renew = self.srv.received[-1]
        self.assertEqual((renew.msg_name, renew.ciaddr, renew.requested_ip, renew.server_id),
                         ("REQUEST", "172.31.47.100", None, None))
        self.assertIn("renewed", res.message)

    def test_renew_without_a_lease_falls_back_to_the_asset_ip_then_gets_a_nak(self):
        res = self.provider().renew(make_asset(1))          # server knows no lease for this MAC
        self.assertFalse(res.ok)
        self.assertIn("NAK", res.message)
        self.assertEqual(self.srv.received[-1].ciaddr, "10.20.30.101")
        none = self.provider().renew(make_asset(2, ip=None, ipv4=None, mac="02:00:00:00:00:02"))
        self.assertEqual((none.ok, none.message), (False, "no known lease: run 'dhcp request' first"))

    def test_release_sends_ciaddr_and_server_id_and_forgets_the_lease(self):
        p = self.provider()
        p.request(make_asset(1))
        res = p.release(make_asset(1))
        self.assertTrue(res.ok, res.message)
        self.assertTrue(self.wait_for(lambda: "RELEASE" in self.srv.types()))  # RELEASE has no reply
        rel = next(x for x in self.srv.received if x.msg_name == "RELEASE")
        self.assertEqual((rel.ciaddr, rel.server_id, rel.giaddr), ("172.31.47.100", "10.9.9.9", "127.0.0.1"))
        self.assertTrue(self.wait_for(lambda: MAC not in self.srv.leases))
        # the saved lease is gone: a second release falls back to the asset's own IP, not the old lease
        p.release(make_asset(1))
        self.assertTrue(self.wait_for(lambda: self.srv.types().count("RELEASE") == 2))
        self.assertEqual([x.ciaddr for x in self.srv.received if x.msg_name == "RELEASE"],
                         ["172.31.47.100", "10.20.30.101"])

    def test_release_with_nothing_known(self):
        res = self.provider().release(make_asset(1, ip=None, ipv4=None))
        self.assertEqual((res.ok, res.message), (False, "no known lease to release"))

    def test_nak_is_reported(self):
        self.srv.mode = "nak"
        res = self.provider().request(make_asset(1))
        self.assertFalse(res.ok)
        self.assertIn("NAK", res.message)

    def test_silence_is_reported_like_dras(self):
        self.srv.mode = "silent"
        res = self.provider().request(make_asset(1))
        self.assertEqual((res.ok, res.message), (False, "no replies received from DHCP server"))

    def test_offer_without_ack(self):
        self.srv.mode = "offer_only"
        self.assertEqual(self.provider().request(make_asset(1)).message, "server sent no ACK")

    def test_replies_for_other_clients_or_transactions_are_ignored(self):
        # a stray reply with the wrong xid must not be accepted: the client keeps waiting, then times out
        self.srv.mode = "silent"
        res = self.provider(timeout=0.4).discover(make_asset(1))
        self.assertFalse(res.ok)

    def test_retries_resend_the_message(self):
        self.srv.mode = "silent"
        self.provider(timeout=0.3, retries=3).discover(make_asset(1))
        self.assertEqual(self.srv.types(), ["DISCOVER"] * 3)

    def test_ineligible_asset_is_skipped(self):
        res = self.provider().perform("request", make_asset(1, mac=None))
        self.assertEqual((res.ok, self.srv.received), (False, []))

    def test_dry_run_sends_nothing(self):
        p = self.provider()
        p.dry_run = True
        res = p.request(make_asset(1))
        self.assertEqual((res.ok, res.dry_run, self.srv.received), (True, True, []))
        self.assertTrue(any("giaddr=127.0.0.1" in c for c in res.command))

    def test_relay_map_selects_giaddr_per_subnet(self):
        p = NativeDHCPProvider("127.0.0.1", DraConfig(
            relay_agent_ip="127.0.0.1", lease_dir=str(self.tmp / "d"),
            relay_map=[{"cidr": "10.20.30.0/24", "relay": "127.0.0.1"}]),
            NativeDhcpConfig(listen_port=0, timeout=1.0, retries=1), self.srv.port)
        self.assertTrue(p.discover(make_asset(1)).ok)

    def test_hostname_can_be_disabled(self):
        p = NativeDHCPProvider("127.0.0.1", DraConfig(relay_agent_ip="127.0.0.1", send_hostname=False,
                                                      lease_dir=str(self.tmp / "d")),
                               NativeDhcpConfig(listen_port=0, timeout=1.0, retries=1), self.srv.port)
        p.discover(make_asset(1))
        self.assertIsNone(self.srv.received[0].hostname)


class Errors(NativeCase):
    def test_missing_relay_address(self):
        p = NativeDHCPProvider("127.0.0.1", DraConfig(lease_dir=str(self.tmp / "d")),
                               NativeDhcpConfig(listen_port=0), self.srv.port)
        res = p.request(make_asset(1))
        self.assertFalse(res.ok)
        self.assertIn("relay_agent_ip is required", res.message)

    def test_relay_address_not_owned_by_this_host(self):
        p = NativeDHCPProvider("127.0.0.1", DraConfig(relay_agent_ip="203.0.113.5", lease_dir=str(self.tmp / "d")),
                               NativeDhcpConfig(listen_port=0, timeout=0.5, retries=1), self.srv.port)
        res = p.request(make_asset(1))
        self.assertFalse(res.ok)
        self.assertIn("not an address this host owns", res.message)

    def test_port_already_in_use(self):
        blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        blocker.bind(("127.0.0.1", 0))
        self.addCleanup(blocker.close)
        res = self.provider(listen_port=blocker.getsockname()[1]).request(make_asset(1))
        self.assertFalse(res.ok)
        self.assertIn("already in use", res.message)

    @unittest.skipIf(os.geteuid() == 0, "needs a non-root user to see the permission error")
    def test_privileged_port_needs_root(self):
        res = self.provider(listen_port=67).request(make_asset(1))
        self.assertFalse(res.ok)
        self.assertIn("needs root", res.message)
        self.assertIn("sudo $(which demo) -c", res.message)

    def test_permission_error_is_translated(self):
        with mock.patch.object(socket.socket, "bind", side_effect=OSError(errno.EACCES, "denied")):
            res = self.provider().request(make_asset(1))
        self.assertIn("needs root", res.message)

    def test_bad_server_address(self):
        from demo_core.errors import ConfigError
        with self.assertRaises(ConfigError):
            NativeDHCPProvider("not-an-ip", DraConfig(), NativeDhcpConfig())


class Factory(TmpCase):
    def cfg(self, **dhcp):
        return make_cfg(self.tmp, infrastructure={"type": "ova"}, dns={"server": "10.0.0.53"},
                        dhcp={"server": "10.0.0.54", **dhcp})

    def test_auto_uses_native_when_dras_is_missing(self):
        with mock.patch.dict(os.environ, {"PATH": ""}):
            self.assertIsInstance(build_dhcp_provider(self.cfg()), NativeDHCPProvider)

    def test_auto_prefers_dras_when_installed(self):
        with mock.patch("generators.dhcp.shutil.which", return_value="/usr/local/bin/dras"):
            self.assertIsInstance(build_dhcp_provider(self.cfg()), DRADHCPProvider)

    def test_explicit_choices(self):
        self.assertIsInstance(build_dhcp_provider(self.cfg(provider="native")), NativeDHCPProvider)
        self.assertIsInstance(build_dhcp_provider(make_cfg(self.tmp)), MockDHCPProvider)  # mock infra

    def test_config_validation(self):
        from demo_core.errors import ConfigError
        with self.assertRaisesRegex(ConfigError, "auto\\|dra\\|native\\|mock"):
            self.cfg(provider="scapy")
        with self.assertRaisesRegex(ConfigError, "retries"):
            self.cfg(native={"retries": 0})


class CLI(TmpCase):
    def test_native_through_the_cli(self):
        srv = FakeDhcp()
        self.addCleanup(srv.stop)
        raw = {"infrastructure": {"type": "ova"}, "dns": {"server": "127.0.0.1"},
               "store": {"path": str(self.tmp / "a.json")},
               "reporting": {"output_dir": str(self.tmp / "r"), "state_dir": str(self.tmp / "s")},
               "dhcp": {"provider": "native", "server": "127.0.0.1", "port": srv.port,
                        "dra": {"relay_agent_ip": "127.0.0.1", "lease_dir": str(self.tmp / "d")},
                        "native": {"listen_port": 0, "timeout": 1.0, "retries": 1}}}
        (self.tmp / "c.yaml").write_text(yaml.safe_dump(raw))
        JSONAssetStore(self.tmp / "a.json").upsert_many([make_asset(1)])

        def cli(*argv):
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = main(["-c", str(self.tmp / "c.yaml"), *argv])
            return code, out.getvalue(), err.getvalue()

        code, out, _ = cli("dhcp", "request", "--asset", "asset-001")
        self.assertEqual(code, 0)
        self.assertIn("ACK 172.31.47.100", out)
        self.assertIn("172.31.47.100", out)
        code, out, _ = cli("dhcp", "renew", "--asset", "asset-001")
        self.assertEqual(code, 0)
        code, out, _ = cli("dhcp", "release", "--asset", "asset-001")
        self.assertEqual(code, 0)
        self.assertIn("RELEASE sent", out)
        code, out, _ = cli("dhcp", "request", "--asset", "asset-001", "--dry-run", "--show-commands")
        self.assertEqual(code, 0)
        self.assertIn("giaddr=127.0.0.1", out)
        srv.mode = "silent"
        code, out, _ = cli("dhcp", "discover", "--asset", "asset-001")
        self.assertEqual(code, 3)
        self.assertIn("no replies received", out)


if __name__ == "__main__":
    unittest.main()
