import json
import os
import unittest

from helpers import ApiCase, TmpCase, make_asset, make_cfg

from asset_discovery import AssetInsightsClient
from asset_store import JSONAssetStore, SQLiteAssetStore, open_store
from demo_core.errors import AssetSourceError
from fake_asset_api import API_KEY, build_records


def client(cfg, **kw):
    return AssetInsightsClient(cfg.asset_source, sleep=kw.pop("sleep", lambda s: None), **kw)


class Contract(ApiCase):
    def test_request_follows_documented_contract(self):
        cfg = self.cfg(asset_source={"filter": 'vendor = "Dell"', "category": "devices",
                                     "fields": ["id", "name", "ip_addresses"], "page_size": 50})
        client(cfg).probe()
        path, headers, body = self.api.state.requests[0]
        self.assertEqual(path, "/api/v1/assets/search")
        self.assertEqual(headers["Authorization"], f"token {API_KEY}")
        self.assertEqual(headers["X-Client-Id"], "asset-insights-ddi-demo")
        self.assertEqual(body, {"page_size": 1, "filter": 'vendor = "Dell"', "category": "devices",
                                "fields": ["id", "name", "ip_addresses"], "sync": {"mode": "FULL"}})

    def test_optional_fields_omitted_when_unset(self):
        cfg = self.cfg(asset_source={"sync_mode": None})
        client(cfg).probe()
        self.assertEqual(self.api.state.requests[0][2], {"page_size": 1})

    def test_auth_scheme_switch(self):
        cfg = self.cfg(asset_source={"auth_scheme": "Bearer"})
        with self.assertRaisesRegex(AssetSourceError, "HTTP 401"):
            client(cfg).probe()
        self.assertTrue(self.api.state.requests[0][1]["Authorization"].startswith("Bearer "))

    def test_probe_reports_shape(self):
        info = client(self.cfg()).probe()
        self.assertEqual((info["returned"], info["ok"]), (1, True))
        self.assertIn("ip_addresses", info["record_keys"])
        self.assertEqual(info["pagination"]["snapshot_at"], "2026-11-11T10:00:00Z")


class Discovery(ApiCase):
    def test_pagination_collects_everything(self):
        res = client(self.cfg()).discover()  # 18 raw records, page_size 5 -> 4 pages
        self.assertEqual((res.pages, res.raw_count), (4, 18))
        self.assertEqual(res.snapshot_at, "2026-11-11T10:00:00Z")
        self.assertEqual(len(self.api.state.requests), 4)
        tokens = [r[2].get("page_token") for r in self.api.state.requests]
        self.assertIsNone(tokens[0])
        self.assertTrue(all(tokens[1:]))

    def test_filtering_and_counts(self):
        res = client(self.cfg()).discover()
        ids = {a.asset_id for a in res.assets}
        self.assertNotIn("asset-deleted", ids)
        self.assertEqual(res.skipped_deleted, 1)
        self.assertEqual(len(res.assets), 17)
        self.assertEqual((res.invalid_ip, res.invalid_mac), (1, 1))
        self.assertEqual(res.dns_eligible, 16)  # all but asset-noip
        self.assertEqual(res.dhcp_eligible, 15)  # 12 + multi + v6 + noip
        self.assertEqual(res.ip_count, 17)

    def test_multi_ip_asset_and_public_ip_policy(self):
        res = client(self.cfg()).discover()
        multi = next(a for a in res.assets if a.asset_id == "asset-multi")
        self.assertEqual(multi.ips, ["10.20.40.5", "10.20.40.6"])  # public one dropped
        self.assertEqual(multi.mac, "7c:1e:52:59:f5:40")
        res = client(self.cfg(asset_source={"ip_selection": {"private_only": False}})).discover()
        self.assertEqual(len(next(a for a in res.assets if a.asset_id == "asset-multi").ips), 3)

    def test_include_cidrs(self):
        res = client(self.cfg(asset_source={"ip_selection": {"include_cidrs": ["10.20.30.0/24"]}})).discover()
        self.assertEqual(res.ip_count, 12)

    def test_provider_filter_matches_id_or_label_case_insensitively(self):
        res = client(self.cfg(asset_source={"providers": ["aws"]})).discover()
        self.assertEqual([a.asset_id for a in res.assets], ["asset-multi"])
        res = client(self.cfg(asset_source={"providers": ["Third Party Demo"]})).discover()
        self.assertEqual(len(res.assets), 12)
        self.assertEqual(res.skipped_provider, 5)  # multi (AWS) + 4 live extras without providers
        res = client(self.cfg(asset_source={"providers": ["nobody"]})).discover()
        self.assertEqual((len(res.assets), res.skipped_provider), (0, 17))

    def test_zero_max_assets_means_whole_inventory(self):
        res = client(self.cfg(asset_source={"max_assets": 0, "page_size": 2})).discover()
        self.assertEqual((len(res.assets), res.truncated, res.pages), (17, False, 9))

    def test_all_ips_including_public_and_duplicate_accounting(self):
        rows = build_records(2, extras=False) + [
            {"id": "cloud-1", "name": "ec2-a", "ip_addresses": ["10.20.30.101", "54.1.2.3"]},  # shares an IP
            {"id": "cloud-2", "name": "ec2-b", "ip_addresses": ["54.1.2.3"]}]
        self.restart_api(records=rows)
        cfg = self.cfg(asset_source={"max_assets": 0, "ip_selection": {"private_only": False}})
        res = client(cfg).discover()
        self.assertEqual((len(res.assets), res.ip_total, res.ip_count), (4, 5, 3))  # 5 entries, 3 distinct: 2 duplicates removed

    def test_max_assets_counts_only_matching_assets(self):
        res = client(self.cfg(asset_source={"providers": ["thirdparty-demo"], "max_assets": 4})).discover()
        self.assertEqual(len(res.assets), 4)
        self.assertTrue(res.truncated)

    def test_max_assets_truncates_early(self):
        res = client(self.cfg(asset_source={"max_assets": 7})).discover()
        self.assertTrue(res.truncated)
        self.assertEqual(len(res.assets), 7)
        self.assertEqual(res.pages, 2)
        self.assertTrue(any("max_assets" in w for w in res.warnings))

    def test_single_page_when_small(self):
        self.restart_api(count=3, extras=False)
        res = client(self.cfg(asset_source={"page_size": 100})).discover()
        self.assertEqual((res.pages, len(res.assets), res.truncated), (1, 3, False))

    def test_empty_inventory(self):
        self.restart_api(records=[])
        res = client(self.cfg()).discover()
        self.assertEqual((len(res.assets), res.pages), (0, 1))

    def test_dedupe_by_asset_id(self):
        rows = build_records(2, extras=False) + [dict(build_records(1, extras=False)[0],
                                                      tags=["again"], ip_addresses=["10.20.30.200"])]
        self.restart_api(records=rows)
        res = client(self.cfg()).discover()
        self.assertEqual((len(res.assets), res.duplicates_merged), (2, 1))
        merged = next(a for a in res.assets if a.asset_id == "asset-001")
        self.assertEqual(merged.ips, ["10.20.30.101", "10.20.30.200"])


class FailureModes(ApiCase):
    def test_retries_5xx_then_succeeds(self):
        self.restart_api(count=3, extras=False, fail_first=2)
        sleeps = []
        c = client(self.cfg(), sleep=sleeps.append)
        res = c.discover()
        self.assertEqual((len(res.assets), res.retries, len(sleeps)), (3, 2, 2))

    def test_429_honours_ratelimit_reset(self):
        self.restart_api(count=3, extras=False, rate_limit_first=1, ratelimit_reset=1000 + 7)
        sleeps = []
        c = client(self.cfg(), sleep=sleeps.append, now=lambda: 1000.0)
        c.discover()
        self.assertEqual(sleeps, [7.0])

    def test_gives_up_with_clear_message(self):
        self.restart_api(fail_first=100)
        with self.assertRaisesRegex(AssetSourceError, "giving up after 4 attempts"):
            client(self.cfg()).discover()

    def test_401_fails_fast_with_guidance_and_envelope_text(self):
        os.environ["INFOBLOX_API_KEY"] = "wrong"
        c = client(self.cfg())
        with self.assertRaises(AssetSourceError) as ctx:
            c.discover()
        msg = str(ctx.exception)
        for needle in ("HTTP 401", "UNAUTHORIZED", "Asset Insights read permission", "auth_scheme"):
            self.assertIn(needle, msg)
        self.assertEqual(c.retries, 0)

    def test_400_envelope_is_rendered(self):
        with self.assertRaisesRegex(AssetSourceError, "VALIDATION_ERROR: bad page_size"):
            client(self.cfg())._post({"page_size": 5000})

    def test_404_points_at_url_and_path(self):
        with self.assertRaisesRegex(AssetSourceError, "base_url.*search_path"):
            client(self.cfg(asset_source={"search_path": "/api/v1/nope"})).probe()

    def test_missing_api_key_env_var(self):
        os.environ.pop("INFOBLOX_API_KEY")
        with self.assertRaisesRegex(AssetSourceError, "INFOBLOX_API_KEY is not set"):
            client(self.cfg()).probe()

    def test_empty_or_invalid_base_url(self):
        for bad in ("", "tenant.example.com", "ftp://x"):
            with self.assertRaises(AssetSourceError, msg=bad):
                AssetInsightsClient(make_cfg(self.tmp, asset_source={"base_url": bad}).asset_source)

    def test_connection_refused_reports_giving_up(self):
        cfg = make_cfg(self.tmp, asset_source={"base_url": "http://127.0.0.1:1"})
        with self.assertRaisesRegex(AssetSourceError, "giving up"):
            client(cfg).probe()

    def test_non_search_endpoint_shape_is_detected(self):
        self.restart_api()
        cfg = self.cfg()
        c = AssetInsightsClient(cfg.asset_source)
        c._post = lambda body: {"items": []}  # an endpoint that is not the search API
        with self.assertRaisesRegex(AssetSourceError, "no 'data' list"):
            c.discover()

    def test_repeated_page_token_is_a_loop(self):
        c = client(self.cfg())
        c._post = lambda body: {"data": [{"id": "a"}], "pagination": {"next_page_token": "same"}}
        with self.assertRaisesRegex(AssetSourceError, "loop"):
            c.discover()

    def test_tls_verification_opt_out_is_explicit(self):
        cfg = make_cfg(self.tmp, asset_source={"base_url": "https://tenant.example.com", "verify_tls": False})
        self.assertIsNotNone(AssetInsightsClient(cfg.asset_source)._ssl)
        cfg = make_cfg(self.tmp, asset_source={"base_url": "https://tenant.example.com"})
        self.assertIsNone(AssetInsightsClient(cfg.asset_source)._ssl)


class Stores(TmpCase):
    def check(self, store):
        a = make_asset(1)
        a.first_seen = "2026-01-01T00:00:00Z"
        self.assertEqual(store.upsert_many([a, make_asset(2)]), (2, 0))
        again = make_asset(1, hostname="renamed", ips=["10.20.30.101", "10.20.30.250"])
        again.first_seen = "2026-06-01T00:00:00Z"
        self.assertEqual(store.upsert_many([again]), (0, 1))
        self.assertEqual(store.count(), 2)
        got = store.get("asset-001")
        self.assertEqual(got.hostname, "renamed")
        self.assertEqual(got.ips, ["10.20.30.101", "10.20.30.250"])
        self.assertEqual(got.first_seen, "2026-01-01T00:00:00Z")  # preserved
        self.assertIsNone(store.get("nope"))
        self.assertEqual([x.asset_id for x in store.list()], ["asset-001", "asset-002"])
        store.clear()
        self.assertEqual(store.count(), 0)

    def test_json(self):
        self.check(JSONAssetStore(self.tmp / "a.json"))

    def test_sqlite(self):
        s = SQLiteAssetStore(self.tmp / "a.db")
        self.addCleanup(s.close)
        self.check(s)

    def test_json_persists_across_instances(self):
        JSONAssetStore(self.tmp / "p.json").upsert_many([make_asset(3)])
        self.assertEqual(JSONAssetStore(self.tmp / "p.json").get("asset-003").ip, "10.20.30.103")

    def test_factory(self):
        s = open_store(make_cfg(self.tmp, store={"type": "sqlite", "path": "x.db"}).store)
        self.addCleanup(s.close)
        self.assertIsInstance(s, SQLiteAssetStore)


if __name__ == "__main__":
    unittest.main()
