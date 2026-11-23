"""Shared test helpers (stdlib unittest; also runnable under pytest)."""
from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from demo_core.config import Config, config_from_dict  # noqa: E402
from demo_core.models import Asset  # noqa: E402

BASE: dict[str, Any] = {
    "asset_source": {"base_url": "http://127.0.0.1:1", "page_size": 5,
                     "retry": {"max_attempts": 4, "backoff_base": 0.0, "timeout": 5}},
    "store": {"type": "json", "path": "assets.json"},
    "infrastructure": {"type": "mock", "mock": {"nxdomain_domains": ["mock-blocked-1.test"]}},
    "dns": {"rate_per_asset": 4.0, "duration": 1, "concurrency": 4, "timeout": 1.0, "seed": 7},
    "dhcp": {"provider": "auto"},
    "threat_defense": {
        "domains": [{"name": "mock-blocked-1.test", "category": "blocked", "expected_action": "block"},
                    {"name": "mock-suspicious-1.test", "category": "suspicious"}],
        "enabled_scenarios": ["normal-dns", "blocked-domain", "suspicious-domain",
                              "high-volume-dns", "mixed-workload"],
    },
    "safety": {"max_total_qps": 500},
}


def make_cfg(tmp: str | Path, **overrides: Any) -> Config:
    """Build a Config rooted in ``tmp``. ``overrides`` replace whole top-level sections."""
    raw = copy.deepcopy(BASE)
    for key, val in overrides.items():
        if isinstance(val, dict) and isinstance(raw.get(key), dict):
            raw[key].update(copy.deepcopy(val))
        else:
            raw[key] = copy.deepcopy(val)
    tmp = Path(tmp)
    raw["store"]["path"] = str(tmp / Path(raw["store"]["path"]).name)
    raw["reporting"] = {"output_dir": str(tmp / "reports"), "state_dir": str(tmp / "state")}
    raw.setdefault("dhcp", {}).setdefault("dra", {})["lease_dir"] = str(tmp / "dhcp")
    return config_from_dict(raw)


def make_asset(i: int = 1, **kw: Any) -> Asset:
    base = dict(asset_id=f"asset-{i:03d}", hostname=f"demo-device-{i:03d}", ip=f"10.20.30.{100 + i}",
                ipv4=f"10.20.30.{100 + i}", mac=f"02:00:00:00:00:{i:02x}", device_type="workstation")
    base.update(kw)
    if "ips" not in kw:
        base["ips"] = [base["ip"]] if base.get("ip") else []
    if "macs" not in kw:
        base["macs"] = [base["mac"]] if base.get("mac") else []
    return Asset(**base)


class TmpCase(unittest.TestCase):
    """TestCase with a per-test temp directory in ``self.tmp``."""

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.tmp = Path(self._td.name)


class ApiCase(TmpCase):
    """TmpCase + a fake Asset Insights API. ``self.cfg(**overrides)`` points at it."""

    def setUp(self) -> None:
        import os
        from fake_asset_api import API_KEY, start_fake_api
        super().setUp()
        os.environ["INFOBLOX_API_KEY"] = API_KEY
        self.addCleanup(os.environ.pop, "INFOBLOX_API_KEY", None)
        self.start_api = start_fake_api
        self.api, self.url = start_fake_api()
        self.addCleanup(lambda: (self.api.shutdown(), self.api.server_close()))

    def restart_api(self, **kw):
        self.api.shutdown()
        self.api.server_close()
        self.api, self.url = self.start_api(**kw)

    def cfg(self, **overrides: Any) -> Config:
        src = {"base_url": self.url, **overrides.pop("asset_source", {})}
        return make_cfg(self.tmp, asset_source=src, **overrides)
