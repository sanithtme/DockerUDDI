"""Shared services used by both the CLI and the orchestrator."""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from asset_discovery import AssetInsightsClient, DiscoveryResult
from asset_store import AssetStore, open_store
from demo_core.config import Config
from demo_core.errors import DemoError
from demo_core.ledger import RunLedger
from demo_core.models import Asset
from generators.dhcp import DHCPResult
from generators.dns import DNSRunSettings, RunSummary
from providers import InfrastructureProvider, build_provider


def ledger_for(cfg: Config) -> RunLedger:
    return RunLedger(Path(cfg.reporting.state_dir) / "run_ledger.jsonl")


def record_run(ledger: RunLedger, summary: RunSummary) -> None:
    ledger.append(summary.to_dict())


def record_dhcp(ledger: RunLedger, result: DHCPResult) -> None:
    ledger.append({"kind": "dhcp", **result.to_dict()})


def run_discovery(cfg: Config, store: AssetStore) -> tuple[DiscoveryResult, tuple[int, int]]:
    """Call the Asset Insights API, persist the assets, return ``(result, (inserted, updated))``."""
    result = AssetInsightsClient(cfg.asset_source).discover()
    return result, store.upsert_many(result.assets)


def select_assets(store: AssetStore, asset_id: str | None = None, limit: int | None = None,
                  require: str | None = None) -> list[Asset]:
    """Pick assets from the store.

    ``require`` ("dns", "dhcp" or "any") drops assets that cannot be used for that traffic *before*
    ``limit`` is applied, so ``--limit 5`` means five usable assets, not the first five stored.
    An explicitly named ``asset_id`` is never filtered (you see why it was skipped).
    """
    if asset_id:
        asset = store.get(asset_id)
        if asset is None:
            raise DemoError(f"asset {asset_id!r} not found in the store; run 'demo discover' first")
        return [asset]
    assets = store.list()
    if not assets:
        raise DemoError("the asset store is empty; run 'demo discover' first")
    if require:
        ok = {"dns": lambda a: a.dns_eligible, "dhcp": lambda a: a.dhcp_eligible,
              "any": lambda a: a.dns_eligible or a.dhcp_eligible}[require]
        usable = [a for a in assets if ok(a)]
        if not usable:
            what = {"dns": "an IP", "dhcp": "a MAC", "any": "an IP or MAC"}[require]
            raise DemoError(f"none of the {len(assets)} stored assets has a validated {what}. "
                            "Check asset_source.ip_selection "
                            "(private_only) and re-run 'demo discover'.")
        assets = usable
    return assets[:limit] if limit else assets


def dns_settings(cfg: Config, provider: InfrastructureProvider, **overrides: Any) -> DNSRunSettings:
    ep = provider.dns_endpoint()
    return DNSRunSettings.from_config(cfg, server=ep.host, port=ep.port, **overrides)


@contextmanager
def runtime(cfg: Config) -> Iterator[tuple[InfrastructureProvider, AssetStore]]:
    """Start the infrastructure provider and open the store; always clean up."""
    provider = build_provider(cfg)
    store = open_store(cfg.store)
    provider.start()
    if provider.kind == "mock" and cfg.zones.zones:
        from ddi_zones import parse_zone_specs

        provider.emulate_zones(parse_zone_specs(cfg))  # type: ignore[attr-defined]
    try:
        yield provider, store
    finally:
        provider.stop()
        store.close()
