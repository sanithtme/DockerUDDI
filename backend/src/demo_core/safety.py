"""Safety guards. This tool is for controlled demo/test environments only."""
from __future__ import annotations

import ipaddress

from .config import SafetyConfig
from .errors import SafetyError


def check_dns_target(server: str, safety: SafetyConfig) -> None:
    """Refuse DNS targets that are not explicitly acceptable for demo traffic."""
    if safety.allowed_dns_servers and server not in safety.allowed_dns_servers:
        raise SafetyError(
            f"DNS server {server} is not in safety.allowed_dns_servers "
            f"({', '.join(safety.allowed_dns_servers)}). Refusing to send traffic."
        )
    ip = ipaddress.ip_address(server)
    is_private = ip.is_private or ip.is_loopback or ip.is_link_local
    if not is_private and not safety.allow_public_dns_server:
        raise SafetyError(
            f"DNS server {server} is a public address. Demo traffic (especially Threat Defense "
            "scenarios) must target your demo tenant's resolver. If that resolver really has a "
            "public address, set safety.allow_public_dns_server: true."
        )


def clamp_duration(requested: float, safety: SafetyConfig) -> tuple[float, bool]:
    if requested > safety.max_duration:
        return safety.max_duration, True
    return requested, False


def clamp_total_qps(requested: float, safety: SafetyConfig) -> tuple[float, bool]:
    if requested > safety.max_total_qps:
        return safety.max_total_qps, True
    return requested, False


def check_asset_count(count: int, safety: SafetyConfig) -> None:
    if count > safety.max_assets_per_run:
        raise SafetyError(
            f"{count} distinct IP stream(s) selected, above safety.max_assets_per_run="
            f"{safety.max_assets_per_run}. Use --limit, or raise safety.max_assets_per_run "
            "(and check safety.max_total_qps) deliberately."
        )
