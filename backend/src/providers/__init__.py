"""DNS/DHCP infrastructure providers: XaaS, OVA, bare metal and mock."""
from __future__ import annotations

from demo_core.config import Config
from demo_core.errors import ConfigError

from .base import (Capabilities, CheckResult, Endpoint, InfrastructureProvider, Recommendation,
                   recommend_infrastructure)
from .deployments import BareMetalProvider, OVAProvider, XaaSProvider
from .mock import MockDNSServer, MockProvider

PROVIDERS: dict[str, type[InfrastructureProvider]] = {
    "xaas": XaaSProvider,
    "ova": OVAProvider,
    "baremetal": BareMetalProvider,
    "mock": MockProvider,
}


def build_provider(cfg: Config) -> InfrastructureProvider:
    try:
        return PROVIDERS[cfg.infrastructure.type](cfg)
    except KeyError:
        raise ConfigError(f"unknown infrastructure.type {cfg.infrastructure.type!r}") from None


__all__ = [
    "BareMetalProvider", "Capabilities", "CheckResult", "Endpoint", "InfrastructureProvider",
    "MockDNSServer", "MockProvider", "OVAProvider", "PROVIDERS", "Recommendation", "XaaSProvider",
    "build_provider", "recommend_infrastructure",
]
