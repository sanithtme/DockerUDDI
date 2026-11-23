"""Exception hierarchy. Every error carries a CLI exit code."""
from __future__ import annotations


class DemoError(Exception):
    exit_code = 1


class ConfigError(DemoError):
    exit_code = 2


class SafetyError(DemoError):
    """A safety guard refused to run (scenario not enabled, DNS target not allowed, ...)."""

    exit_code = 4


class AssetSourceError(DemoError):
    pass


class ProviderError(DemoError):
    pass


class NotVerifiedError(DemoError):
    """Raised by stubs for capabilities that are NOT verified in internal documentation.

    The message always states what information is required to implement the stub.
    """

    exit_code = 5
