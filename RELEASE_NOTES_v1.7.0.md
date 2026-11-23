# Release Notes v1.7.0

Author: Sanith V Kumar, TME

## Guided SE workflow

The web UI now enforces a guided sequence: Infoblox API credential -> validation and automatic readiness -> deployment-state discovery -> one safe recommended action (Deploy New, Resume, or Generate Traffic).

## Web service lifecycle

Added `demo web start`, `demo web status`, `demo web stop`, and `demo web restart`. The server records a per-user PID, checks health before starting duplicates, handles SIGTERM/SIGINT cleanly, and keeps the default localhost-only bind for SSM port forwarding.

## Safety retained

SSO/SSM Run-As workspace isolation, CSP ownership checks, deployment locking, checkpoint/resume behavior, exact-ID cleanup confirmation, and per-user state remain in place.
