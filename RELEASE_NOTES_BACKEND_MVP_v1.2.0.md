# Backend MVP v1.2.0

Consolidated runtime/installer fixes from live EC2 testing.

- Installer runs container as invoking numeric UID/GID and sets HOME=/workspace.
- Backend identity prefers INFOBLOX_DEMO_OWNER and supports numeric UIDs without /etc/passwd entries.
- Installer is executable and bootstraps protected runtime storage when needed.
- Preflight verifies Docker access, bind-mount write access, CLI import, demo setup, and status.
- Retains backend MVP deployment safeguards: new-vs-resume separation, ownership blocking, existing VPN reuse, checkpointed progress/status, cleanup persistence, and resumable BGP diagnostics.
