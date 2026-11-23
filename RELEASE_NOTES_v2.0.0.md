# Release Notes v2.0.0

## Backend reconciliation hardening

- Resume discovers and reuses existing VPN connections by `DeploymentId` before creating anything.
- Legacy VPNs without an `Owner` tag remain eligible only when `ManagedBy`, `DeploymentId`, and tunnel/name evidence match.
- `InvalidCidr.InUse` triggers rediscovery and a safe reconciliation block instead of a raw duplicate-create failure.
- New resources continue to carry `Owner`, `ManagedBy`, and `DeploymentId` tags.
- Customer/demo labels are descriptive only and never establish authorization.
- Backend readiness, cleanup-state persistence, GUI-first workflow, and web lifecycle controls from v1.9 are retained.
