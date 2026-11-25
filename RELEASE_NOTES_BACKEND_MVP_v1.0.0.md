# Backend MVP v1.0.0

- Backend-only deliverable; frontend/portal removed from the MVP path.
- One-command timestamped per-SE Docker runtime installer.
- Unbuffered progress and checkpoint-driven status semantics.
- `--new` ignores unrelated CSP deployments and creates its own service.
- Resume reuses same-deployment CGWs/VPNs/tunnel CIDRs.
- CIDR conflicts rediscover ownership and block safely when foreign/unknown.
- Cleanup persists `cleaned` and removes deployment PSKs.
- BGP timeout becomes a resumable attention state with preserved telemetry.
