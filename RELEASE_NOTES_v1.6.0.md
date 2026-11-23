# v1.6.0

- Enforces per-SE workspace ownership and restrictive permissions.
- Supports production enforcement of unique SSM Run-As Linux identities (`INFOBLOX_DEMO_PRODUCTION=1`).
- Adds OS-side SE account bootstrap helper and SSM Run-As guide.
- Adds `Owner` tagging to deployment-owned AWS resources where created by the engine.
- Cleanup state is reflected immediately by the web UI: no active deployment, Resume disabled, stale confirmation cleared.
- Readiness is simplified to AWS access plus Infoblox authentication/capability/entitlement presentation.
- Asset Insights and TIDE remain pending until actually probed; they are no longer shown as confirmed merely because an API key exists.
- Removes internal DHCP synthetic/configuration terminology from the readiness UI.
