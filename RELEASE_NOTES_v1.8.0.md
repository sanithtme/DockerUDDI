# v1.8.0

GUI-first SE workflow and cleanup/reconciliation hardening.

- API credential is the first gate; local checkpoints are not exposed as resumable before validation.
- Readiness probes the actual Infoblox API surfaces used by the demo for NIOS-XaaS, Threat Defense, DNS, DHCP/IPAM, Asset Insights, and TIDE.
- Saved deployment state is reconciled read-only against AWS resources and CSP endpoint ownership before Resume is offered.
- Stale local state is not resumed; partial/ambiguous remote state is blocked for review.
- Successful cleanup persists `phase=cleaned` plus `cleaned_at`, secures state files, removes per-deployment PSK secrets, and cleaned checkpoints are excluded from active state.
- GUI remains the SE control plane for validation, deploy, resume, traffic, monitoring, and cleanup.
- `demo web start|status|stop|restart` retained for admin operations.
- SSO/SSM Run-As and per-SE workspace isolation retained.
