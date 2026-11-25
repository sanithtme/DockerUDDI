# Release 2.2.0

- Adds a host-side browser Workspace Portal (`demo-portal`).
- SE enters workspace name, customer/demo label, and Infoblox API key in one GUI.
- Portal creates/opens the per-SE Docker container automatically and waits for health.
- API key is forwarded to the selected container's in-memory credential endpoint; it is not persisted by the workspace registry.
- Readiness runs automatically after workspace creation/opening.
- Portal proxies deployment state and Deploy/Resume/Traffic/Cleanup/Interrupt actions to the isolated container backend.
- Retains per-SE persistent state, deterministic localhost port, deployment-scoped DHCP MAC namespace, restricted container capabilities, VPN reconciliation, backend prerequisite gates, cleanup persistence, and ownership protections from prior releases.
- Typed workspace name is an isolation selector, not authentication. SSM remains the controller access gate.
