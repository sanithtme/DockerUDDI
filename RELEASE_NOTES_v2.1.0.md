# v2.1.0

- Adds per-SE container workspace launcher for shared SSM controllers where all shell sessions are `ssm-user`.
- Typed SE name is explicitly a workspace selector, not authenticated identity.
- Deterministic per-SE container, persistent workspace, localhost port, and DHCP MAC namespace.
- Container drops all capabilities and adds only NET_RAW by default; no `--privileged`.
- Customer/demo name remains a label separate from ownership.
- Retains v2.0 VPN reconciliation: existing same-deployment VPNs are reused on Resume; foreign ownership blocks mutation.
