# Per-SE container workspaces

This mode is designed for a shared SSM controller where Linux sessions all appear as `ssm-user`.

The SE types a workspace name such as `sanith` or `alice`. **This name is a workspace selector, not authentication.** AWS SSO/SSM remains the access control to the controller. Do not treat a typed name as proof of identity.

## Admin setup

Install Docker and allow the controlled launcher to manage only these demo containers. Build once:

```bash
docker build -t infoblox-nios-xaas-demo:2.2.0 .
```

Create/open an SE runtime:

```bash
demo-workspace create sanith --customer "ACME Bank"
demo-workspace create alice --customer "Contoso"
```

Each SE gets a deterministic container name, persistent directory under `/var/lib/infoblox-nios-xaas-demo/users/<name>`, and unique localhost port. The launcher publishes only on `127.0.0.1`.

The default container drops all Linux capabilities and adds only `NET_RAW`. It does not use `--privileged`. If native synthetic DHCP proves to require `NET_ADMIN` in your environment, add it only after validation; do not grant unrestricted privileged mode.

## Isolation

Application state, locks, logs, reports and session-memory credentials are process/container separated. Cloud resources remain separated by `DeploymentId`, `Owner`, and ownership reconciliation. Customer/demo name is a label only.

## DHCP

Each deployment records its own NIOS-XaaS service/DHCP target. Synthetic clients must target that deployment's DHCP service. The launcher provides a deterministic per-workspace MAC prefix to reduce cross-demo client identity collisions. Sanith and Alice can therefore use different DHCP services/ranges concurrently.

## Security limitation

Because the SE workspace name is typed, a user with controller access could type another workspace name. This is operational isolation, not strong user authentication. For stronger isolation, bind the launcher to an authenticated web/SSO identity or restrict workspace creation/attachment through an admin service.
