# GUI-only SE workflow

## Administrator

Install Docker and the repository once, then start the localhost workspace portal:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
demo-portal --host 127.0.0.1 --port 8787
```

Keep port 8787 private. SEs reach it through the approved AWS SSM port-forward workflow.

The portal automatically builds `infoblox-nios-xaas-demo:2.2.0` from the repository if the image is not present.

## Sales engineer

No shell/Docker/deployment CLI commands are required after the portal is available.

1. Open the portal in the browser.
2. Enter SE / Workspace Name.
3. Enter Customer / Demo Name.
4. Enter Infoblox API Key.
5. Click **Create / Open Workspace & Validate**.
6. Review backend readiness results.
7. Use the single recommended GUI action: Deploy New, Resume, Generate Traffic, Cleanup, or resolve a displayed blocker.

## Isolation model

The typed workspace name is an isolation selector, not proof of identity. SSM controls who can reach the controller. Each workspace maps to:

- `infoblox-demo-<workspace>` container
- `/var/lib/infoblox-nios-xaas-demo/users/<workspace>` persistent state
- deterministic localhost-only container port
- deterministic DHCP MAC namespace
- independent in-memory Infoblox credential session
- independent deployment state, locks, logs and reports

Containers use `--cap-drop ALL --cap-add NET_RAW` by default and are not privileged.

## Backend API split

Host portal:

- `POST /api/workspaces/open`
- `GET /api/workspaces`
- `GET /api/workspaces/<name>/state`
- proxied workspace actions under `/api/workspaces/<name>/...`

Per-workspace container backend remains authoritative for credential validation, readiness, deployment/reconciliation, traffic and cleanup.
