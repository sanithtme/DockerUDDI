# Local Web UI Guide

**Author:** Sanith V Kumar, TME

The web UI is a thin local control plane over the existing `demo` CLI. It does not implement a second AWS/Infoblox deployment engine.

## Security model

The server binds to `127.0.0.1:8787` by default. Do not open port 8787 in the EC2 security group. The recommended path is AWS authentication -> SSM port forwarding -> localhost web UI. AWS credentials remain in the controller instance role; `INFOBLOX_API_KEY` and VPN PSKs are never returned by the web API.

A non-loopback bind is refused unless `INFOBLOX_DEMO_ALLOW_REMOTE_WEB=1` is explicitly set. That override is not recommended without adding an authenticated TLS reverse proxy.

## Start on the controller

```bash
cd /opt/infoblox-sales-demo
source .venv/bin/activate
demo setup
demo web
```

Default URL on the controller: `http://127.0.0.1:8787`.

## Reach it from an SE workstation

Use an SSM port-forwarding session to map local port 8787 to controller port 8787. The exact AWS CLI command depends on the controller instance ID/profile/region used by your organization. After the tunnel is established, browse to `http://127.0.0.1:8787` on the workstation.

Do not add an inbound EC2 security-group rule for 8787 merely to make the UI reachable.

## Operations

The page exposes Readiness, Deploy new, Resume, Generate traffic, Interrupt and Cleanup. Deploy new requires a confirmation dialog. Cleanup additionally requires the active deployment ID to be typed exactly. The backend refuses to start another web job while one is running.

Deployment output is written under `~/.infoblox-demo/web-jobs/` and tailed by the UI. Closing the browser does not terminate the server-side job. Reopen the page to see the current job and saved deployment state. If a deployment was interrupted, use Resume rather than Deploy new.

## Multi-user requirement

The web process inherits the Linux user's `INFOBLOX_DEMO_WORKSPACE`. For a shared controller, configure SSM Run As / unique Linux users so each SE gets a separate home and `~/.infoblox-demo`. Do not run concurrent SE web sessions as the shared `ssm-user` account.

## Production operation

For an initial test, run `demo web` in the SE's SSM shell. For persistent operation, create a user-scoped systemd unit or another supervised process after the SSM Run As identity model is finalized. Keep the listener loopback-only.
