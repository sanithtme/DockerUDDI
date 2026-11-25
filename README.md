# Infoblox NIOS-XaaS Demo — Backend MVP

**Author:** Sanith V Kumar, TME

Backend-only MVP for validating NIOS-XaaS deployment, AWS VPN/BGP reconciliation, DNS/DHCP/Threat Defense traffic, status, resume, and cleanup before adding a frontend.

## MVP operating model

A shared SSM controller may expose every human as Linux `ssm-user`. The MVP therefore isolates each test/demo run in its own Docker runtime. The SE supplies a name and customer label to `install-demo.sh`; the installer appends a UTC timestamp and creates a distinct container and persistent workspace.

The supplied SE name is a workspace/ownership label, not cryptographic authentication. SSM remains the access gate to the controller.

## One-time controller prerequisite

Docker must be installed and running. The administrator should configure Docker access for the account/service that runs the installer. Do not give every production SE unrestricted Docker daemon access; for the MVP this is an admin/test workflow.

## Create an isolated runtime

```bash
./install-demo.sh
```

Example input:

```text
SE name: sanith
Customer/demo name: ACME Bank
```

Example runtime:

```text
sanith-20261125-185200
```

The same SE can run the installer again and receives another timestamped isolated runtime.

## Enter the runtime and test the backend

The installer prints the exact container name. Enter it with the printed `docker exec` command, then set the API key only inside that container session:

```bash
export INFOBLOX_API_KEY='<key>'
```

Do not bake API keys into the image, Git, config examples, or installer arguments.

### Backend commands

```bash
demo readiness

demo deploy --dry-run --new   # plan a genuinely new deployment
demo deploy --new             # intentionally create a new deployment
demo deploy                   # resume/reconcile saved deployment only

demo status
demo traffic
demo cleanup
```

## Required lifecycle rules

- `--new` creates a distinct deployment and ignores unrelated existing CSP services. It never adopts an older endpoint merely because region/provider/ASN values match.
- Plain `demo deploy` resumes only the saved deployment. It reuses same-deployment CGWs, VPNs and tunnel `/30`s and never blindly recreates them.
- Foreign CSP/AWS ownership causes an ownership block with no modification.
- Deployment locking prevents concurrent mutation of the same deployment.
- Cleanup persists `phase=cleaned`, removes the deployment PSK file after successful cleanup, and cleaned deployments are not resumable.
- Shared VPC/VGW infrastructure is retained by normal cleanup.
- IPsec UP is not enough for readiness: BGP must be UP and routes must be learned before `DEMO READY`.

## Live progress and status

The container sets `PYTHONUNBUFFERED=1`. Long waits emit progress even when output is captured by Docker/logging. Checkpoints are written during deployment so another shell can run `demo status`.

Status symbols are strict:

```text
✓ confirmed successful
⠋ currently running/waiting
○ pending/not started
⚠ attention required/resumable
✗ confirmed failure
```

A stage is never marked ✓ merely because it was attempted.

Example BGP-attention state:

```text
✓ Plan
✓ NIOS-XaaS
✓ AWS VPN
✓ Demo client
✓ Tunnel endpoints
⚠ BGP / routes

Tunnel 1: IPSEC IS UP, BGP DOWN, routes=0
Tunnel 2: IPSEC IS UP, BGP DOWN, routes=0

State preserved. Correct connectivity/BGP and run: demo deploy
```

## Multiple existing services

Existing unrelated NIOS-XaaS/CSP services are allowed to coexist. A new deployment uses a new deployment ID/service network/tunnel allocation. Resume is strict and reconciles only its own saved deployment.

## DHCP isolation

Each timestamped runtime carries a unique owner/runtime identity and persistent workspace. DHCP configuration and synthetic-client state are deployment-scoped. Synthetic DHCP remains separate from Asset Insights inventory. Containers are not launched with `--privileged`; the MVP grants `NET_RAW` only. If a platform-specific DHCP path proves to require an additional capability, add only the minimum required capability after testing.

## AWS credentials inside the container

The MVP uses host networking so the container can use the controller's normal AWS instance-role/IMDS path and low-level traffic path without copying AWS credentials into the container. Verify with `aws sts get-caller-identity` if AWS CLI is installed, or `demo readiness` through boto3.

## Repository layout

```text
backend/       deployment + traffic implementation
config/        configuration examples
scripts/       supporting backend scripts
tests/         backend tests
install-demo.sh
Dockerfile
README.md
```
