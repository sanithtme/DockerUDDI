# Infoblox NIOS-XaaS Demo Automation

Automates a reusable NIOS-X as a Service Sales demo connected to AWS through AWS Site-to-Site VPN and dynamic BGP. The tool provisions or reuses shared AWS platform resources, creates tenant-specific VPN resources, enables DNS and Threat Defense, creates a dedicated demo client, and waits for BGP route learning before declaring the demo ready.

## 1. What the tool automates

For each new demo deployment the tool:

1. Validates AWS and Infoblox CSP access (`doctor`).
2. Discovers/reuses the shared AWS VPC, client subnet, route table, and managed VGW.
3. Allocates a unique NIOS-X service network from the configured pool.
4. Allocates two unused AWS-valid link-local `/30` tunnel-inside CIDRs.
5. Generates/persists IPsec PSKs (unless `IPSEC_PSK` is explicitly supplied).
6. Creates NIOS-XaaS with DNS and the Cloud VPN access location.
7. Discovers the two Infoblox Cloud VPN public IPs.
8. Creates/reuses two AWS Customer Gateways and two dynamic Site-to-Site VPN connections.
9. Updates both Infoblox primary and secondary access-location WAN IPs with AWS tunnel-1 outside IPs.
10. Enables VGW route propagation on the shared client route table.
11. Creates/reuses a dedicated EC2 demo client.
12. Waits until the selected tunnel on both VPNs is `UP` and AWS has learned BGP routes.
13. Prints `DEMO READY` only after the BGP readiness gate passes.

The second AWS-generated tunnel inside each VPN connection is intentionally not used. The design uses tunnel 1 from each of two VPN connections to map to the Infoblox primary and secondary paths.

## 2. Shared vs. per-deployment resources

### Shared platform resources

These are reused by multiple SE/demo deployments and are not removed by normal cleanup:

- AWS account and configured region
- Shared VPC
- Shared client subnet
- Shared route table
- Shared managed VGW

### Per-deployment resources

Each deployment gets its own:

- Deployment ID
- NIOS-X service network and DNS/helper IPs
- Two PSKs
- Two tunnel-inside `/30` CIDRs
- Two Infoblox Cloud VPN paths
- Two AWS Customer Gateways
- Two AWS Site-to-Site VPN connections
- Dedicated EC2 demo client/security group

AWS resources are tagged with `ManagedBy=Infoblox-Sales-Demo` and `DeploymentId=<deployment-id>` where applicable.

## 3. Safety and idempotency rules

### New deployment

Use `--new` only when you intentionally want a new demo environment.

```bash
python demo_tool.py deploy --dry-run --new
python demo_tool.py deploy
```

The dry-run creates `.pending-plan.json`. The real `deploy` reuses the saved deployment ID, service network, and tunnel CIDRs.

### Retry/resume an existing deployment

If a deployment failed or was interrupted, do **not** use `--new`. Reconcile the same deployment:

```bash
python demo_tool.py deploy --deployment-id demo-YYYYMMDD-HHMMSS-xxxxxx
```

The deployment ID is authoritative. Existing service network, tunnel CIDRs, PSKs, CGWs, VPNs, and client are reused when found. Missing/incomplete pieces are created or repaired.

### Plain `deploy`

`python demo_tool.py deploy` is intentionally conservative:

- If a dry-run pending plan exists, it executes that plan.
- If exactly one active local deployment exists, it resumes/reconciles it.
- If multiple active deployments exist, it stops and requires `--deployment-id`.
- If no resumable deployment exists, it stops and requires `--new`.

This prevents accidental duplicate environments.

### Existing CSP tenant protection

The tool does not silently adopt an unrelated NIOS-XaaS deployment. If CSP already contains an endpoint whose expected automation name does not match the requested deployment ID, deployment is blocked with `OWNERSHIP BLOCK` and no CSP changes are made.

For a matching deployment, the original PSKs must still be available in `.demo-secrets/<deployment-id>.json` or supplied via the configured `IPSEC_PSK` environment variable. The tool refuses to generate replacement PSKs for an already-existing matching CSP deployment.

## 4. Checkpoint/recovery model

Deployment state is checkpointed in `deployment-state/<deployment-id>.json` through phases such as:

- `planned`
- `csp-ready`
- `aws-vpn-ready`
- `client-ready`
- `csp-tunnels-updated`
- `ready`
- `cleaned`

This allows retries to discover and reuse resources instead of starting over.

Important deployment parameters are immutable on retry:

- Deployment ID
- Service network
- DNS/helper IP allocation
- Tunnel-inside CIDRs
- PSKs

## 5. Prerequisites

- Python virtual environment with project dependencies installed (`boto3`, `requests`, `PyYAML`).
- AWS credentials supplied through the EC2 instance role / approved AWS identity. Do not place static AWS access keys in `config.yaml`.
- Infoblox CSP service API key exported as `INFOBLOX_API_KEY`.
- AWS IAM permissions for EC2/VPC/VPN discovery and management, demo-client creation, tagging, route propagation, and narrowly scoped `iam:PassRole` for the approved client role.
- The client instance profile configured in `config.yaml` must already exist if automatic client creation is enabled.

DynamoDB is **not required**. Allocation inventory is derived from existing AWS resources/tags and local deployment state.

## 6. Configuration

The normal SE should not need to supply AWS VPC IDs, route-table IDs, VPN IDs, CGW IDs, tunnel outside IPs, service IPs, or tunnel `/30`s. Those are discovered or allocated automatically.

Typical platform configuration:

```yaml
platform:
  aws_region: eu-north-1
  shared_vpc:
    name: Infoblox-Sales-Demo
    cidr: 10.10.0.0/16
    client_subnet_cidr: 10.10.1.0/24
  service_network_pool:
    cidr: 10.20.0.0/16
    prefix: 24
  client_instance_type: t3.micro
  client_instance_profile_name: Infoblox-Demo-Client-Profile

infoblox:
  base_url: https://csp.infoblox.com
  auth_scheme: Token
  service_location: AWS Europe (Frankfurt)
  endpoint_size: S
  provision_timeout_seconds: 900
  poll_interval_seconds: 20

vpn:
  customer_gateway_asn: 65500
  aws_bgp_asn: 64512
  pre_shared_key_env: IPSEC_PSK

services:
  dns_enabled: true
  threat_defense_enabled: true
  security_policy: Default Global Policy
```

`tunnel_inside_cidrs` should not be hard-coded for reusable/multi-SE deployments; the script allocates them automatically.

## 7. Standard execution commands

### Activate the environment

```bash
cd ~/infoblox-sales-demo
source .venv/bin/activate
```

### Set the CSP API key

```bash
export INFOBLOX_API_KEY='YOUR-TENANT-SERVICE-API-KEY'
[ -n "$INFOBLOX_API_KEY" ] && echo "CSP API key: SET" || echo "CSP API key: MISSING"
```

### Validate configuration/access

```bash
python demo_tool.py doctor
```

### First/new deployment - recommended workflow

```bash
python demo_tool.py deploy --dry-run --new
```

Review the output. It should show the generated deployment ID, shared AWS resources, unique service network, DNS IP, and two unique tunnel CIDRs.

Then execute the saved plan:

```bash
python demo_tool.py deploy
```

### Retry after an error/interruption

```bash
python demo_tool.py deploy --deployment-id <deployment-id>
```

Example:

```bash
python demo_tool.py deploy --deployment-id demo-20261119-034435-3d319f
```

Do not use `--new` for a retry.

### Show status

```bash
python demo_tool.py status
```

For a specific deployment:

```bash
python demo_tool.py status --deployment-id <deployment-id>
```

### Cleanup a demo

```bash
python demo_tool.py cleanup --deployment-id <deployment-id>
```

Normal cleanup removes tenant-specific AWS resources/client allocation while retaining the shared VPC/VGW platform.

## 8. Readiness behavior

Resource creation alone is not considered success. The tool waits for the selected first tunnel of both AWS VPN connections to satisfy:

- AWS tunnel `Status == UP`
- `AcceptedRouteCount >= 1`

Only then does it print:

```text
DEMO READY deployment=<id> client=<instance-id> dns=<service-ip>
```

A known BGP race/convergence issue was encountered during development and was fixed by the engineering team. The readiness wait remains important so SEs do not receive a false success while IPsec is up but BGP is still converging.

NIOS-XaaS may advertise the service/helper addresses as `/32` routes (for example DNS and helper IPs), so readiness is based on learned-route count rather than requiring the whole service `/24` to appear as one route.

## 9. Conditions addressed during development

| Condition | Final behavior |
|---|---|
| CSP API key missing | `doctor/deploy` fails immediately with clear error |
| AWS IAM permission missing | AWS returns AccessDenied; fix role rather than using static admin credentials |
| Existing shared VPC/subnet/route table | Discovered and reused |
| Existing shared VGW | Reused |
| Route propagation already enabled | Left unchanged |
| NIOS-XaaS missing | Created automatically |
| Unrelated CSP deployment already present | Blocked; not adopted or modified |
| Matching deployment rerun | Reconcile/resume |
| Missing persisted PSKs for existing CSP deployment | Blocked; replacements are not generated |
| Duplicate CSP credential names | Creation retries with unique credential names |
| AWS-invalid PSK characters | Generated PSKs use AWS-compatible character set |
| Multiple SEs/service-network collision | Unique service network allocated from configured pool |
| Multiple SEs/tunnel CIDR collision | Existing AWS VPN tunnel CIDRs scanned; two unused `/30`s allocated |
| Retry changed service network | Fixed; saved deployment state is authoritative |
| Retry changed tunnel CIDRs | Fixed; saved plan/state is authoritative |
| Secondary CSP tunnel left at dummy IP | Both primary and secondary outside IPs updated |
| CSP rejected `cloud_bgp_ip` update | Field is not sent in update payload |
| CSP BGP update schema | Reference-aligned: BGP update sends ID, ASN, hop limit and cloud CIDR |
| IPsec up but BGP not yet ready | Wait/retry; no false `DEMO READY` |
| BGP learned `/32`s rather than `/24` | Readiness checks route count, not a specific aggregate prefix |
| Accidental duplicate `deploy` | Plain deploy resumes only an unambiguous deployment; intentional new deployment requires `--new` |
| Partial failure after resource creation | Checkpoint state + AWS tags allow reconciliation |
| Cleanup risk to shared platform | Normal cleanup retains shared VPC/VGW |
| DynamoDB dependency | Removed; not required |

## 10. Useful verification commands

### Check AWS VPN/BGP telemetry

```bash
aws ec2 describe-vpn-connections \
  --region eu-north-1 \
  --filters "Name=tag:DeploymentId,Values=<deployment-id>" \
  --query 'VpnConnections[*].{VPN:VpnConnectionId,Tunnels:VgwTelemetry[*].{IP:OutsideIpAddress,Status:Status,Routes:AcceptedRouteCount,Message:StatusMessage}}' \
  --output json
```

Expected selected tunnel behavior after convergence:

```text
Status: UP
Routes: > 0
```

### Check propagated routes

```bash
aws ec2 describe-route-tables \
  --region eu-north-1 \
  --route-table-ids <route-table-id> \
  --query 'RouteTables[0].Routes' \
  --output table
```

### Check allocated tunnel CIDRs without displaying PSKs

```bash
aws ec2 describe-vpn-connections \
  --region eu-north-1 \
  --filters "Name=tag:DeploymentId,Values=<deployment-id>" \
  --query 'VpnConnections[*].{VPN:VpnConnectionId,TunnelCIDRs:Options.TunnelOptions[*].TunnelInsideCidr}' \
  --output json
```

Avoid dumping the full `Options.TunnelOptions` object because it may expose pre-shared keys.

## 11. Git update workflow on the controller VM

If `config.yaml` contains intentional local settings, do not overwrite it just to pull code changes.

To update only tracked code safely when `demo_tool.py` has local troubleshooting edits:

```bash
cd ~/infoblox-sales-demo
cp demo_tool.py ~/demo_tool.py.local-backup
git restore demo_tool.py
git pull origin main
python -m py_compile demo_tool.py && echo "SCRIPT OK"
```

GitHub HTTPS authentication requires a Personal Access Token (PAT) rather than the GitHub account password when prompted for the password field.

## 12. Security notes

- Never commit `INFOBLOX_API_KEY`, PSKs, `.demo-secrets/`, or other credentials.
- Keep `.demo-secrets/` and `deployment-state/` out of Git.
- `.demo-secrets/<deployment-id>.json` should remain mode `0600`.
- Do not paste full AWS VPN tunnel option output into tickets/chats because it can contain PSKs.
- Keep `iam:PassRole` restricted to the approved demo-client role and EC2 service.
- Use branch protection/code review for changes to `demo_tool.py`; the controller has provisioning privileges in both AWS and CSP.

## 13. Operational decision guide

**I want a brand-new demo:**

```bash
python demo_tool.py deploy --dry-run --new
python demo_tool.py deploy
```

**My deployment failed halfway:**

```bash
python demo_tool.py deploy --deployment-id <same-id>
```

**I already ran this tenant and want to check it:**

```bash
python demo_tool.py status --deployment-id <id>
python demo_tool.py deploy --deployment-id <id>
```

The second command reconciles the existing deployment; it does not intentionally create a replacement.

**The tenant already contains an unrelated NIOS-XaaS service:**

Do not force deployment. The ownership guard should stop the operation. Use the correct tenant/deployment ID or explicitly clean the old demo through the approved process.

**I want another concurrent SE/demo deployment:**

Use the other CSP tenant's API key and intentionally start a new deployment with `--new`. The shared AWS VPC/VGW can be reused while service networks, tunnel CIDRs, CGWs, VPNs and client resources remain deployment-specific.

## 14. Residual concurrency consideration

The no-DynamoDB design intentionally avoids a central atomic allocation database. The tool scans AWS resources/tags and local deployment state before choosing service networks and tunnel CIDRs. This prevents normal sequential reuse and AWS also rejects duplicate tunnel CIDRs, but two brand-new deployments started at exactly the same instant before either has created/tagged resources can theoretically select the same free service network. For normal Sales usage, start each new deployment after its dry-run/plan has been established. If strict simultaneous atomic allocation becomes a requirement, add a central locking/allocation mechanism rather than relying only on discovery.

## 15. CSP cleanup scope

The current `cleanup` command removes the deployment-specific AWS VPN/CGW/client resources and marks the local deployment state as cleaned. It deliberately retains shared AWS platform resources. It does not currently delete the NIOS-XaaS service from CSP; CSP service deletion should follow the approved tenant cleanup process until an ownership-validated CSP delete operation is added to the tool.
