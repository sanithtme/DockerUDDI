# Infoblox NIOS-XaaS Demo — SE Deployment and Operations Guide

**Author:** Sanith V Kumar, TME  
**Release:** v1.2.0

This guide describes the shared-controller deployment model for Sales Engineers (SEs), the security boundaries, AWS/Infoblox resource ownership, addressing and capacity model, retry/resume behavior, and recommended production hardening.

> **Scope note:** Sections marked **Implemented** describe behavior present in this repository. Sections marked **Production recommendation** describe the target operating model and are not silently claimed as already automated.

## 1. Architecture

```text
SE identity
   |
   | AWS Identity Center / IAM
   v
AWS Systems Manager Session Manager
   |
   v
Shared Sales Controller EC2
   |-- admin-managed code + Python virtualenv
   |-- per-SE Linux identity / ~/.infoblox-demo workspace
   |-- controller EC2 IAM instance role
   |
   +---------------- AWS APIs ----------------+
   |                                           |
   |                                      Shared platform
   |                                      - VPC
   |                                      - client subnet
   |                                      - route table
   |                                      - Internet Gateway
   |                                      - VGW
   |                                           |
   |                                      per deployment
   |                                      - 2 CGWs
   |                                      - 2 VPN connections
   |                                      - demo client EC2
   |                                      - client security group
   |
   +-------------- Infoblox APIs -------------+
                                               |
                                           NIOS-XaaS
                                           - Threat Defense
                                           - DNS
                                           - DHCP
                                           - Cloud VPN/BGP
```

The controller is an orchestration host. It is not the generated demo client. SEs administer the demo from the controller; `demo deploy` creates/reconciles the per-demo AWS and Infoblox resources.

## 2. Access model: why SSM

**Production recommendation:** use AWS Systems Manager Session Manager instead of distributing a shared SSH private key.

Benefits:

- no shared `.pem` file;
- no requirement to expose TCP/22 publicly on the controller;
- SE access is granted/revoked centrally through AWS identity;
- session activity can be audited through AWS controls;
- access can be scoped to the sales-controller instance(s).

### Multi-user identity requirement

**Implemented:** `demo setup` warns when the shell identity is the shared `ssm-user`.

**Production recommendation:** configure Session Manager **Run As** so each authenticated SE lands as a unique Linux user. Example:

```text
/home/sanith/.infoblox-demo/
/home/alice/.infoblox-demo/
/home/bob/.infoblox-demo/
```

Do not rely on a shared `ssm-user` home directory for multiple simultaneous SEs. A Python virtual environment isolates Python dependencies; it is not a user security boundary.

## 3. Software isolation

The controller uses a central Python installation/virtual environment for the application. Docker is not required by this repository.

Recommended layout:

```text
/opt/infoblox-sales-demo/        admin Git checkout
/opt/infoblox-sales-demo/.venv/  admin-managed Python environment
/home/<se>/.infoblox-demo/       per-SE runtime workspace
```

Each SE workspace contains configuration, deployment checkpoints, pending plans, local secrets/PSKs, generated telemetry configuration, reports, logs and traffic state. Unique Linux users and normal filesystem permissions provide the local isolation boundary.

## 4. IAM model — three separate permission planes

Do not treat "the IAM permissions" as one role. The architecture has three different principals.

### 4.1 SE identity permissions

**Production recommendation:** the human SE identity should primarily be allowed to establish an SSM session to the approved sales controller. The SE should not need direct EC2/VPN provisioning permissions simply to operate the demo.

Typical access plane:

```text
SE IAM/Identity Center permission set
        -> SSM session access to tagged controller
        -> supporting read/session-channel permissions required by your SSM setup
```

Keep the provisioning authority on the controller instance role rather than copying AWS access keys to users.

See `docs/iam/se-ssm-policy.example.json` for a deliberately scoped example that must be adapted to your account/region/controller ARN.

### 4.2 Controller EC2 instance role

**Implemented AWS API surface:** the deployment engine discovers/creates/reconciles VPC, subnet, route table, Internet Gateway, VGW, Customer Gateways, VPN connections, route propagation, security group and demo client EC2. It reads the public Amazon Linux 2023 AMI parameter and calls STS caller identity.

The controller therefore needs the EC2/SSM read/write actions represented in `docs/iam/controller-role-policy.example.json`.

If `client_instance_profile_name` is configured, the caller launching the client also needs `iam:PassRole` for the **specific demo-client role only**. Do not grant wildcard `iam:PassRole`.

The example policy is a deployment template, not a promise that every EC2 action can be resource-scoped by AWS IAM. Validate it with IAM Access Analyzer / policy simulation in the target account.

### 4.3 Generated demo-client EC2 role

The generated client is intentionally separate from the controller. It must not receive the controller's provisioning role.

**Current code:** the client bootstrap installs DNS utilities and creates the `ibdig` helper. The deployment engine does not require the client itself to call AWS provisioning APIs.

Therefore the safest default is either:

- no instance profile if the client does not need AWS APIs; or
- a minimal client profile containing only explicitly required functions (for example SSM-managed access if you intentionally want to administer the client through Session Manager).

See `docs/iam/demo-client-role-policy.example.json`.

## 5. Network and route-table model

Default example platform configuration:

```yaml
shared_vpc:
  cidr: 10.10.0.0/16
  client_subnet_cidr: 10.10.1.0/24
service_network_pool:
  cidr: 10.20.0.0/16
  prefix: 24
```

The VPC, client subnet, route table, Internet Gateway and VGW are shared platform resources. The deployment engine reuses them when they already exist.

The client subnet's route table is shared. `demo deploy` enables VGW route propagation on the selected route table; BGP-learned service-network routes are therefore propagated through the shared VGW rather than creating a separate route table for each SE.

Per-deployment service networks must be unique to avoid route overlap.

## 6. Service IP and capacity

For every allocated service `/24`, the current allocator chooses:

```text
network + third usable host  -> NIOS-XaaS service/DNS IP
network + fourth usable host -> neighbour 1
network + fifth usable host  -> neighbour 2
```

Example:

```text
10.20.2.0/24
  service IP : 10.20.2.3
  neighbour  : 10.20.2.4
  neighbour  : 10.20.2.5
```

Threat Defense, DNS and DHCP are capabilities of the same NIOS-XaaS deployment; the repository does not allocate one service IP per capability.

A `/16` divided into `/24`s provides 256 candidate service networks mathematically. That does **not** mean 256 simultaneous demos are guaranteed: AWS VPN/VGW/route/EC2 quotas, Infoblox tenant limits and operational concurrency may be lower. Monitor quotas and active allocations.

When no free service network remains, the allocator stops rather than reusing an active network.

## 7. BGP and tunnel allocation

Default configuration:

```yaml
vpn:
  customer_gateway_asn: 65500
  aws_bgp_asn: 64512
```

**Implemented:** ASNs are configured values; they are not randomized per SE. The shared AWS VGW is created with the configured AWS ASN, and Customer Gateways use the configured customer ASN.

What is dynamically allocated is the tunnel-inside `/30`. The engine scans existing AWS VPN tunnel CIDRs and local deployment state, then selects unused `/30`s from the supported link-local pool.

The readiness gate is deliberately stronger than "IPsec is up": selected tunnels must report `UP` and have learned routes before the deployment reports `DEMO READY`.

## 8. New deployment, rerun, interruption and locking

New environment:

```bash
demo deploy --new
```

Resume/reconcile:

```bash
demo deploy
```

Never use `--new` to recover an interrupted deployment.

**Implemented:** deployment checkpoints preserve the deployment ID, service network, tunnel CIDRs, PSKs and discovered/created resource IDs. A per-deployment local lock prevents two local deploy processes from intentionally operating on the same deployment at once.

If the SE presses `Ctrl+C` or loses the terminal:

```bash
demo status
demo deploy
```

The deployment engine discovers/reuses tagged resources and continues. Long-running NIOS-XaaS/BGP operations display progress rather than appearing idle.

## 9. Same Infoblox tenant / CSP ownership

Multiple SEs may target the same tenant only when the tenant/platform supports the required concurrent endpoints and each deployment remains uniquely owned.

**Implemented safety boundary:** an existing CSP endpoint/access location is not considered reusable merely because provider, service location, ASN or other parameters match. Reuse/update requires ownership by the current deployment ID. A foreign endpoint triggers `OWNERSHIP BLOCK` before modification.

This specifically prevents a new deployment from silently overwriting an older sales demo endpoint.

For early production rollout, validate same-tenant concurrency deliberately before allowing many simultaneous demos in one tenant.

## 10. Secrets and sensitive state

Never commit:

- `INFOBLOX_API_KEY`;
- VPN PSKs;
- deployment checkpoint secrets;
- generated runtime configs containing sensitive values;
- credentials or private keys.

**Current testing:** `INFOBLOX_API_KEY` can be supplied as an environment variable.

**Production recommendation:** store the Infoblox API credential in an approved secret store such as AWS Secrets Manager and allow only the controller role to retrieve the specific secret. Do not expose the key to every SE if the application can retrieve it on their behalf.

Deployment PSK files are written with restrictive local permissions and are required to reconcile an existing matching VPN/CSP deployment safely.

## 11. Generated demo client security

**Current code:** the generated client security group is created without an ingress authorization rule. The client is launched in the shared client subnet and receives outbound connectivity through the platform network. This repository does not open SSH to the world for every generated client.

If direct SE access to the generated client is required later, prefer SSM or explicitly scoped ingress rather than `0.0.0.0/0:22`.

The client role must remain separate from the controller role.

## 12. Cleanup and cost control

Manual cleanup:

```bash
demo cleanup
```

removes deployment-owned AWS/client resources while preserving shared platform resources.

**Current limitation:** CSP deletion is intentionally conservative; unrelated CSP resources must never be deleted simply because a local deployment references them.

### Production recommendation: TTL cleanup

Add deployment metadata such as:

```text
Owner
DeploymentId
ManagedBy
CreatedAt
ExpiresAt
```

A scheduled cleanup worker can find expired deployments and invoke the same ownership-safe cleanup logic. A 48-72 hour default lifetime is a reasonable starting policy for short-lived sales demos, but choose the actual TTL based on your demo process.

Do not implement TTL cleanup as blind tag deletion. It must validate deployment ownership and retain shared VPC/subnet/route-table/VGW resources.

## 13. Concurrency and central allocation

**Current implementation:** service networks and tunnel CIDRs are selected by inspecting existing AWS resources and local deployment state. This is appropriate for controlled testing, but two brand-new deployments starting at exactly the same instant do not have a distributed atomic allocator.

**Production recommendation:** add a small central deployment registry (for example DynamoDB with conditional writes) containing:

```text
DeploymentId
Owner
Tenant
ServiceNetwork
TunnelCidrs
CreatedAt
ExpiresAt
State
```

Use conditional writes to reserve networks atomically. This also becomes the source for TTL cleanup and fleet-wide deployment visibility.

## 14. SE workflow

First login:

```bash
demo setup
demo readiness
```

New demo:

```bash
demo deploy --dry-run --new   # optional but recommended for first tests
demo deploy                   # executes saved plan
```

or directly:

```bash
demo deploy --new
```

Monitor:

```bash
demo status
```

Generate demo traffic:

```bash
demo traffic
```

Cleanup:

```bash
demo cleanup
```

## 15. Administrator checklist

Before giving the controller to SEs:

1. Create/tag the controller EC2 and attach the controller instance role.
2. Configure SSM Agent/connectivity and restrict SE session access to the controller.
3. Configure SSM Run As / unique Linux users for SEs.
4. Install the repository centrally and expose the `demo` command.
5. Create/approve the minimal demo-client role/profile if required.
6. Configure the Infoblox credential securely.
7. Validate AWS quotas for expected concurrent demos.
8. Validate same-tenant Infoblox concurrency or define one-active-demo-per-tenant policy.
9. Test `demo readiness`, dry-run, deployment, interruption/resume, ownership block, traffic and cleanup.
10. Add TTL/central allocation before high-concurrency rollout.

## 16. Security constraints summary

- no shared PEM/private SSH key;
- no public SSH requirement for the controller when SSM is used;
- unique SE OS identity for filesystem/workspace isolation;
- human SE identity does not need broad provisioning permissions;
- controller uses a dedicated least-privilege instance role;
- demo client never receives the controller role;
- `iam:PassRole` restricted to the approved client role;
- API keys/PSKs excluded from Git and logs;
- CSP ownership checked before reuse/update;
- AWS resources tagged with deployment ownership;
- shared resources are retained during normal cleanup;
- retries reconcile existing resources instead of intentionally duplicating them;
- local deployment locking prevents same-deployment double execution;
- service networks/tunnel CIDRs must be unique;
- BGP route learning is required before declaring readiness;
- production concurrency should use an atomic central allocation registry.
