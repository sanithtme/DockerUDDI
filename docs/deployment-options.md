# Deployment options

The framework targets whatever resolver/DHCP server you configure; the provider only adds
checks, capability flags and notes. It does **not** provision anything.

Preferred order: **1. XaaS → 2. OVA → 3. Bare metal.**

```bash
demo infra recommend                                  # xaas
demo infra recommend --needs-local-dns-dhcp           # ova
demo infra recommend --xaas-unsupported               # ova (capability gap)
demo infra recommend --needs-physical                 # baremetal
```

| | XaaS (NIOS-X as a Service) | OVA (NIOS-X virtual) | Bare metal |
|---|---|---|---|
| Use when | **Default.** Stable, reusable demo tenant and the DNS/DHCP/DFP capabilities you need are supported | You need local DNS/DHCP or on-prem-style behaviour | Physical infrastructure is *part of the demo* |
| Hardware to run | none | a hypervisor | rack, power, network |
| Reuse between demos | highest | medium | lowest |
| Config | `infrastructure.type: xaas` | `ova` | `baremetal` |

## XaaS checklist (from the internal AU realm test plan)

1. Create a universal service with capabilities **DNS, DHCP and DFP** and a location. DFP is what
   puts Threat Defense on the DNS path; without it, TD scenarios will not be observed.
2. Wait for the service to reach **Ready** and receive a **Cloud Service IP**.
3. Build the IPsec tunnel (VyOS static/dynamic routing or cloud VPN) from the lab; the generator
   host needs a route through it.
4. Put the service's DNS address in `dns.server` and its DHCP address in `dhcp.server`; list the
   enabled capabilities under `infrastructure.xaas.capabilities` (preflight uses them).
5. Open lab egress on TCP 443 to your realm's portal endpoints.
6. `demo infra check`.

## OVA checklist

Deploy the NIOS-X OVA, join it with a join token, enable DNS/DHCP/DFP. Enable DNSSEC validation in
the test view if you want SERVFAIL traffic. Use `source_mode: bind` with IP aliases if you need
per-asset attribution.

## Bare metal

Same configuration surface as OVA. Choose it only when the physical box is the point.

## Generator host requirements

Python ≥ 3.10, PyYAML, `dras` on PATH (DHCP), passwordless `sudo` for `dras` (or
`use_sudo: false` when running as root), L3 reachability to the DNS/DHCP servers. Run DHCP
simulation only on networks you control: `dras` answers real DHCP servers.
