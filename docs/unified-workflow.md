# Unified workflow

## Goal

Keep two identity populations intentionally separate:

1. **Asset Insights population** — fetched from the Infoblox portal and stored in `state/assets.json`. These IPs drive DNS telemetry. In `dns.source_mode: spoof`, Scapy places each asset IPv4 directly in the IPv4 source header; EDNS/ECS is not used.
2. **Synthetic DHCP population** — generated locally with made-up locally-administered MAC addresses and hostnames. These do not come from Asset Insights and are used only for DRAS DHCP lease traffic.

## Recommended sequence

```text
Asset Insights API
  -> state/assets.json
  -> DNS external-domain JSON
  -> Scapy spoofed DNS from asset IPv4s
  -> DNS Activity / Security Activity

Universal DDI DNS API
  -> create tagged internal zone + records
  -> verify authoritative answers
  -> query internal records using the same spoof source mode

Universal DDI IPAM/DHCP API
  -> create tagged IP space/subnet/range
  -> assign DHCP host
  -> synthetic MAC/hostname clients
  -> DRAS DISCOVER/REQUEST
  -> lease files + API lease verification
```

## Why this split

Do not reuse discovered Asset Insights MAC addresses for the DHCP workload unless that is explicitly the scenario. Reusing them makes the demo imply that a lease was obtained by the discovered physical/virtual device. Synthetic clients keep the DHCP story independent and auditable.

## DNS domains and caching

`dns.domains_file` can point to a JSON list or `{ "domains": [...] }`. The normal profile maps assets across the domain list instead of choosing the same name for every asset. A finite list still does **not** guarantee a cache miss. If every query must force authoritative recursion, use unique names under a test zone you control (per-asset/per-run labels) and create matching/wildcard records as appropriate.

## Source modes

- `direct`: generator host is the packet source.
- `bind`: requires the generator host to own the asset IP.
- `edns`: preserves client identity in configured EDNS options for a compatible forwarder path.
- `spoof`: authorized lab only; Scapy writes the asset IPv4 into the actual IPv4 source header. This is send-only and responses route toward the spoofed address.

## Safety

Keep `safety.allowed_dns_servers` populated, use tagged zone/IPAM objects, dry-run provisioning first, and begin traffic with a small asset limit. Cloud source/destination checks, routing, NACLs and security controls can affect spoofed traffic.

## File locations

`dns.domains_file` may be absolute or relative. Relative domain-file paths are resolved against the directory containing the selected YAML config. `store.path` may likewise be set to an absolute path when the saved Asset Insights inventory lives elsewhere.


## Server selection

The customer normally supplies server addresses only. `zones` resolves `dns.server` to exactly one `dns/host` object and `ipam` resolves `dhcp.server` to exactly one `dhcp/host` object. If no match or multiple matches are found, the command stops and asks for the explicit override rather than guessing.
