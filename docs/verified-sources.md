# Verified sources and open TODOs

Rule for this project: **no invented Infoblox endpoints, auth schemes, schemas, DRA commands or
service names.** Everything below was checked against internal documentation (found via Glean,
Nov 2026). Anything not confirmed is a stub that fails loudly and says what is needed.

> This page names internal documents. Review it before publishing the repo outside Infoblox.

## Verified and implemented

| Capability | Source (internal) | Where used |
|---|---|---|
| `dras` flags: `-i` server, `-a` MAC, `-c` relay/giaddr, `-n` count, `-p` ping mode (stop after OFFER), `-r` release after ACK, `-o` output lease file, `-f` input lease file, `-w renew`, `-O <dec>:<hex>` raw option, `-P` server port, `-I` listen interface (drasraw), `-v` | "dras / drasraw DHCP Relay Agent Simulator" tool notes (usage text) | `generators/dhcp.py` |
| Renew = `dras -i <srv> -f <leasefile> -w renew -v`, lease file line `<MAC> <IP>` | DHCP Learning Exercise 2 (Lease Lifecycle) and tool notes | `DRADHCPProvider.renew` |
| Hostname via `-O 12:<hex>` | tool notes (option 12 example) | `DRADHCPProvider.request` |
| giaddr (`-c`) selects the subnet the lease comes from | DHCP Learning Exercise 1 / tool notes | `dhcp.dra.relay_agent_ip`, `relay_map` |
| `dras` normally runs with `sudo`; no reply prints "no replies received" | Exercises 1-2 | success detection, `use_sudo` |
| `dras`/`drasraw` are simulators: DISCOVER/REQUEST are unicast | Exercise 1 | docs only |
| XaaS needs a universal service with DNS/DHCP/DFP capabilities, a location, reaches Ready, gets a Cloud Service IP, IPsec tunnel; clients resolve and lease through the tunnel | AU Realm CSP Tenant Test Plan (XAAS-01/02) | `XaaSProvider` |
| NIOS-X OVA / bare metal host onboarding exists as deployment options | AU Realm CSP Tenant Test Plan | `OVAProvider`, `BareMetalProvider` |
| DNSSEC validation must be enabled in test views to produce SERVFAIL | IQ DNS Traffic Generation Setup | OVA notes |
| Portal places to check: DNS Activity (DDI-04), leases visible (DDI-02), Security Activity + TI reports (TD-04), SOC Insights (TD-07, needs SOC Insights SKU) | AU Realm CSP Tenant Test Plan | `verification/` checklist |
| Asset Insights public API: `POST /api/v1/assets/search`; body `filter` (FilterEL), `category`, `fields`, `page_size` (default 100, max 1000), `page_token`, `sync.mode` FULL/DELTA; response `{data[], pagination{page_size, returned, snapshot_at, next_page_token}}`; asset fields `id, name, ip_addresses[], mac_addresses[], vendor, type[], category, os{}, providers[], tags[], first/last_seen, deleted_at`; error envelope `{error:{status,code,message,details,request_id}}`; 429 + `RateLimit-*` headers | "Asset Inventory Public API Design Document" (Asset Visibility engineering, Apr 2026), sections 4.1.1, 4.7, 4.8 | `asset_discovery/` |
| API-key auth `Authorization: token <API key>`, tenant base URL, read permission on the Search Assets API, 401/403 = bad/expired key | Service Graph Connector for Universal Asset Insights installation guide + deployment guide | `AssetInsightsClient._headers` |
| API key creation: Profile > User API Keys (interactive) or a service user key | KB 000012607 "Universal Asset Insights External API" | docs |
| TIDE Active Indicators (live threat data): `GET /tide/api/data/threats/state?type=host&rlimit=N&data_format=json` (also `class=`, `property=`, `profile=` filters; `/threats/host/{recent,hourly,daily}`; `bulk-export`), header `Authorization: Token <key>`, response `{"threat":[{host, domain, class, property, threat_level, ...}]}`; throttle 12,000 req/h and 5 req/s on `/tide/api/data/threats`; "Active indicators tool" is an Advanced-tier entitlement; UI at Monitor > Research > Active Indicators | "TIDENG APIs", "Infoblox Threat Defense - TIDE" (support training), TIDE API getting-started guide, "infoblox-security-tokens-and-licensing", licensing page, AU test plan TD-06 | `generators/tide.py`, `demo td fetch` |
| EDNS0 client-attribution options: 65523 (0xFFF3) client source IP as seen by the DFP, 4 or 16 bytes; 65524 (0xFFF4) MAC; 65526 (0xFFF6) DNS view name (ASCII, set by NIOS); 65517/65518 client / customer+client ID for BloxOne Endpoints (65518 deprecated); 65521 customer ID; 65522 site ID; 65520 / 65525 source IP seen by cloud-side CoreDNS / dnsdist. NIOS *Add/Copy client IP, MAC addresses, and DNS View name to outgoing recursive queries*; unidentified clients get RCODE 18 (Prohibited) | Engineering "EDNS Options" (Portunus on-call training), NIOS "Using Forwarders" (8.6, 9.1), KB 000012509 / 000010568 / 000009554, "DFP Multi-Hop End-to-End Architecture Review", TD On-Prem Asset Discovery doc | `dns.source_mode: edns` |
| Anycast resolvers for External Networks without endpoint/DFP: 52.119.41.100 and 103.80.6.100 recommended; 52.119.40.100 and 103.80.5.100 legacy/backup with limited regional availability | Threat Defense docs, "Forwarding DNS Traffic to Infoblox Platform" | docs |
| DNS config/data API: base `https://<tenant>/api/ddi/v1`, `Authorization: Token <key>`; `POST dns/auth_zone` (`fqdn`, `primary_type: cloud`, `internal_secondaries: [{host: dns/host/<id>}]` or `nsgs: [<auth_nsg id>]`, optional `view`), `GET dns/auth_nsg?_filter=(name=='X')`, `PATCH dns/auth_zone/<uuid>`, `DELETE dns/auth_zone/<uuid>`; `POST dns/record` (`name_in_zone`, `zone`, `type`, `rdata`, `ttl`, `tags`), `PATCH dns/record`; filters `fqdn==`, `name_in_zone== and zone==`, `type==`, `tags.ManagedBy==`; record rdata `{address}` for A and `{preference, exchange}` for MX; list errors `{"error":[{"message"}]}`; DNS host ref is the DNS host id, not the on-prem host id (UDDIST-2382); some environments reject `primary_type` as read-only (DDIDNS-11568) | KB "Create an Authoritative Zone in UDDI via API Call", KB "DNS Data API / Filter", Northstar QA onboarding doc, Cato DNS Integration V3, Jira UDDIST-2382 / DDIDNS-11568 / DDIDNS-11210 | `ddi_zones/`, `demo zones` |
| IPAM/DHCP API: `POST ipam/ip_space` (`name`, `tags`), `POST ipam/address_block`, `POST ipam/subnet` (`space`, `address`, `cidr`, `name`, `dhcp_host: dhcp/host/<id>`, `tags`), `POST ipam/range` (`space`, `start`, `end`, `name`; inherits the serving host from its subnet), `GET dhcp/host`, `GET dhcp/lease`, `POST dhcp/fixed_address` (`address`, `ip_space`, `match_type`, `match_value`; `relay_hex` shown); a DHCP host's IP space is fixed by its first subnet/range; on NIOS-federated spaces `dhcp_host` is accepted but ignored (`nios_dhcp_hosts` is the field there); DHCP config takes about 30-60 s to reach the host | KB 000010531 "configure Universal DDI DHCP objects through an API call using curl", Universal DDI "Creating HA Groups" / DHCP docs, Jira UDDIST-3407 / UDDIST-3508 / DDIDHCP-3582, SaaS "Customer Environment Simulation Scenarios" (script variables: IP space, block, subnet, range, assignment host, relay/giaddr, propagation wait) | `ddi_zones/ipam.py`, `demo ipam` |
| `dns-threat-sim` (Infoblox-TME) pulls active TIDE indicators and queries them with randomised volume | TME-885 Jira | design reference only; not called |

## NOT verified: stubbed with TODO

| Item | Behaviour today | Needed to implement |
|---|---|---|
| **Asset Insights API: deployed-tenant confirmation** | Implemented from the design doc and connector guides. The design doc lists `Bearer <JWT>`; connector guides use `token <key>`; default is `token`, switchable via `auth_scheme`. KB 000012607 says to confirm the contract for the deployed release. | Run `demo discover --probe` against your tenant. It validates URL, key, scheme and response shape. If the shape differs, adjust `search_path`/normaliser. |
| **Portal verification API** (DNS Activity, Security Activity, leases, assets) | `ApiPortalVerifier` raises `NotVerifiedError`. Default is a generated manual checklist. | Documented query APIs/exports, auth + base URL per realm, response schemas, ingestion delay. |
| **Standalone DHCP release** | `release` = request then `-r`. | Confirmation from the dras owners that `-r` works against an existing lease file, or another documented method. |
| **dras output format** (assigned IP, NAK text) | Success = exit code + no "no replies received" + `Acks Received` counter if printed. The granted IP is read from the `-o` lease file (assumed same `<MAC> <IP>` shape as the `-f` input). | Documented output / `-k` parsable format. |
| **`dras` vs `drasraw` for renew** | `dhcp.dra.renew_binary` defaults to `dras` (Exercise 2); tool notes say use `drasraw` when `-f`/`-I` are needed. | Ask the tool owners which is current; set the config key. |
| **Threat domains approved for your tenant** | None shipped. | Your approved list (optionally sourced from TIDE / `dns-threat-sim`). |
| **rdata shapes for CNAME, TXT, SRV, AAAA, NS, PTR, CAA** | Not shipped as defaults; put them in the config from `<tenant>/apidoc`. The API error is shown verbatim. | The `dns/record` rdata schema per type. |
| **How to read the DNS host's IP from `dns/host`** | `demo zones hosts` prints the id, name and a few other fields; you match your server by name/address. | The documented `dns/host` field list. |
| **Apex records** (`name_in_zone` for the zone apex) | Rejected by the tool. | The documented apex convention. |
| **Whether Threat Defense honours EDNS client-IP options sent directly to anycast by a non-forwarder** | `edns` mode refuses public targets unless explicitly allowed. | Test on a NIOS/NIOS-X forwarder first (documented path); ask Threat Defense engineering about direct-to-anycast behaviour. |
| **Native DHCP client against NIOS-X** | Built from RFC 2131 and the documented relay behaviour (server replies to giaddr on UDP 67; renew sends ciaddr; release is DHCPRELEASE). Tested only against a stand-in server. | One real DORA against your NIOS-X host. |
| **`dhcp/lease` field names, and `dhcp/fixed_address` for a MAC match** | `demo ipam leases --mac` does a substring match over the whole record; fixed addresses are not created by the tool. | The documented lease schema and the `match_type`/`match_value` values for a MAC (only `relay_hex` appeared in what I found). |
| **Whether relayed leases show in your portal** | Not asserted. DDIDHCP-3582 (P1, Sydney realm NIOS-X as a Service) reported they did not; marked Done for 27.1. | Run `dras` once and read `demo ipam leases`. |
| **What the default Global Policy blocks** | Not found in the documentation searched, so nothing here asserts it. | Check your tenant's security policy (which feeds it enables), then confirm with Security Activity after a run. A domain being in TIDE does not guarantee your policy blocks it. |
| **Whether a domain is blocked vs logged** | Not asserted. `expected_action` is a presenter label only. | Your tenant's policy. |

## Not accessible when this was built

`github.com/Infoblox-TME/IQ-NIOS-Traffic-Generator` returned 404 from Glean (likely a private repo), so
it was not consulted. If it contains a documented DNS/DHCP generation approach, compare it with
`generators/` and reconcile.
