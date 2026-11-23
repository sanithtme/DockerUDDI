# Architecture

```
 Asset Insights API ──► [asset_discovery] ──► [asset_store]
 POST /api/v1/assets/search   normalise·validate·select IPs·dedupe   JSON | SQLite
 (your tenant, API key)
                                                                   │
                      ┌────────────────────────────────────────────┤
                      ▼                    ▼                       ▼
              [generators.dhcp]     [generators.dns]     [generators.threat_defense]
              DHCPProvider          A/AAAA/PTR/TXT        scenarios = DNS only
              dras | mock           paced, concurrent     config-supplied domains
                      │                    │                       │
                      └──────────► [providers]  XaaS | OVA | BareMetal | Mock ◄──┘
                                   endpoints · capabilities · preflight
                                               │
                         [demo_core.ledger] ◄──┘  every run is recorded
                                               ▼
                                   [verification] portal checklist
                                               ▼
                               [orchestrator]  `demo run-demo`
```

| Package | Responsibility |
|---|---|
| `demo_core` | typed config (unknown keys rejected), `Asset` model, IP/MAC validation, pacer, ledger, safety guards |
| `asset_discovery` | `AssetInsightsClient` (POST search, `page_token` pagination, retries honouring `Retry-After` / `RateLimit-Reset`, error-envelope parsing, `--probe`), normaliser, IP selection policy, dedupe |
| `asset_store` | `AssetStore` ABC, atomic JSON store, SQLite store; `first_seen` preserved on update |
| `generators` | `dnswire` (stdlib DNS), `dns`, `dhcp`, `threat_defense`, `domains` |
| `providers` | deployment model abstraction + recommendation logic |
| `verification` | checklist generator (default) and API verifier (stub) |
| `orchestrator` | six-step demo with per-step status, reports in `reports/demo-<ts>/` |
| `demo_cli` | the `demo` command |

Packages sit directly under `src/` (as specified in the brief), so they install as top-level
modules (`generators`, `providers`, ...). Rename or nest them if that could collide with other
packages in your environment.

## Data rules

* **Eligibility is separate for DNS and DHCP.** An asset with a valid IP but bad MAC still gets DNS
  traffic; the reverse gets DHCP only. Invalid values are recorded in `validation_errors` and
  never used. Rejected: malformed, unspecified, loopback, multicast, link-local, reserved IPv4;
  all-zero/broadcast/multicast MACs.
* **IP selection.** Assets carry `ip_addresses[]`. `ip_selection` keeps private addresses by default
  (`private_only`), optionally only `include_cidrs`, minus `exclude_cidrs`. Rejected addresses are
  listed in `metadata.excluded_ips`. The DNS generator runs one stream per distinct selected IP.
* **Dedupe.** The API already de-duplicates across providers, so only `asset_id` is on by default;
  `mac` / `ip` are opt-in (`dedupe_by`) because DHCP reuse can map different devices to one value.
* **Deleted assets** (`deleted_at` set) are skipped. `max_assets` stops discovery early.

## How the source IP reaches the portal (and the no-endpoint scenario)

Infoblox attributes DNS activity to a client IP in three ways. Pick the one that matches your demo:

| Path | Identity the portal sees | Needs |
|---|---|---|
| **Direct to anycast** (External Networks) | the public egress IP of the machine you run from, if that IP is registered as an external network | nothing else; no endpoint, no DFP |
| **Forwarder + DFP** (NIOS / NIOS-X / XaaS with DFP) | the **original client IP** inside EDNS0 option `0xFFF3` (65523), MAC in `0xFFF4` (65524), DNS view in `0xFFF6` (65526) | NIOS: *Add/Copy client IP, MAC addresses, and DNS View name to outgoing recursive queries*; NIOS-X has the same switch. DFP carries it to Threat Defense over TCP/443 |
| **BloxOne Endpoint** (roaming client) | the endpoint's client ID (option `0xFFEE`/65517); IP/MAC are whatever the endpoint reports | registering endpoints in the tenant (what IQDDI/IQTD does) |

All of this comes from internal docs (Engineering "EDNS Options", NIOS "Using Forwarders", the DFP KB
articles). Notes from those docs: the *Add* option adds the source IP **as seen by NIOS**; if one NIOS
forwards to another, use *Copy* so the true client IP survives; if an incoming query already carries
the options, they are copied unchanged; conditional-forwarding zones don't support these options;
only BIND-based DNS supports them (not Unbound).

### Scenario without a BloxOne endpoint: `dns.source_mode`

| Mode | Behaviour | Portal shows |
|---|---|---|
| `direct` (default) | queries leave this host | the host's egress IP; asset context only in the report |
| `bind` | socket binds to each asset IP | the asset IPs, but the host must own them (VM inside the network) and replies must route back |
| `edns` | each query carries the asset IP (65523) and MAC (65524) as EDNS0 options | the asset IPs, **if** the receiving NIOS/NIOS-X forwarder has Add/Copy enabled and passes them on |

`edns` mode plays the role of "the previous hop that already attached the client identity", exactly the
documented multi-hop pattern (Clients → NIOS1 → NIOS2/DFP). Set up:

1. A NIOS member or NIOS-X host with DFP, recursion enabled, **Add and Copy client IP, MAC…** turned on.
2. `dns.server` = that host (private address), `dns.source_mode: edns`.
3. Capture on the forwarder (`tcpdump -n -i any port 53 -vv`) and confirm options 65523/65524 arrive.
4. Run `demo dns run --all --limit 20 --source-mode edns`, then check DNS Activity / Security Activity.

Honest limits: I have not verified that Threat Defense accepts these options from an arbitrary client
sending **directly** to the public anycast, so `edns` refuses public targets unless
`dns.edns.allow_public_target: true`. IQTD's own code (per your notes) uses a different option
(65525) than the engineering doc lists for client IP (65523); 65525 is documented as the source IP
seen by the cloud-side dnsdist. Both are configurable (`dns.edns.ip_option`).

## DHCP caveat

`dras` leases by MAC. The IP granted equals the third-party asset IP only if the demo tenant has a
reservation/fixed address for that MAC in the matching subnet. The granted lease is captured from
`-o` and reported, so mismatches are visible rather than hidden. Relay selection uses
`relay_agent_ip` or per-subnet `relay_map`.

## Extending

* **Different Asset Insights schema**: adjust `normalize.py` (record fields) after `demo discover --probe`.
* **Automated verification**: implement `ApiPortalVerifier.verify()` in `verification/`.
* **New deployment model**: subclass `InfrastructureProvider`, register in `providers.PROVIDERS`.
* **New DHCP backend**: subclass `DHCPProvider` (discover/request/renew/release).
