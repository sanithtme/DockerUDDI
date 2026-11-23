# Customer demo: 15 minutes, one story

**The story, in one sentence:** every device touches DNS and DHCP, and Infoblox sits there, so it knows
what is on your network, who is asking, and which device is behind a threat, with no agents and no scans.

That is the positioning Infoblox uses for Universal Asset Insights, Universal DDI and Threat Defense
(DNS/DHCP as the authoritative foundation). The demo shows it with the customer's own kind of data and
keeps the terminal in the background: **the portal is the star.**

| Who is in the room | What they care about | Act |
|---|---|---|
| NetOps / CloudOps | a complete, accurate inventory; DNS/DHCP/IPAM managed without tickets | 1, 4, 5 |
| SecOps / SOC | knowing which device is behind an alert, fast | 2, 3 |
| IT leadership / CMDB owners | trusted asset data, fewer blind spots | 1 |

## Before you present (10 minutes, not in front of the customer)

1. **Tenant check.** Acts 2 and 3 attribute demo queries (including threat domains) to a *real* asset
   identity from the inventory. Use a dedicated demo tenant, or a device you have agreed to use. In a
   shared or customer-like tenant, do not run these acts against real devices.
2. `source ~/.demo_env && cd ~/uddi && ./scripts/showcase.sh check` and fix every FAIL line.
3. **Warm the portal 5 to 10 minutes ahead**: run acts 2 and 3 once, so DNS Activity and Security
   Activity already have rows (portal ingestion lags by a few minutes). The live run then adds fresh
   ones on top.
4. **Browser tabs, in order:** Assets (inventory) · Monitor > Reports > DNS Activity · Security Activity ·
   Network > Reports > DNS Reports (optional). Filter DNS Activity and Security Activity to the demo device.
5. Pick the device: `export DEMO_ASSET=<asset-id>` (otherwise the first usable one is used).
6. Put the terminal on a second screen or a small window. Do not show config files, flags or IDs.

## The demo

Run `./scripts/showcase.sh` and press Enter between acts. Each act is one command and one portal screen.

| Act | Say (value first) | Terminal | Portal |
|---|---|---|---|
| **1. What is on your network?** (2 min) | "Asset Insights builds one inventory from DNS/DHCP plus your cloud and security tools. No agents, no scan windows." | `demo assets summary` | **Assets**: the inventory, by source and type |
| **2. Who is asking?** (3 min) | "A normal DNS log shows an IP. Watch what you see for one lookup." | `demo dns query --asset <id> --name www.google.com` | **DNS Activity**: that query with the device name, IP, MAC and OS |
| **3. Threats, with the device attached** (3 min) | "Same device, now looking up domains from our threat feed. Your SOC sees the device on the first alert." | `demo td run --scenario blocked-domain --asset <id>` | **Security Activity**: the events tied to the device |
| **4. Internal DNS as code** (4 min) | "One command creates an internal zone through the API. It is repeatable, and the server answers as the authority." | `demo zones apply`, `verify`, then the `dig` contrast, `zones test` | terminal; optionally the zone in the portal |
| **5. A new device joins** (optional, 3 min) | "A new device asks for an address, relayed like a branch router would. The lease is granted from a network created by API." | `demo ipam apply`, `dhcp request`, `ipam leases` | DHCP/IPAM: the lease |

Wrap-up line: *"Discovery, identity on every DNS query, threats tied to devices, and DDI managed as code,
all from the DNS/DHCP layer every device already uses."*

Customer proof points Infoblox has published (quote as "customers have reported", not as results of this
demo, and confirm internal-only ones before using them externally):

* "Most customers discover 20 to 40 percent more assets than they knew existed" (Universal Asset Insights page).
* A global enterprise discovered 130,000 assets within 30 minutes of integrating (customer quote on the same page).
* A security customer detected threats 35 days earlier using real-time DNS/DHCP data (internal enablement deck).
* A financial services company found 847 orphaned cloud resources, saving about $180,000 a year (case study in the decks).

## Keep it simple

* One device, one story. Do not explain EDNS, relay addresses, or the API calls unless asked.
* If asked how the identity gets attached: "the inventory already knows the device; Threat Defense matches
  the DNS client to it." Offer a deeper session rather than detouring.
* Never show `config.aws.yaml`, keys, or the `--help` output.

## If something goes wrong

| Symptom | Do |
|---|---|
| The portal row is not there yet | Show the warm-up rows from step 3 and say ingestion takes a minute or two |
| Act 3 prints failures | Skip it and talk over the warm-up events; run `demo td fetch --show` afterwards |
| `zones verify` shows NOT YET | Wait about a minute and rerun, or continue with the `dig` contrast |
| Act 5 reports no replies | Skip it. It is optional and depends on the DHCP service and `sudo` |

## Questions you will get

* **Does this need agents on devices?** No. Identity comes from DNS/DHCP and the integrations.
* **Is this real traffic?** No. It is generated, DNS only, against a demo tenant. Nothing is attacked or downloaded.
* **Where does the inventory come from?** The Asset Insights API on the tenant, the same data as the Assets page.
* **Can we automate this?** Everything shown is API-driven, which is the point of the zone and DHCP acts.

## After the demo

`./scripts/showcase.sh cleanup` removes the zone, the DHCP network and the demo lease. Threat Defense and
DNS queries leave nothing to remove.

## What has and has not been verified on your tenant

| Act | Status |
|---|---|
| 1 inventory | verified (3,867 assets fetched) |
| 2 identity in DNS Activity | verified (device IP, MAC, name and OS appeared) |
| 3 Security Activity | the queries are sent; **check the events appear and show the device** before presenting |
| 4 zones, authoritative | verified (AA flag, NXDOMAIN, queries answered) |
| 5 DHCP lease | the client got a real OFFER and ACK; **check the lease shows in the portal** and whether the device then appears as an asset (documented as a default passive source, not confirmed here) |
