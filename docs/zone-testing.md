# Test zones: make the DNS server authoritative for internal domains

The tool can create a test zone with records in your Universal DDI tenant, prove your DNS server
answers for it **authoritatively**, and then query those internal names as your discovered devices
(with the device identity in EDNS).

Legend: **[doc]** found in Infoblox docs/KBs/QA notes; **[check]** not confirmed, verify first.

## One-time setup

1. **An API key with a DNS role** [doc]: *DDI DNS Operator* (zones and records) or *DDI DNS Manager*.
   An Asset Insights-only key gets HTTP 401/403 here. Same variable, `INFOBLOX_API_KEY`, or point
   `zones.api_key_env` at another one.
2. **Find your DNS host id**:
   ```bash
   demo zones hosts
   ```
   Copy the id of the NIOS-X server that answers at `172.31.37.228` into `zones.dns_host`
   (format `dns/host/<id>`). Use the **DNS host id, not the on-prem host id**: a Jira bug shows the
   on-prem id is wrong for zone assignment [doc]. Which column of the output holds the server's IP
   is not documented [check]: match by name or address. Alternative: `zones.nsg: <name server group>`.
3. **Enable and edit the zone list** in `config/config.aws.yaml` (see `config.example.yaml`, section 5).

## Commands

```bash
demo zones apply --dry-run     # plan only; reads the API, writes nothing
demo zones apply               # create the zone + records (idempotent: re-running changes nothing)
demo zones verify              # does 172.31.37.228 answer authoritatively? (polls up to zones.wait_seconds)
demo zones test --limit 5 --source-mode edns   # each record queried once as each device
demo zones status              # zone exists? ours? records present? assigned to which server?
demo zones destroy --dry-run   # then without --dry-run (asks you to type 'delete'; or --yes)
```

`demo run-demo` runs the same flow when `zones.enabled: true`: create zones, verify, normal DNS,
internal-domain queries, Threat Defense, checklist. Skip it with `--skip-zones`.

### What "authoritative" means here

`verify` queries the DNS server directly for every record and for the `negative_names`:

| Check | Pass condition |
|---|---|
| Each record | NOERROR, at least one answer, **AA flag set** (authoritative answer) |
| Each negative name | NXDOMAIN with the AA flag (the server is authoritative for the zone and says "no such name") |

The AA flag is the proof: a server that merely forwards or recurses would not set it. Until the
zone has propagated to the server you will see `AA=False` or an unexpected rcode, and `verify`
keeps retrying for up to `zones.wait_seconds`.

## Safety

* **Real domains are refused.** Zone names must end in `.internal.`, `.test.`, `.example.`,
  `.invalid.`, `.localhost.` or `.home.arpa.` (override `zones.allowed_suffixes` deliberately).
  An authoritative zone for `google.com` on your server would break resolution for its clients.
* **Only what this tool made is touched.** Everything gets the tag `ManagedBy=asset-insights-ddi-demo`.
  A zone that already exists without that tag is never modified or deleted; untagged records are
  left alone; destroy deletes tagged records first, then the zone.
* **No unassigned zones.** `apply` refuses to run without `zones.dns_host` or `zones.nsg`.
* **`--dry-run` everywhere that writes.** Destroy asks for typed confirmation.

## Record types

| Type | rdata shape | Status |
|---|---|---|
| A | `{address: 10.99.0.10}` | [doc] from internal QA docs |
| MX | `{preference: 10, exchange: mail.demo.internal.}` | [doc] from internal QA docs |
| CNAME, TXT, SRV, AAAA, NS, PTR, CAA | same pattern, field names per type | **[check]** in `<tenant>/apidoc` (`dns/record`); the API's error text is printed verbatim if a shape is wrong |

Notes: record names must be relative and non-empty (apex records are not supported by the tool);
add types in the YAML exactly as the API documents them. The query side supports A, AAAA, TXT, PTR,
CNAME, MX, SRV, NS, SOA, CAA.

Quirk handled automatically [doc]: some environments reject `primary_type` as read-only
(internal bug DDIDNS-11568). The tool retries the zone creation without it.

## What to expect in DNS reports (internal domains)

From the Threat Defense documentation and KB articles [doc]:

- Domains on an **Internal Domains list** go to local resolvers instead of Threat Defense, so those
  queries generally do **not** appear in DNS Activity or Security Activity.
- The DNS Forwarding Proxy is meant to send only recursive queries to the cloud, not authoritative
  ones. On NIOS adding authoritative domains to the list is optional; for OVA / bare-metal NIOS-X
  the KB says to add the list and a local resolver.
- **Private PTR lookups never reach the cloud** (10/8, 172.16/12, 192.168/16 reverse zones are
  forwarded to local DNS), so PTR queries of asset IPs will not show in reports.
- It is not 100% reliable in practice: support cases show internal queries still appearing
  depending on resolver assignment and the DNS view's Match Clients. Treat it as something to observe.

### A clear three-step demo

1. `demo zones apply && demo zones verify`, then `demo zones test --source-mode edns`.
   Note whether the zone's names appear in Monitor > Reports > DNS Activity.
2. Add `demo.internal` to an Internal Domains list (Configure > Security > Internal Domains), attach it
   to the DNS Forwarding Proxy service with an internal resolver, and repeat step 1.
3. Query an external name alongside; it should still appear, which shows the bypass working.

## Cleaning up

```bash
demo zones destroy --yes
```
Remove the Internal Domains list entry if you added one.
