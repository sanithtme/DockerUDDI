# Safety

For **controlled demo/test environments only.**

## Hard rules built into the code

* **DNS only.** No malware, exploits, scanning or destructive traffic. Threat Defense scenarios
  are DNS queries; classification and action are decided by Infoblox and your tenant policy.
* **No shipped threat domains.** `threat_defense.domains` is empty by default and every scenario
  that needs one refuses to run without it. Entries still containing `replace-me` are rejected.
* **TIDE feed is opt-in and reviewable.** `threat_defense.tide.enabled` defaults to false;
  `demo td fetch` writes a snapshot you can read and edit before any scenario uses it. Fetched names
  are validated (IP literals and malformed names are dropped) and only ever queried via DNS.
* **Explicit approval.** A scenario runs only if listed in `threat_defense.enabled_scenarios`.
* **Target guard.** `safety.allowed_dns_servers` restricts destinations; public resolver addresses
  are refused unless `allow_public_dns_server: true`.
* **Rate/volume caps.** `max_total_qps` (default 200), `max_duration` (900 s), `max_assets_per_run`
  (500). Clamps are reported in the run notes.
* **EDNS attribution is opt-in and private-only.** `source_mode: edns` attaches asset IP/MAC metadata
  to queries; it refuses public resolvers unless `dns.edns.allow_public_target: true`.
* **No spoofing.** Source IPs are only ever the host's own (`direct`) or an address it owns (`bind`).
* **Secrets.** Tokens come from environment variables named in config; the config file never holds
  them. `config/config.yaml`, `state/`, and `reports/` are git-ignored.
* **DHCP.** Sequential and slow by default (`delay_between`). `dras` talks to real DHCP servers:
  point it only at the demo tenant's DHCP service, never a production range.

## Before a customer demo

1. Rehearse with `config/config.mock.yaml` (mock DNS/DHCP; assets from your mock Asset Insights API or `demo assets import`).
   Use a read-only API key scoped to Asset Insights; never commit it.
2. `demo infra check` and `demo run-demo --dry-run` against the real config.
3. Confirm your threat domains are approved for the demo tenant and tenant policy is as expected.
4. Keep `duration` and `rate_per_asset` modest; raise only when the audience needs to see volume.
