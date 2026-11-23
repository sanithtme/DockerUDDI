# Prompt: merge the Infoblox traffic/telemetry module into an existing auto-deployment project

Use the attached `infoblox-traffic-telemetry-module` project as the traffic-generation and verification layer of my existing Infoblox DNS/DHCP/Threat Defense auto-deployment project.

## Goal
After the parent project deploys/configures DNS, DHCP and Threat Defense, automatically hand the deployed environment details to this module, then use it to create realistic demo telemetry and verify the deployment in the Infoblox portal.

## Preserve these behaviors
1. `demo prepare` authenticates with the Infoblox tenant using the API key from `INFOBLOX_API_KEY`, retrieves Asset Insights inventory, stores it locally, retrieves active TIDE domains, and stores the normalized domain snapshot. Do not require a customer-maintained domains JSON file.
2. Asset Insights devices are used only for DNS attribution tests. DNS `source_mode: spoof` places each discovered asset IPv4 directly in the IPv4 source header; it does not use EDNS/ECS.
3. External/security DNS traffic consumes the automatically generated TIDE domain snapshot.
4. Internal DNS zones/records are provisioned through the Infoblox API. Resolve `dns.server` automatically to the matching `dns/host/<id>`; do not require the user to copy an internal host ID. Fail safely on zero or multiple matches.
5. Internal-zone test queries use discovered Asset Insights IPs as spoofed DNS sources.
6. DHCP clients are NOT Asset Insights devices. `demo dhcp synthetic` generates independent deterministic hostnames/MACs such as `demo-dhcp-0001` / `02:dd:10:00:00:01`.
7. Synthetic DHCP uses the built-in native relay-style DHCP provider, not DRAS. It performs DISCOVER/OFFER/REQUEST/ACK using the configured DHCP server and local relay/giaddr.
8. Resolve `dhcp.server` automatically to the matching `dhcp/host/<id>` for IPAM/range assignment. Keep explicit host-ID overrides only as an advanced escape hatch.
9. Keep dry-run and safety controls. Never silently disable the DNS allowlist, rate caps, duration caps, managed-object tags, or destructive-operation protections.
10. Keep generated runtime data (`state/`, reports, leases, real config, credentials) out of Git.

## Integration contract
The parent deployment project should produce or update one runtime YAML file after deployment. At minimum it must supply:
- Infoblox tenant/base URL.
- Environment variable name containing the API key (`INFOBLOX_API_KEY` by default); never write the secret into Git.
- DNS server IPv4 and port.
- DHCP server IPv4 and port.
- Traffic-generator/relay host local IPv4 used as DHCP `giaddr`.
- DHCP IP space/subnet/range desired for the demo, if the parent project owns their creation.
- Internal demo zone/records, or accept the module defaults.
- `safety.allowed_dns_servers` containing the deployed DNS server.

Prefer consuming deployment outputs directly rather than asking the user to re-enter values. If the parent project already knows the DNS/DHCP server IPs, subnet, range and tenant URL, render them into the module config automatically.

## Platform behavior
Keep API/DDI operations cross-platform where practical. Treat low-level packet generation separately:
- Linux is the recommended execution platform.
- Linux DNS spoofing needs raw-packet capability; native DHCP relay needs permission to bind UDP/67. Bootstrap may grant only the minimum required capabilities to the venv Python on a dedicated lab host.
- macOS/Windows must not be claimed fully supported for low-level spoof/relay traffic unless validated. API provisioning can remain portable.
Add a platform/doctor check if the parent project already has a diagnostics framework.

## Desired orchestration
Integrate a post-deployment workflow equivalent to:
1. Validate configuration/credentials.
2. `demo prepare`.
3. Optional external/TIDE DNS dry-run, then live DNS test.
4. `demo zones apply --dry-run`, then apply/verify when approved by the parent workflow.
5. Internal DNS spoof test.
6. `demo ipam apply --dry-run`, then apply/status when approved.
7. `demo dhcp synthetic --count <N>`.
8. `demo ipam leases` and verification/report output.

Do not duplicate the module's Asset Insights, TIDE normalization, host-IP-to-host-ID resolution, DNS spoofing, zone management, IPAM, or native DHCP implementation inside the parent project. Import/call/reuse these components and make the parent deployment outputs feed the module configuration.

## Deliverables
- Merged code with a clear module boundary.
- One generated runtime config derived from deployment outputs.
- Updated bootstrap/setup for required Python dependencies and Linux capabilities.
- A `doctor` or equivalent preflight check if practical.
- Dry-run support for all provisioning/traffic stages where currently available.
- README section showing end-to-end deployment -> telemetry -> verification workflow.
- Tests proving Asset Insights DNS identities and synthetic DHCP identities remain separate.
