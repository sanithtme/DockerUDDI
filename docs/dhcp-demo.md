# DHCP demo: lease activity for the discovered devices

Goal: each discovered device (MAC + hostname from Asset Insights) goes through DISCOVER, REQUEST,
RENEW and RELEASE against your NIOS-X DHCP service, and you can show the leases from the terminal.

Legend: **[doc]** found in Infoblox docs/KBs/Jira; **[check]** not confirmed, verify first.

## What has to exist before a lease can be granted

1. A DHCP service running on the NIOS-X host (enabled in the portal) [doc].
2. An **IP space, subnet and range**, with the host assigned to serve the subnet [doc].
3. A **relay address (giaddr)** inside that subnet. `dras -c <ip>` sets it; the server picks the
   subnet from it and sends the OFFER back to it, so the VM must own it and the server must be able
   to reach it [doc]. In your VPC the VM's own address works.
4. **A DHCP client that can send relayed requests.** Either `dras` (Infoblox internal tool, in the NIOS
   Team support tools share) or the **built-in native client** (no extra install). With
   `dhcp.provider: auto` the tool uses `dras` if it is on PATH and the native client otherwise.

Step 2 is what `demo ipam` automates.

## The two DHCP clients

| | `dras` | native (built in) |
|---|---|---|
| Install | internal binary | nothing |
| Packets | relayed DISCOVER/REQUEST, `-c` sets giaddr | the same: `giaddr` = `dhcp.dra.relay_agent_ip`, unicast to the server |
| Needs root | yes (`sudo -n dras`) | yes, to bind UDP 67: run `sudo $(which demo) -c "$DEMO_CONFIG" dhcp ...` |
| Release | request then release | a real DHCPRELEASE for the known lease |
| Select with | `dhcp.provider: dra` | `dhcp.provider: native` (or `auto` when `dras` is absent) |

Both use the relay settings under `dhcp.dra` (`relay_agent_ip`, `relay_map`, `send_hostname`,
`lease_dir`). Native-only settings are under `dhcp.native` (`listen_port` 67, `timeout`, `retries`).

**Why root and port 67:** the server sends its reply to `giaddr` on UDP 67, so the client must listen
there. The relay address must be an address this host owns (your VM's own VPC address works), and
nothing else may be using UDP 67 (`sudo ss -ulpn | grep ':67 '`). In AWS the security group must allow
UDP 67 from the DHCP server to the VM and from the VM to the server.

```bash
sudo $(which demo) -c "$DEMO_CONFIG" dhcp request --asset <id>      # root is needed only for this command
sudo chown -R $USER state                            # root created files under state/dhcp
# NOTE: pass the config with -c. On Ubuntu, `sudo -E` is refused ("preserving the entire environment is
# not supported"), so root does NOT see DEMO_CONFIG and would silently fall back to config/config.yaml
# (the example copy that bootstrap.sh creates). Delete that file so a missing config is an error:
rm -f config/config.yaml
demo ipam leases --mac <asset-mac>
sudo tcpdump -n -i any 'udp port 67 or udp port 68' -vv   # if there is no reply: do packets leave/arrive?
```

The native client was tested against a stand-in DHCP server, not against NIOS-X; the first run on your
server is the real test.

## Automating the network (step 2)

```bash
demo ipam hosts                 # copy the DHCP host id (dhcp/host/<id>) into ipam.dhcp_host
demo ipam apply --dry-run       # plan: IP space, subnet, range, assignment
demo ipam apply                 # create them (idempotent), tagged ManagedBy=asset-insights-ddi-demo
demo ipam status                # exists? ours? which host serves it? ranges?
```

Config (`config/config.example.yaml`, section 6): `ipam.dhcp_host`, `ipam.ip_space`,
`ipam.create_ip_space`, and the `subnets` list. The DHCP config takes about a minute to reach the host
(`ipam.wait_seconds`), so wait before requesting leases. `run-demo` does it for you when
`ipam.enabled: true`.

### Rules the tool enforces (from the docs)

* **One IP space per DHCP host** [doc]. The first subnet you assign fixes the space; later ones must
  use the same. If your host already serves a space, set `ipam.ip_space` to its name and
  `create_ip_space: false`, or the API will reject the assignment (its message is shown verbatim).
* **NIOS-federated IP spaces ignore `dhcp_host`** [doc, UDDIST-3407]. The tool refuses them up front,
  and if the API accepts a subnet without recording the host it removes the subnet and says why.
* **The range inherits the serving host from its subnet**, so only the subnet carries `dhcp_host`.
* **Private subnets only**, no larger than /16, ranges inside the subnet and at most 4096 addresses.
* **Only tagged objects are touched.** An existing subnet/range without the tag is never modified;
  `destroy` refuses a subnet that contains ranges it did not create.

## Generating the leases

```bash
demo dhcp request --asset <id> --dry-run         # prints the exact dras command
sudo dras -i <dhcp-server> -a <asset-mac> -c <relay-ip> -v    # once by hand to see DORA
demo dhcp request --asset <id>
demo dhcp renew   --asset <id>
demo dhcp release --asset <id>
demo dhcp request --all --limit 5
```

Config: `dhcp.server`, `dhcp.dra.relay_agent_ip`, `dhcp.dra.use_sudo`. The tool sends the asset's MAC
and its hostname as option 12; leases come from the range, so the address is **not** the asset's own IP
unless you also create a fixed address for that MAC (see "Next").

## Proving it without the GUI

| Proof | Command | Look for |
|---|---|---|
| Protocol | `sudo dras -i <srv> -a <mac> -c <relay> -v` | OFFER with `yiaddr`, then ACK, and the server id |
| API | `demo ipam leases --mac <mac>` | the lease record for that device (field names are not verified, `--json` shows everything) |
| Server log | on the NIOS-X host: `sudo journalctl -u kea-dhcp4.service --no-pager \| grep -i <mac>` | the create/delete events [check the exact wording] |

`demo ipam leases` reads `GET /api/ddi/v1/dhcp/lease` [doc]. `--mac` is a case-insensitive substring
match over the record, because the lease field names are not documented in what I could find.

## Known issues to check against your release

* **Relayed leases not visible in the portal** (Jira DDIDHCP-3582, P1, NIOS-X as a Service, Sydney
  realm): a completed DORA through a relay produced no lease in the portal or `dhcp/lease`. Marked Done
  for 27.1; a related test ticket is still open. If `ipam leases` comes back empty after a successful
  `dras` run, this is the first thing to suspect.
* **Relay-hex fixed addresses stall the host's DHCP config push** (UDDIST-3508, open): do not create
  fixed addresses with `match_type: relay_hex` on the demo host.

## Next (not built)

* **Reservations per asset**: a fixed address matched by the asset's MAC, so the lease equals the
  asset's IP. The documented example only covers `match_type: relay_hex`; the MAC variant's field
  values need to be confirmed before it can be automated.
* **DHCP to DNS**: `dras -F <domain>:S1:O1:E1:N1` sends option 81 asking the server to update DNS.
  Needs DDNS configured on the space and zone; not verified here.

## Cleaning up

```bash
demo ipam destroy --yes      # ranges, subnets, and the IP space if this tool created it and it is empty
```
