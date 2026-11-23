#!/usr/bin/env bash
# Narrated customer demo. Press Enter to advance through each act.
#
#   ./scripts/showcase.sh check      # pre-flight: is everything ready? (run this before the customer joins)
#   ./scripts/showcase.sh            # run the demo (acts 1-4)
#   ACTS="1 2 3 4 5" ./scripts/showcase.sh   # include the optional DHCP act
#   ./scripts/showcase.sh cleanup    # remove what the demo created
#
# Prerequisites: venv active, INFOBLOX_API_KEY and DEMO_CONFIG set (source ~/.demo_env), run from the repo root.
# Optional: DEMO_ASSET=<asset id> to choose the device used in acts 2-3 (default: the first usable one),
#           NO_PAUSE=1 to run without waiting for Enter.
# Full storyline and talk track: docs/customer-demo.md
set -uo pipefail

ACTS="${ACTS:-1 2 3 4}"
NO_PAUSE="${NO_PAUSE:-0}"
SYNTH="${SYNTH_ASSET:-demo-dhcp-001}"

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
dim()  { printf '\033[2m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m[ok]\033[0m   %s\n' "$*"; }
warn() { printf '  \033[33m[warn]\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m[FAIL]\033[0m %s\n' "$*"; FAILED=1; }
pause() { [ "$NO_PAUSE" = 1 ] || read -rp "   -- press Enter to continue -- " _; }
run()  { printf '\n\033[36m$ %s\033[0m\n' "$*"; "$@"; local rc=$?; [ $rc -ne 0 ] && warn "command exited $rc"; return 0; }
say()  { printf '   \033[3m%s\033[0m\n' "$*"; }
portal() { printf '\n   \033[35mIn the portal:\033[0m %s\n' "$*"; }

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing command: $1" >&2; exit 2; }; }
need demo; need python3

dns_server() { demo --json infra show 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['dns']['host'])" 2>/dev/null; }
first_asset() { demo --json assets list --eligible 2>/dev/null | python3 -c "import sys,json; r=json.load(sys.stdin); print(r[0]['asset_id'] if r else '')" 2>/dev/null; }
asset_field() { demo --json assets show "$1" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('$2') or '')" 2>/dev/null; }

check() {
  FAILED=0
  bold "Pre-flight"
  [ -n "${DEMO_CONFIG:-}" ] && [ -f "$DEMO_CONFIG" ] && ok "config: $DEMO_CONFIG" || bad "DEMO_CONFIG is not set or the file is missing (source ~/.demo_env)"
  [ -n "${INFOBLOX_API_KEY:-}" ] && ok "API key is set (${#INFOBLOX_API_KEY} chars)" || bad "INFOBLOX_API_KEY is not set"
  local n; n=$(demo --json assets summary 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['assets'])" 2>/dev/null || echo 0)
  [ "${n:-0}" -gt 0 ] 2>/dev/null && ok "$n assets stored" || bad "no assets stored: run  demo discover"
  local a="${DEMO_ASSET:-$(first_asset)}"
  [ -n "$a" ] && ok "demo device: $a ($(asset_field "$a" hostname), $(asset_field "$a" ip))" || bad "no usable device (needs an IP)"
  demo infra check >/dev/null 2>&1 && ok "DNS server $(dns_server) answers" || bad "DNS server check failed: demo infra check"
  [ -f state/tide_domains.json ] && ok "Threat Defense domain snapshot exists" || warn "no state/tide_domains.json: run  demo td fetch  (act 3 needs domains)"
  demo zones status >/dev/null 2>&1; case $? in 0|3) ok "zones configured (dns_host set)";; *) bad "zones not usable: check zones.dns_host in the config";; esac
  command -v dig >/dev/null 2>&1 && ok "dig installed" || warn "dig not installed (act 4 contrast will be skipped): sudo apt-get install -y dnsutils"
  if echo "$ACTS" | grep -qw 5; then
    sudo -n true 2>/dev/null && ok "passwordless sudo (act 5)" || bad "act 5 needs passwordless sudo"
    demo ipam status >/dev/null 2>&1; case $? in 0|3) ok "ipam configured (dhcp_host set)";; *) bad "ipam not usable: check ipam.dhcp_host";; esac
  fi
  echo
  [ "$FAILED" = 0 ] && echo "Ready." || { echo "Fix the FAIL lines above before presenting."; return 1; }
}

act1() {
  bold "ACT 1 - What is actually on your network?"
  say "Asset Insights builds one authoritative inventory from DNS/DHCP plus your cloud and security tools."
  run demo assets summary
  portal "Assets (left menu): the same inventory, with owner, OS and where each asset was seen."
  pause
}

act2() {
  bold "ACT 2 - Every device touches DNS, so we know exactly who it is"
  say "Normal DNS logs only show an IP. Watch what Infoblox shows for this one lookup."
  run demo dns query --asset "$ASSET" --name www.google.com --type A
  portal "Monitor > Reports > DNS Activity: the query, with the device name, IP, MAC and operating system."
  say "No agent on the device, no scan. The identity comes from the inventory."
  pause
}

act3() {
  bold "ACT 3 - Threats are stopped at DNS, with the device attached"
  say "The same device now looks up domains from Infoblox's threat intelligence feed."
  run demo td run --scenario blocked-domain --asset "$ASSET" --duration 5 --rate 1
  portal "Security Activity (Threat Defense): the events, each tied to the device, user and OS."
  say "The SOC sees which device it is on the first alert, without a hunt through logs."
  pause
}

act4() {
  bold "ACT 4 - Your internal DNS, managed as code"
  local S; S=$(dns_server)
  say "One command creates an internal zone and its records through the API. It is repeatable and tagged, so it can be removed cleanly."
  run demo zones apply
  run demo zones verify
  if command -v dig >/dev/null 2>&1 && [ -n "$S" ]; then
    say "Proof the server answers for it as the authority (flag 'aa'), and that a normal lookup is different:"
    printf '\n\033[36m$ dig @%s host1.demo.internal A  (internal)\033[0m\n' "$S"
    dig @"$S" host1.demo.internal A +noall +comments +answer +time=3 +tries=1 | grep -E "flags|IN"
    printf '\n\033[36m$ dig @%s www.google.com A  (external, for contrast)\033[0m\n' "$S"
    dig @"$S" www.google.com A +noall +comments +time=3 +tries=1 | grep -E "flags"
  fi
  say "Now the discovered devices look up the internal names:"
  run demo zones test --limit 3
  say "Change a record in the config, run  demo zones apply  again, and the new answer is live in seconds."
  pause
}

act5() {
  bold "ACT 5 (optional) - A new device joins the network and gets an address"
  say "A made-up client asks the DHCP server for a lease, relayed the way a real branch router would."
  local mac; demo assets synth --count 1 >/dev/null 2>&1
  mac=$(asset_field "$SYNTH" mac)
  run demo ipam apply
  say "(The DHCP configuration takes about a minute to reach the server.)"
  sleep 60
  run sudo "$(command -v demo)" -c "$DEMO_CONFIG" dhcp request --asset "$SYNTH"
  sudo chown -R "$USER" state 2>/dev/null || true
  run demo ipam leases --mac "$mac"
  portal "DHCP / IPAM: the lease in the new subnet. If passive discovery is on, the device also appears as a new asset."
  pause
}

cleanup() {
  bold "Cleaning up what the demo created"
  sudo -n true 2>/dev/null && run sudo "$(command -v demo)" -c "$DEMO_CONFIG" dhcp release --asset "$SYNTH"
  sudo chown -R "$USER" state 2>/dev/null || true
  run demo zones destroy --yes
  run demo ipam destroy --yes
  echo; echo "Done. (Threat Defense and DNS queries leave no objects behind.)"
}

case "${1:-run}" in
  check) check; exit $? ;;
  cleanup) cleanup; exit 0 ;;
  run) ;;
  *) echo "usage: $0 [check|run|cleanup]"; exit 2 ;;
esac

ASSET="${DEMO_ASSET:-$(first_asset)}"
[ -n "$ASSET" ] || { echo "no usable device found: run  demo discover  first"; exit 1; }
bold "Demo device: $ASSET  ($(asset_field "$ASSET" hostname), $(asset_field "$ASSET" ip))"
dim "Tip: run  $0 check  before the customer joins. Press Enter to move between acts."
pause
for a in $ACTS; do "act$a"; done
bold "Wrap-up"
say "Discovery, identity on every DNS query, threats tied to devices, and DDI managed as code, all from the DNS/DHCP layer every device already uses."
