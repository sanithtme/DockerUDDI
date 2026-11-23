#!/usr/bin/env bash
# Plain dig from many source IPs (the host must own each IP; see docs/architecture.md).
#   ./scripts/dig-loop.sh <dns-server> <qname> [ips-file]   # default ips file: ips.txt
#   demo assets ips --export ips.txt                         # creates the file
set -uo pipefail
SERVER="${1:?usage: $0 <dns-server> <qname> [ips-file]}"
QNAME="${2:?usage: $0 <dns-server> <qname> [ips-file]}"
IPS_FILE="${3:-ips.txt}"
CLASS="${DIG_CLASS:-IN}"; TYPE="${DIG_TYPE:-A}"
[ -f "$IPS_FILE" ] || { echo "no such file: $IPS_FILE" >&2; exit 1; }
while read -r ip; do
  [ -z "$ip" ] && continue
  echo "== source $ip"
  dig -b "$ip" @"$SERVER" "$QNAME" -c "$CLASS" -t "$TYPE" +time=2 +tries=1 +short || echo "   failed (exit $?)"
  sleep 0.5
done < "$IPS_FILE"
