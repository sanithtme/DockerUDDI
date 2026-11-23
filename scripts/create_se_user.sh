#!/usr/bin/env bash
set -euo pipefail
if [ "${EUID}" -ne 0 ]; then echo "Run as root/sudo" >&2; exit 2; fi
u="${1:-}"
if ! [[ "$u" =~ ^[a-z_][a-z0-9_-]*$ ]]; then echo "usage: sudo $0 <linux-user>" >&2; exit 2; fi
id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
install -d -m 0700 -o "$u" -g "$u" "/home/$u/.infoblox-demo"
echo "Prepared isolated SE account: $u"
echo "Configure AWS SSM Run As / Identity Center mapping separately; this script does not alter IAM/SSO."
