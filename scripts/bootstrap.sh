#!/usr/bin/env bash
# One-shot setup on a Linux cloud VM (Ubuntu/Debian/RHEL/Amazon Linux).
#   git clone <your repo> && cd <repo> && ./scripts/bootstrap.sh
# Creates .venv, installs the tool, and creates config/config.yaml from the example if missing.
# It never asks for, stores or prints your API key.
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "python3 not found. Install it first (e.g. sudo apt-get install -y python3 python3-venv)." >&2
  exit 1
fi
if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
  echo "Python >= 3.10 required (found: $("$PY" --version))." >&2
  exit 1
fi

"$PY" -m venv .venv || { echo "venv failed. On Debian/Ubuntu: sudo apt-get install -y python3-venv" >&2; exit 1; }
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -e .

mkdir -p state reports
if [ ! -f config/config.yaml ]; then
  cp config/config.example.yaml config/config.yaml
  echo "Created config/config.yaml from the example. Edit it before running."
fi

echo
echo "Installed: $(demo --help >/dev/null 2>&1 && echo 'demo CLI OK' || echo 'demo CLI NOT FOUND')"
command -v dras >/dev/null 2>&1 && echo "dras: found (DHCP simulation available)" \
  || echo "dras: not found (DNS and Threat Defense work; DHCP needs dras installed)"
cat <<'NEXT'

Next steps:
  source .venv/bin/activate
  nano config/config.yaml                 # tenant URL, DNS/DHCP servers, safety.allowed_dns_servers
  read -rs -p "Infoblox API key: " INFOBLOX_API_KEY; export INFOBLOX_API_KEY; echo
  demo discover --probe                   # validates URL, key and response shape
  demo discover
  demo infra check
  demo run-demo --dry-run
NEXT
