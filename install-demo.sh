#!/usr/bin/env bash
set -euo pipefail
IMAGE="infoblox-nios-xaas-demo-backend-mvp:1.0.0"
BASE="${INFOBLOX_DEMO_RUNTIME_ROOT:-/var/lib/infoblox-nios-xaas-demo-mvp}"
if ! command -v docker >/dev/null 2>&1; then echo "ERROR: Docker is required on the controller." >&2; exit 2; fi
if ! docker info >/dev/null 2>&1; then echo "ERROR: Docker daemon is unavailable to this account. Ask the controller admin to configure Docker access." >&2; exit 2; fi
read -r -p "SE name: " SE
read -r -p "Customer/demo name: " CUSTOMER
SAFE_SE=$(printf '%s' "$SE" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_.-]/-/g; s/^-*//; s/-*$//' | cut -c1-32)
[ -n "$SAFE_SE" ] || { echo "ERROR: invalid SE name" >&2; exit 2; }
STAMP=$(date -u +%Y%m%d-%H%M%S)
RUNTIME="${SAFE_SE}-${STAMP}"
CONTAINER="infoblox-demo-${RUNTIME}"
WORKSPACE="${BASE}/users/${RUNTIME}"
mkdir -p "$WORKSPACE"
chmod 700 "$WORKSPACE"
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "Building backend MVP image $IMAGE ..."
  docker build -t "$IMAGE" .
fi
echo "Starting isolated runtime $RUNTIME ..."
docker run -d --name "$CONTAINER" --restart unless-stopped --network host \
  --cap-drop ALL --cap-add NET_RAW \
  -e PYTHONUNBUFFERED=1 -e INFOBLOX_DEMO_OWNER="$SAFE_SE" -e INFOBLOX_DEMO_CUSTOMER="$CUSTOMER" \
  -e INFOBLOX_DEMO_RUNTIME_ID="$RUNTIME" -e INFOBLOX_DEMO_WORKSPACE=/workspace \
  -v "$WORKSPACE:/workspace" "$IMAGE" >/dev/null
docker exec "$CONTAINER" demo setup >/dev/null
if ! docker exec "$CONTAINER" demo --help >/dev/null; then
  echo "ERROR: backend CLI failed its container smoke test." >&2; docker logs --tail 50 "$CONTAINER" >&2 || true; exit 2
fi
cat <<OUT

Infoblox NIOS-XaaS Demo Backend MVP
-----------------------------------
Runtime ID : $RUNTIME
SE          : $SAFE_SE
Customer    : $CUSTOMER
Container   : $CONTAINER
Workspace   : $WORKSPACE

Enter this isolated backend:
  docker exec -it $CONTAINER bash

Then provide the Infoblox API key only inside that container/session:
  export INFOBLOX_API_KEY='<key>'

Backend workflow:
  demo readiness
  demo deploy --dry-run --new
  demo deploy --new
  demo status
  demo traffic
  demo cleanup

Resume an interrupted deployment with: demo deploy
Do NOT use --new to resume.
OUT
