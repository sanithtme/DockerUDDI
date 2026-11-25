#!/usr/bin/env bash
set -euo pipefail
IMAGE="infoblox-nios-xaas-demo-backend-mvp:1.2.0"
BASE="${INFOBLOX_DEMO_RUNTIME_ROOT:-/var/lib/infoblox-nios-xaas-demo-mvp}"

fail(){ echo "ERROR: $*" >&2; exit 2; }
command -v docker >/dev/null 2>&1 || fail "Docker is required on the controller."

# One-time host bootstrap. Use sudo only for the protected /var/lib parent.
if [ ! -d "$BASE" ]; then
  echo "Preparing controller runtime directory $BASE ..."
  sudo mkdir -p "$BASE/users"
  sudo chown -R "$(id -u):$(id -g)" "$BASE"
  sudo chmod 700 "$BASE" "$BASE/users"
fi
[ -w "$BASE" ] || fail "$BASE is not writable by $(id -un). Ask the controller admin to chown it to the demo service account."
mkdir -p "$BASE/users"
chmod 700 "$BASE" "$BASE/users" 2>/dev/null || true

docker info >/dev/null 2>&1 || fail "Docker daemon is unavailable to this account. Reconnect after Docker group/service access is configured."

read -r -p "SE name: " SE
read -r -p "Customer/demo name: " CUSTOMER
SAFE_SE=$(printf '%s' "$SE" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_.-]/-/g; s/^-*//; s/-*$//' | cut -c1-32)
[ -n "$SAFE_SE" ] || fail "invalid SE name"
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
  --user "$(id -u):$(id -g)" -e HOME=/workspace \
  --cap-drop ALL --cap-add NET_RAW \
  -e PYTHONUNBUFFERED=1 -e INFOBLOX_DEMO_OWNER="$SAFE_SE" -e INFOBLOX_DEMO_CUSTOMER="$CUSTOMER" \
  -e INFOBLOX_DEMO_RUNTIME_ID="$RUNTIME" -e INFOBLOX_DEMO_WORKSPACE=/workspace \
  -v "$WORKSPACE:/workspace" "$IMAGE" >/dev/null

cleanup_failed(){ docker logs --tail 80 "$CONTAINER" >&2 2>/dev/null || true; docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }

# Verify the bind mount before declaring the runtime usable.
if ! docker exec "$CONTAINER" sh -lc 'test -w /workspace && touch /workspace/.preflight && rm -f /workspace/.preflight'; then
  echo "ERROR: container cannot write its /workspace bind mount." >&2; cleanup_failed; exit 2
fi
if ! docker exec "$CONTAINER" demo --help >/dev/null; then
  echo "ERROR: backend CLI failed its container import smoke test." >&2; cleanup_failed; exit 2
fi
if ! docker exec "$CONTAINER" demo setup >/dev/null; then
  echo "ERROR: demo setup failed inside the isolated runtime." >&2; cleanup_failed; exit 2
fi
if ! docker exec "$CONTAINER" demo status >/dev/null 2>&1; then
  echo "NOTE: no deployment exists yet; backend runtime itself is ready."
fi

cat <<OUT

Infoblox NIOS-XaaS Demo Backend MVP
-----------------------------------
✓ Docker daemon accessible
✓ Controller runtime directory ready
✓ Isolated workspace writable
✓ Backend CLI verified
✓ Demo workspace initialized

Runtime ID : $RUNTIME
SE         : $SAFE_SE
Customer   : $CUSTOMER
Container  : $CONTAINER
Workspace  : $WORKSPACE

Enter this isolated backend:
  docker exec -it $CONTAINER bash

Provide the Infoblox API key only inside that container/session:
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
