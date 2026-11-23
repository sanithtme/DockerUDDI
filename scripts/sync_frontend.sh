#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$ROOT/backend/src/demo_web/static"
cp "$ROOT/frontend/static/"* "$ROOT/backend/src/demo_web/static/"
echo "Frontend synchronized into backend package assets."
