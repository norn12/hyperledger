#!/usr/bin/env bash
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/output/z12/e2e-results.txt"
mkdir -p "$ROOT/output/z12"
if ! "$ROOT/scripts/z12/network-preflight.sh"; then
  {
    echo "Not measured - live Fabric network unavailable in the evaluation environment."
    cat "$ROOT/output/z12/network-preflight.txt"
    echo "No start, reset, deploy, or sequence-1 lifecycle operation was attempted."
  } > "$OUT"
  cat "$OUT"
  exit 2
fi
cd "$ROOT/gateway"
ZT_Z12_LIVE=1 GOMAXPROCS=16 GOCACHE=/tmp/z12-gateway-cache GOTOOLCHAIN=auto go test -tags=z12integration -count=1 -v -run '^TestZ12LiveValidClaimAndReplay$' ./... > "$OUT" 2>&1
cat "$OUT"
