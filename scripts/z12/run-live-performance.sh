#!/usr/bin/env bash
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/output/z12/live-performance-results.txt"
mkdir -p "$ROOT/output/z12"
if ! "$ROOT/scripts/z12/network-preflight.sh"; then
  {
    echo "Not measured - live Fabric network unavailable in the evaluation environment."
    echo "The gated TestZ12LiveSequentialClaimsAndDuplicateNullifierRace test performs sequential unique claims and a two-submission duplicate-nullifier race when the configured updated Fabric network is reachable."
    cat "$ROOT/output/z12/network-preflight.txt"
  } > "$OUT"
  cat "$OUT"
  exit 2
fi
cd "$ROOT/gateway"
ZT_Z12_LIVE=1 GOMAXPROCS=16 GOCACHE=/tmp/z12-gateway-cache GOTOOLCHAIN=auto go test -tags=z12integration -count=1 -v -run '^TestZ12LiveSequentialClaimsAndDuplicateNullifierRace$' ./... > "$OUT" 2>&1
cat "$OUT"
