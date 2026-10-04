#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/output/z12"
mkdir -p "$OUT"
run() {
  local name="$1"; shift
  echo "Running $name: $*"
  if "$@" >"$OUT/$name.txt" 2>&1; then
    cat "$OUT/$name.txt"
  else
    code=$?
    echo "Benchmark failed ($code), see $OUT/$name.txt"
    cat "$OUT/$name.txt"
    exit "$code"
  fi
}
run zkp-benchmarks env GOMAXPROCS=16 GOCACHE=/tmp/z12-hardened-cache GOTOOLCHAIN=auto go -C "$ROOT/zkp/healthclaimhardened" test -count=10 -run '^$' -bench 'BenchmarkProof(Generation|Verification)$' -benchtime=10x -benchmem
run gateway-benchmarks env GOMAXPROCS=16 GOCACHE=/tmp/z12-gateway-cache GOTOOLCHAIN=auto go -C "$ROOT/gateway" test -count=10 -run '^$' -bench '^BenchmarkGatewayLocalZKPProcessing$' -benchtime=10x -benchmem
{
  echo "Z12 local cryptographic/Gateway benchmark summary; 10 independent runs, 10 operations per run; $(date -Is)"
  python3 "$ROOT/scripts/z12/summarize-bench.py" "$OUT/zkp-benchmarks.txt" "$OUT/gateway-benchmarks.txt"
  echo "P95 is nearest-rank and equals the maximum for N=10. P99 is not reported because N<100."
  echo "No Fabric values are derived by subtraction here; no live Fabric sample was available."
} > "$OUT/performance-results.txt"
cat "$OUT/performance-results.txt"
