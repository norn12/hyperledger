#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/output/z12"
mkdir -p "$OUT"
run() {
  local name="$1"; shift
  local path="$OUT/${name}.txt"
  echo "Running $name: $*"
  if "$@" >"$path" 2>&1; then
    echo "PASS: $name"
  else
    code=$?
    echo "FAIL ($code): $name; output: $path"
    cat "$path"
    exit "$code"
  fi
}
run hardened-tests env GOMAXPROCS=16 GOCACHE=/tmp/z12-hardened-cache GOTOOLCHAIN=auto go -C "$ROOT/zkp/healthclaimhardened" test -count=1 -v ./...
run gateway-tests env GOMAXPROCS=16 GOCACHE=/tmp/z12-gateway-cache GOTOOLCHAIN=auto go -C "$ROOT/gateway" test -count=1 -v ./...
run chaincode-tests env GOMAXPROCS=16 GOCACHE=/tmp/z12-chaincode-cache GOTOOLCHAIN=auto go -C "$ROOT/chaincode" test -count=1 -v ./...
run live-test-compile env GOMAXPROCS=16 GOCACHE=/tmp/z12-gateway-cache GOTOOLCHAIN=auto go -C "$ROOT/gateway" test -tags=z12integration -run '^$' ./...
{
  echo "Z12 deterministic/local security validation: $(date -Is)"
  for name in hardened-tests gateway-tests chaincode-tests live-test-compile; do
    echo "===== $name ====="
    cat "$OUT/$name.txt"
  done
} > "$OUT/security-results.txt"
echo "Wrote local validation outputs to $OUT"
