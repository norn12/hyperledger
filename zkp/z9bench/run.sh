#!/usr/bin/env bash
set -euo pipefail
export GOMAXPROCS="${GOMAXPROCS:-16}"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
OUT=${1:-"$SCRIPT_DIR/results/z9-benchmark-output.txt"}
mkdir -p "$(dirname -- "$OUT")"

exec > >(tee "$OUT") 2>&1
  echo "Z9 reproducible benchmark run"
  date -u '+UTC %Y-%m-%dT%H:%M:%SZ'
  go version
  go env GOTOOLCHAIN
  uname -a
  lscpu | grep -E 'Model name|Socket\(s\)|Core\(s\) per socket|Thread\(s\) per core|CPU\(s\):' || true
  free -h
  echo "GOMAXPROCS=${GOMAXPROCS:-default}"
  echo "Git commit: $(git -C "$REPO_ROOT" rev-parse HEAD)"
  echo "Working tree state at run start:"
  git -C "$REPO_ROOT" status --short
  echo "Core go.mod:"; sed -n '1,12p' "$REPO_ROOT/zkp/healthclaimcore/go.mod"
  echo "Hardened go.mod:"; sed -n '1,12p' "$REPO_ROOT/zkp/healthclaimhardened/go.mod"
  echo "Benchmark policy: Core/Hardened/legacy count=10, benchtime=10x; parameterized components count=5, benchtime=5x."
  echo

  echo '=== E1 Legacy AgeRange ==='
  (cd "$REPO_ROOT/zkp" && go version && GOCACHE=/tmp/healthclaim-z9-legacy-cache go test -count=10 -run '^$' -bench '^BenchmarkLegacy(AgeRange|Diagnosis)(Generation|Verification)$' -benchtime=10x -benchmem)
  echo
  echo '=== E2 Core ==='
  (cd "$SCRIPT_DIR" && GOCACHE=/tmp/healthclaim-z9-metadata-cache go test -run '^Test(Core|Hardened)BenchmarkMetadata$' -v)
  (cd "$REPO_ROOT/zkp/healthclaimcore" && go version && GOCACHE=/tmp/healthclaim-z9-core-cache go test -count=10 -run '^$' -bench 'BenchmarkProof(Generation|Verification)$' -benchtime=10x -benchmem)
  echo
  echo '=== E3 Hardened ==='
  (cd "$REPO_ROOT/zkp/healthclaimhardened" && go version && GOCACHE=/tmp/healthclaim-z9-hardened-cache go test -count=10 -run '^$' -bench 'BenchmarkProof(Generation|Verification)$' -benchtime=10x -benchmem)
  echo
  echo '=== Separate compile and Groth16 setup costs ==='
  (cd "$SCRIPT_DIR" && GOCACHE=/tmp/healthclaim-z9-setup-cache go test -count=3 -run '^$' -bench 'Benchmark(CircuitCompile|Groth16Setup)$' -benchtime=1x -benchmem)
  echo
  echo '=== E4/E5 Component scaling; isolated Poseidon2 Merkle and policy predicates, not full Z7 ==='
  (cd "$SCRIPT_DIR" && go version && GOCACHE=/tmp/healthclaim-z9-scaling-cache go test -count=5 -run '^$' -bench 'Benchmark(MerkleDepth|PolicySize|MerkleVerification|PolicyVerification)$' -benchtime=5x -benchmem)
  echo
  echo '=== E9 Local witness construction microbenchmark ==='
  (cd "$SCRIPT_DIR" && go version && GOCACHE=/tmp/healthclaim-z9-pipeline-cache go test -count=10 -run '^$' -bench '^BenchmarkWitnessConstruction$' -benchtime=10x -benchmem)
  echo
  echo '=== E9 Full local witness -> Groth16 prove -> Groth16 verify pipeline ==='
  (cd "$SCRIPT_DIR" && GOCACHE=/tmp/healthclaim-z9-pipeline-cache go test -count=10 -run '^$' -bench '^BenchmarkFullPipeline$' -benchtime=10x -benchmem)
