#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$ROOT/experiment-results"

mkdir -p "$RESULTS_DIR"

log() {
    echo
    echo "============================================================"
    echo "$1"
    echo "============================================================"
    echo
}

run_and_save() {
    local name="$1"
    shift
    echo "Running: $*"
    "$@" 2>&1 | tee "$RESULTS_DIR/${name}.log"
}

cd "$ROOT"

echo "ZeroTrustBlock — Full Experimental Evaluation"
echo "Root: $ROOT"
echo "Results: $RESULTS_DIR"
echo

log "Checking prerequisites"
command -v go >/dev/null || { echo "ERROR: Go is not installed."; exit 1; }
command -v npm >/dev/null || { echo "ERROR: npm is not installed."; exit 1; }
command -v docker >/dev/null || { echo "ERROR: Docker is not installed."; exit 1; }

echo "Go:     $(go version)"
echo "Node:   $(node --version)"
echo "npm:    $(npm --version)"
echo "Docker: $(docker --version)"

docker ps >/dev/null 2>&1 || { echo "ERROR: Docker is not accessible."; exit 1; }

log "Checking Fabric network"
if ! docker ps --format '{{.Names}}' | grep -q '^orderer1\.zerotrust\.com$'; then
    echo "ERROR: orderer1.zerotrust.com is not running. Start/deploy the Fabric network first."
    exit 1
fi
if ! docker ps --format '{{.Names}}' | grep -q '^peer0\.hospital\.zerotrust\.com$'; then
    echo "ERROR: peer0.hospital.zerotrust.com is not running."
    exit 1
fi
echo "Fabric network appears to be running."

log "Experiment A — Groth16 Cryptographic Cost"
cd "$ROOT/benchmark"
run_and_save "A-zkp" go run ./cmd/zkp 100
if [[ -f "$ROOT/benchmark/zkp-results.json" ]]; then
    cp "$ROOT/benchmark/zkp-results.json" "$RESULTS_DIR/zkp-results.json"
fi

log "Experiment B — Fabric Baseline"
cd "$ROOT/caliper"
if [[ ! -d node_modules ]]; then
    echo "Installing Caliper dependencies..."
    npm install
fi
run_and_save "B-fabric-baseline" npm run baseline

log "Experiment C — Privacy-Enabled End-to-End Performance"
cd "$ROOT/benchmark"
run_and_save "C-real-zkp" go run ./cmd/real

log "Experiment D — Fabric Scalability"
cd "$ROOT/caliper"
run_and_save "D-scalability" npm run benchmark

log "Experiment E — Zero-Trust Security Matrix"
cd "$ROOT/gateway"

echo "Creating security test record..."
CREATE_OUTPUT="$(go run ./cmd/security create 2>&1 | tee "$RESULTS_DIR/E-create.log")"
RECORD_ID="$(printf '%s\n' "$CREATE_OUTPUT" | awk -F= '/^RECORD_ID=/{print $2}' | tail -n 1)"

if [[ -z "$RECORD_ID" ]]; then
    echo "ERROR: Could not extract RECORD_ID from Experiment E."
    exit 1
fi

echo
echo "Security test record: $RECORD_ID"
echo

run_and_save "E-doctor" env ZT_IDENTITY=doctor go run ./cmd/security read "$RECORD_ID"
run_and_save "E-appAdmin" env ZT_IDENTITY=appAdmin go run ./cmd/security read "$RECORD_ID"
run_and_save "E-insurer" env ZT_IDENTITY=insurer go run ./cmd/security read "$RECORD_ID"

log "Validating Experiment E"
doctor_log="$RESULTS_DIR/E-doctor.log"
admin_log="$RESULTS_DIR/E-appAdmin.log"
insurer_log="$RESULTS_DIR/E-insurer.log"

if ! grep -q 'RESULT=ALLOW' "$doctor_log"; then
    echo "ERROR: doctor did not return RESULT=ALLOW."
    exit 1
fi
if ! grep -q 'RESULT=DENY' "$admin_log"; then
    echo "ERROR: appAdmin did not return RESULT=DENY."
    exit 1
fi
if ! grep -q 'RESULT=DENY' "$insurer_log"; then
    echo "ERROR: insurer did not return RESULT=DENY."
    exit 1
fi

echo "Experiment E validation: PASS"
echo "doctor   -> ALLOW"
echo "appAdmin -> DENY"
echo "insurer  -> DENY"

log "All Experiments Completed"
echo "Results saved under:"
echo "$RESULTS_DIR"
echo
echo "A = Groth16 cryptographic overhead"
echo "B = Fabric baseline"
echo "C = Real ZKP + Gateway + Fabric"
echo "D = Fabric load/scalability"
echo "E = Zero-Trust authorization"
echo
echo "Generated files:"
find "$RESULTS_DIR" -maxdepth 1 -type f -printf '  %f\n' | sort
