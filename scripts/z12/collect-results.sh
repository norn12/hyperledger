#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/output/z12"
mkdir -p "$OUT"
if [ ! -s "$OUT/chaincode-tests.txt" ]; then echo "Missing local chaincode test results; run scripts/z12/run-local-validation.sh" >&2; exit 1; fi
if ! grep -q 'proof_bytes=' "$OUT/chaincode-tests.txt"; then echo "Storage serialization measurements absent from chaincode test log" >&2; exit 1; fi
{
  echo "Storage/privacy measurements collected from TestZ12StorageSerializationSizesAndPrivacy."
  echo "This is a deterministic local serializer fixture with a 164-byte placeholder proof; it is not a live ledger record."
  grep -E 'proof_bytes=|TestZ12StorageSerializationSizesAndPrivacy' "$OUT/chaincode-tests.txt"
  echo "Stored state excludes diagnosis, labValue, patientSecret, coverageCeiling, merkleSiblings, merkleDirections, policyID."
  echo "Proof bytes and all 13 public inputs are intended channel-visible data."
} > "$OUT/storage-results.txt"
{
  echo "Z12 result files and SHA-256:"
  find "$OUT" -maxdepth 1 -type f ! -name result-manifest.sha256 -print0 | sort -z | xargs -0 sha256sum
  REPORT="$ROOT/output/pdf/ZeroTrustBlock-Z12-end-to-end-evaluation-report.pdf"
  if [ -s "$REPORT" ]; then sha256sum "$REPORT"; fi
} > "$OUT/result-manifest.sha256"
cat "$OUT/storage-results.txt"
cat "$OUT/result-manifest.sha256"
