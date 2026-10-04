#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
go version
go mod download
go mod verify
go test -count=1 -run TestCoreRelationAndAdversarialWitnesses ./...
# This one-shot run compiles the R1CS, runs Groth16 setup, proves the fixed
# sample, and verifies it. The generated keys remain in process memory.
go test -count=1 -run '^$' -bench '^BenchmarkProofGeneration$' -benchtime=1x
