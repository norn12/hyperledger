#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
go version
go test -count=1 -run '^$' -bench 'BenchmarkProof(Generation|Verification)$' -benchtime=10x -benchmem
