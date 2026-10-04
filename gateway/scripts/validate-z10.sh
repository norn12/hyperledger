#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
export GOCACHE="${GOCACHE:-/tmp/ztb-z10-gocache}"
go version
go test -count=1 -v ./...
go test -count=1 -run '^$' -bench '^BenchmarkGatewayLocalZKPProcessing$' -benchtime=10x -benchmem
