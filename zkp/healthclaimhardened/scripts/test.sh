#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
go version
go mod verify
go test -count=1 -v ./...
