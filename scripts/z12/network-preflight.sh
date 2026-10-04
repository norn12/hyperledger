#!/usr/bin/env bash
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/output/z12/network-preflight.txt"
mkdir -p "$ROOT/output/z12"
status=0
{
  echo "Z12 live Fabric preflight: $(date -Is)"
  echo "No network start, reset, deploy, or chaincode lifecycle mutation is performed by this script."
  if ! docker info >/dev/null 2>&1; then
    echo "LIVE_FABRIC=UNAVAILABLE: Docker daemon API is inaccessible."
    docker info 2>&1 || true
    status=2
  else
    echo "LIVE_FABRIC=DOCKER_DAEMON_REACHABLE"
    docker ps --format '{{.Names}} {{.Status}}' || status=2
    for name in orderer1.zerotrust.com orderer2.zerotrust.com orderer3.zerotrust.com peer0.hospital.zerotrust.com peer1.hospital.zerotrust.com peer0.insurer.zerotrust.com peer1.insurer.zerotrust.com; do
      if docker inspect "$name" >/dev/null 2>&1; then
        docker inspect --format '{{.Name}} {{.State.Status}}' "$name"
      else
        echo "MISSING_CONTAINER=$name"
        status=2
      fi
    done
    if docker compose version >/dev/null 2>&1; then
      docker compose version
    elif command -v docker-compose >/dev/null 2>&1; then
      docker-compose --version
    else
      echo "COMPOSE=UNAVAILABLE"
      status=2
    fi
    PEER="$(command -v peer || true)"
    if [ -z "$PEER" ] && [ -x "$ROOT/fabric-samples/bin/peer" ]; then PEER="$ROOT/fabric-samples/bin/peer"; fi
    if [ -z "$PEER" ]; then echo "PEER_CLI=UNAVAILABLE"; status=2; else "$PEER" version || status=2; fi
    echo "CHANNEL/CHAINCODE/IDENTITY LIVE QUERIES require the peer CLI, TLS/MSP configuration, and a reachable channel; inspect them manually before running the gated integration tests."
  fi
} > "$OUT"
cat "$OUT"
exit "$status"
