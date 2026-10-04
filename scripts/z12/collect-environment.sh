#!/usr/bin/env bash
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/output/z12/environment.txt"
mkdir -p "$ROOT/output/z12"
{
  echo "Z12 environment collection"
  date -Is
  echo "Repository: $ROOT"
  echo "Git HEAD: $(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unavailable)"
  echo "Git status:"
  git -C "$ROOT" status --short 2>&1 || true
  echo
  echo "OS/kernel:"
  uname -a
  echo "CPU:"
  lscpu 2>/dev/null | grep -E '^(Architecture|CPU\(s\)|Model name|Thread\(s\) per core|Core\(s\) per socket|Socket\(s\)):' || true
  echo "RAM:"
  free -h 2>&1 | head -2 || true
  echo
  echo "Host Go:"
  go version 2>&1 || true
  echo "Gateway module Go and dependencies:"
  GOTOOLCHAIN=auto go -C "$ROOT/gateway" version 2>&1 || true
  GOTOOLCHAIN=auto go -C "$ROOT/gateway" list -m github.com/hyperledger/fabric-sdk-go github.com/consensys/gnark github.com/consensys/gnark-crypto 2>&1 || true
  echo "HealthClaimHardened module Go and dependencies:"
  GOTOOLCHAIN=auto go -C "$ROOT/zkp/healthclaimhardened" version 2>&1 || true
  GOTOOLCHAIN=auto go -C "$ROOT/zkp/healthclaimhardened" list -m github.com/consensys/gnark github.com/consensys/gnark-crypto 2>&1 || true
  echo "Chaincode dependencies:"
  GOTOOLCHAIN=auto go -C "$ROOT/chaincode" list -m github.com/hyperledger/fabric-contract-api-go github.com/hyperledger/fabric-chaincode-go 2>&1 || true
  echo
  echo "Docker client/server:"
  docker --version 2>&1 || true
  docker version 2>&1 || true
  echo "Docker Compose plugin:"
  docker compose version 2>&1 || true
  echo "Docker Compose standalone:"
  docker-compose --version 2>&1 || true
  echo "Docker daemon info:"
  docker info 2>&1 || true
  echo
  echo "Repository-declared Fabric configuration (not live verification):"
  echo "Fabric version: network.sh declares 2.4.9; compose image tags are 2.4"
  echo "CA version: network.sh declares 1.5.7"
  echo "Organizations: HospitalMSP, InsurerMSP"
  echo "Peers: 4 (2 per organization)"
  echo "Orderers: 3, etcdraft/Raft (CFT)"
  echo "Channel: healthchannel"
  echo "Chaincode: health; deploy.sh declares version 1.0 sequence 1"
  echo "Endorsement: AND('HospitalMSP.member','InsurerMSP.member')"
  echo "TLS: enabled in deploy.sh; Gateway profile uses grpcs peers/orderers and https CAs"
  echo "Expected Gateway identity: InsurerMSP zkpVerifier with role=zkpVerifier"
  echo "Expected registry admin: HospitalMSP appAdmin with role=admin"
  echo "Actual live identity/wallet/network state: not verified"
  echo "CLI peer:"
  if command -v peer >/dev/null 2>&1; then peer version 2>&1 || true; elif [ -x "$ROOT/fabric-samples/bin/peer" ]; then "$ROOT/fabric-samples/bin/peer" version 2>&1 || true; else echo "peer executable unavailable"; fi
} > "$OUT"
cat "$OUT"
