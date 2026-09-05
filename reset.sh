#!/bin/bash
# ZeroTrustBlock: one-command development reset
# Rebuilds Fabric crypto/network, deploys chaincode, enrolls gateway identities,
# and starts the separate IPFS service. Does not run the benchmark.
set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}=== ZeroTrustBlock Automated Reset ===${NC}"

echo -e "${YELLOW}[1/5] Resetting Fabric network...${NC}"
./network.sh restart

# Give the Raft cluster time to elect a leader before any channel/lifecycle
# transaction is submitted. This avoids intermittent SERVICE_UNAVAILABLE
# errors immediately after Docker startup.
echo -e "${YELLOW}Waiting for Raft leader election...${NC}"
MAX_RETRIES=45
RETRY_COUNT=0
while true; do
  if docker logs orderer1.zerotrust.com 2>&1 | grep -Eq "Raft leader changed|becomes leader|became leader"; then
    break
  fi
  if [ "$RETRY_COUNT" -ge "$MAX_RETRIES" ]; then
    echo -e "${RED}Raft leader was not elected in time.${NC}"
    docker ps --format 'table {{.Names}}\t{{.Status}}'
    docker logs orderer1.zerotrust.com --tail 80 2>&1 || true
    exit 1
  fi
  sleep 2
  RETRY_COUNT=$((RETRY_COUNT + 1))
done
echo -e "${GREEN}✓ Raft leader established${NC}"

echo -e "${YELLOW}[2/5] Deploying chaincode...${NC}"
./deploy.sh

echo -e "${YELLOW}[3/5] Enrolling fresh gateway identities...${NC}"
cd gateway
go run ./cmd/enroll
cd "$PROJECT_DIR"

echo -e "${YELLOW}[4/5] Starting IPFS...${NC}"
docker-compose -f docker-compose.ipfs.yml up -d
export ZT_IPFS_ENABLED=true
export ZT_IPFS_API_URL="http://127.0.0.1:5001/api/v0"
if [ -z "${ZT_IPFS_ENCRYPTION_KEY:-}" ]; then
  export ZT_IPFS_ENCRYPTION_KEY="$(openssl rand -hex 32)"
fi

# Persist the generated development key locally so the same key can be
# re-used after a reset. .env.local is ignored by git.
cat > "$PROJECT_DIR/.env.local" <<EOF
ZT_IPFS_ENABLED=true
ZT_IPFS_API_URL=http://127.0.0.1:5001/api/v0
ZT_IPFS_ENCRYPTION_KEY=$ZT_IPFS_ENCRYPTION_KEY
EOF
chmod 600 "$PROJECT_DIR/.env.local"

echo -e "${YELLOW}[5/5] Running health checks...${NC}"
docker ps --format 'table {{.Names}}\t{{.Status}}' | grep -E 'ca\.|orderer|peer|chaincode|zerotrust-ipfs' || true
curl -fsS -X POST http://127.0.0.1:5001/api/v0/id >/dev/null && echo -e "${GREEN}✓ IPFS RPC is reachable${NC}" || echo -e "${YELLOW}⚠ IPFS RPC is not reachable${NC}"

echo -e "${GREEN}=== ZeroTrustBlock Reset Complete ===${NC}"
echo "Gateway identities: appAdmin, doctor, insurer"
echo "IPFS: http://127.0.0.1:5001/api/v0"
echo "IPFS credentials saved to: $PROJECT_DIR/.env.local"
echo "Run gateway tests from: $PROJECT_DIR/gateway"
echo "Load IPFS environment in a shell with: source $PROJECT_DIR/.env.local"
