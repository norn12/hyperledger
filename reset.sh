#!/bin/bash
# ZeroTrustBlock: one-command development reset
# Rebuilds Fabric crypto/network, deploys chaincode, enrolls gateway identities,
# and starts the separate IPFS service. Does not run the benchmark.
set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== ZeroTrustBlock Automated Reset ===${NC}"

echo -e "${YELLOW}[1/5] Resetting Fabric network...${NC}"
./network.sh restart

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

echo -e "${YELLOW}[5/5] Running health checks...${NC}"
docker ps --format 'table {{.Names}}\t{{.Status}}' | grep -E 'ca\.|orderer|peer|chaincode|zerotrust-ipfs' || true

echo -e "${GREEN}=== ZeroTrustBlock Reset Complete ===${NC}"
echo "Gateway identities: appAdmin, doctor, insurer"
echo "IPFS: http://127.0.0.1:5001/api/v0"
echo "Run gateway tests from: $PROJECT_DIR/gateway"
