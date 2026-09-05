#!/bin/bash
# ZeroTrustBlock: Full Reset & Benchmark Orchestrator
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${GREEN}=== ZeroTrustBlock Full Lifecycle Start ===${NC}"

# 1. Network reset. network.sh now handles CA-owned file permissions,
#    regenerates CA TLS certificates, and clears stale gateway identities.
echo -e "${YELLOW}[1/6] Resetting Fabric Network...${NC}"
cd "$PROJECT_DIR"
./network.sh down
./network.sh up

# 2. Wait for Network Stability
echo -e "${YELLOW}[2/6] Waiting for Raft leader election...${NC}"
MAX_RETRIES=30
RETRY_COUNT=0
while ! docker logs orderer1.zerotrust.com 2>&1 | grep -q "Raft leader changed"; do
    if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
        echo -e "${RED}Orderer failed to elect leader in time. Check logs.${NC}"
        exit 1
    fi
    echo -n "."
    sleep 2
    RETRY_COUNT=$((RETRY_COUNT+1))
done
echo -e "\n${GREEN}✓ Raft leader established${NC}"

RETRY_COUNT=0
while ! docker logs peer0.hospital.zerotrust.com 2>&1 | grep -q "Started peer"; do
    if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
        echo -e "${RED}Peer failed to start in time. Check logs.${NC}"
        exit 1
    fi
    echo -n "."
    sleep 2
    RETRY_COUNT=$((RETRY_COUNT+1))
done
echo -e "\n${GREEN}✓ Network is stable${NC}"

# 3. Deploy Chaincode
echo -e "${YELLOW}[3/6] Deploying Clinical Chaincode...${NC}"
./deploy.sh
sleep 5

# 4. Enroll fresh gateway identities against the newly generated CAs.
#    network.sh already removed the stale wallet.
echo -e "${YELLOW}[4/6] Provisioning Gateway identities...${NC}"
cd "$PROJECT_DIR/gateway"
go run ./cmd/enroll
cd "$PROJECT_DIR"

echo -e "${GREEN}✓ appAdmin, doctor and insurer identities provisioned${NC}"

# 5. Ensure the separately managed IPFS service is running.
echo -e "${YELLOW}[5/6] Starting IPFS service...${NC}"
docker-compose -f docker-compose.ipfs.yml up -d

echo -e "${GREEN}✓ IPFS service is running${NC}"

# 6. Execution: Go Benchmark Flood
echo -e "${YELLOW}[6/6] Launching High-Concurrency Go Benchmark...${NC}"
cd "$PROJECT_DIR/benchmark"
go run cmd/real/main.go

cd "$PROJECT_DIR"
echo -e "${GREEN}=== ZeroTrustBlock Achievement Completed! ===${NC}"
