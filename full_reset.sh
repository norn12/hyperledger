#!/bin/bash
# ZeroTrustBlock: Full Reset & Benchmark Orchestrator
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== ZeroTrustBlock Full Lifecycle Start ===${NC}"

# 1. Permission Fix
echo -e "${YELLOW}[1/6] Fixing filesystem permissions...${NC}"
docker run --rm -v $(pwd):/data alpine chown -R $(id -u):$(id -g) /data

# 2. Network Down/Up
echo -e "${YELLOW}[2/6] Resetting Fabric Network...${NC}"
./network.sh down
./network.sh up

# 3. Wait for Network Stability (Dynamic Check)
echo -e "${YELLOW}[3/6] Waiting for Raft leader election...${NC}"
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

echo -e "${YELLOW}Waiting for Peer0 Hospital to be ready...${NC}"
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

# 4. Deploy Chaincode
echo -e "${YELLOW}[4/6] Deploying Clinical Chaincode...${NC}"
./deploy.sh
sleep 5 # Final grace period for lifecycle commitment

# 5. Reset and Populate Wallet
echo -e "${YELLOW}[5/6] Initializing Gateway Wallet...${NC}"
rm -rf gateway/wallet
cd gateway
go run cmd/populate/main.go
cd ..

# 6. Execution: Go Benchmark Flood
echo -e "${YELLOW}[6/6] Launching High-Concurrency Go Benchmark...${NC}"
cd benchmark
go run cmd/real/main.go

echo -e "${GREEN}=== ZeroTrustBlock Achievement Completed! ===${NC}"
