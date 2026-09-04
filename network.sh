#!/bin/bash
# ZeroTrustBlock Network Bootstrap Script
# Run this to set up and start the full Fabric network

set -e

NETWORK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FABRIC_VERSION="2.4.9"
CA_VERSION="1.5.7"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== ZeroTrustBlock Network Bootstrap ===${NC}"
echo ""

# ============================================================
# Step 1: Check prerequisites
# ============================================================
check_prereqs() {
  echo -e "${YELLOW}[1/5] Checking prerequisites...${NC}"
  command -v docker >/dev/null 2>&1 || { echo -e "${RED}Docker not found. Install Docker first.${NC}"; exit 1; }
  command -v go >/dev/null 2>&1    || { echo -e "${RED}Go not found. Install Go 1.21+ first.${NC}"; exit 1; }
  echo -e "${GREEN}✓ Docker and Go found${NC}"
}

# ============================================================
# Step 2: Install Fabric binaries and Docker images
# ============================================================
install_fabric() {
  echo -e "${YELLOW}[2/5] Installing Hyperledger Fabric binaries...${NC}"
  if [ ! -d "$HOME/fabric-samples" ] && [ ! -d "$(pwd)/fabric-samples" ]; then
    curl -sSL https://bit.ly/2ysbOFE | bash -s -- ${FABRIC_VERSION} ${CA_VERSION}
    echo -e "${GREEN}✓ Fabric binaries installed${NC}"
  else
    echo -e "${GREEN}✓ Fabric binaries already present${NC}"
  fi
  export PATH=$PATH:$HOME/fabric-samples/bin:$(pwd)/fabric-samples/bin
}

# ============================================================
# Step 3: Generate crypto material
# ============================================================
generate_crypto() {
  echo -e "${YELLOW}[3/5] Generating crypto material...${NC}"
  cd "$NETWORK_DIR"
  cryptogen generate --config=./crypto-config/crypto-config.yaml --output=./crypto-config
  # Copy admincerts to organization MSP folders
  mkdir -p crypto-config/peerOrganizations/hospital.zerotrust.com/msp/admincerts && cp crypto-config/peerOrganizations/hospital.zerotrust.com/users/Admin@hospital.zerotrust.com/msp/signcerts/* crypto-config/peerOrganizations/hospital.zerotrust.com/msp/admincerts/
  mkdir -p crypto-config/peerOrganizations/insurer.zerotrust.com/msp/admincerts && cp crypto-config/peerOrganizations/insurer.zerotrust.com/users/Admin@insurer.zerotrust.com/msp/signcerts/* crypto-config/peerOrganizations/insurer.zerotrust.com/msp/admincerts/
  mkdir -p crypto-config/ordererOrganizations/zerotrust.com/msp/admincerts && cp crypto-config/ordererOrganizations/zerotrust.com/users/Admin@zerotrust.com/msp/signcerts/* crypto-config/ordererOrganizations/zerotrust.com/msp/admincerts/
  
  # Rename private keys to priv_sk for stability in Caliper/Gateway
  find crypto-config -name "*_sk" -exec sh -c 'mv "$0" "$(dirname "$0")/priv_sk"' {} \;
  
  echo -e "${GREEN}✓ Crypto material generated${NC}"
}

# ============================================================
# Step 4: Generate genesis block and channel config
# ============================================================
generate_artifacts() {
  echo -e "${YELLOW}[4/5] Generating genesis block and channel artifacts...${NC}"
  cd "$NETWORK_DIR"
  export FABRIC_CFG_PATH=$PWD/configtx

  configtxgen -profile ZeroTrustOrdererGenesis -channelID system-channel -outputBlock ./configtx/genesis.block
  configtxgen -profile ZeroTrustChannel -outputCreateChannelTx ./configtx/channel.tx -channelID healthchannel
  configtxgen -profile ZeroTrustChannel -outputAnchorPeersUpdate ./configtx/HospitalMSPanchors.tx -channelID healthchannel -asOrg HospitalMSP
  configtxgen -profile ZeroTrustChannel -outputAnchorPeersUpdate ./configtx/InsurerMSPanchors.tx -channelID healthchannel -asOrg InsurerMSP
  echo -e "${GREEN}✓ Artifacts generated${NC}"
}

# ============================================================
# Step 5: Start the network
# ============================================================
start_network() {
  echo -e "${YELLOW}[5/5] Starting Docker network...${NC}"
  cd "$NETWORK_DIR"
  docker-compose stop
  docker-compose rm -f
  docker-compose up -d
  echo ""
  echo -e "${GREEN}✓ Network started!${NC}"
  echo ""
  echo "Services running:"
  docker-compose ps
}

# ============================================================
# Teardown
# ============================================================
teardown() {
  echo -e "${YELLOW}Tearing down network...${NC}"
  cd "$NETWORK_DIR"
  docker stop chaincode.zerotrust.com 2>/dev/null || true
  docker rm chaincode.zerotrust.com 2>/dev/null || true
  docker-compose down --volumes --remove-orphans
  rm -rf "$NETWORK_DIR/crypto-config/peerOrganizations"
  rm -rf "$NETWORK_DIR/crypto-config/ordererOrganizations"
  rm -f "$NETWORK_DIR/configtx/*.block"
  rm -f "$NETWORK_DIR/configtx/*.tx"
  echo -e "${GREEN}✓ Network torn down${NC}"
}

# ============================================================
# Main
# ============================================================
case "${1}" in
  up)
    check_prereqs
    install_fabric
    generate_crypto
    generate_artifacts
    start_network
    ;;
  down)
    teardown
    ;;
  restart)
    teardown
    check_prereqs
    install_fabric
    generate_crypto
    generate_artifacts
    start_network
    ;;
  *)
    echo "Usage: $0 [up|down|restart]"
    echo ""
    echo "  up       - Start the full ZeroTrustBlock network"
    echo "  down     - Stop and clean up the network"
    echo "  restart  - Full teardown and restart"
    exit 1
    ;;
esac
