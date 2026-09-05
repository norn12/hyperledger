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

check_prereqs() {
  echo -e "${YELLOW}[1/5] Checking prerequisites...${NC}"
  command -v docker >/dev/null 2>&1 || { echo -e "${RED}Docker not found. Install Docker first.${NC}"; exit 1; }
  command -v go >/dev/null 2>&1 || { echo -e "${RED}Go not found. Install Go 1.21+ first.${NC}"; exit 1; }
  command -v openssl >/dev/null 2>&1 || { echo -e "${RED}OpenSSL not found. Install openssl first.${NC}"; exit 1; }
  echo -e "${GREEN}✓ Docker, Go and OpenSSL found${NC}"
}

install_fabric() {
  echo -e "${YELLOW}[2/5] Installing Hyperledger Fabric binaries...${NC}"
  if [ ! -d "$HOME/fabric-samples" ] && [ ! -d "$NETWORK_DIR/fabric-samples" ]; then
    curl -sSL https://bit.ly/2ysbOFE | bash -s -- ${FABRIC_VERSION} ${CA_VERSION}
    echo -e "${GREEN}✓ Fabric binaries installed${NC}"
  else
    echo -e "${GREEN}✓ Fabric binaries already present${NC}"
  fi
  export PATH=$PATH:$HOME/fabric-samples/bin:$NETWORK_DIR/fabric-samples/bin
}

generate_ca_tls_cert() {
  local org="$1"
  local ca_name="$2"
  local ca_dir="$NETWORK_DIR/crypto-config/peerOrganizations/$org/ca"
  local ca_cert="$ca_dir/$ca_name-cert.pem"
  local ca_key="$ca_dir/priv_sk"

  if [ ! -f "$ca_cert" ] || [ ! -f "$ca_key" ]; then
    echo -e "${RED}Missing CA material for $ca_name${NC}"
    exit 1
  fi

  openssl req -new -newkey rsa:2048 -nodes \
    -keyout "$ca_dir/tls-server.key" \
    -out "$ca_dir/tls-server.csr" \
    -subj "/CN=$ca_name" \
    -addext "subjectAltName=DNS:$ca_name,DNS:localhost,IP:127.0.0.1" \
    >/dev/null 2>&1

  openssl x509 -req \
    -in "$ca_dir/tls-server.csr" \
    -CA "$ca_cert" \
    -CAkey "$ca_key" \
    -CAcreateserial \
    -out "$ca_dir/tls-server.crt" \
    -days 825 -sha256 -copy_extensions copy \
    >/dev/null 2>&1

  openssl verify -CAfile "$ca_cert" "$ca_dir/tls-server.crt" >/dev/null
  rm -f "$ca_dir/tls-server.csr" "$ca_dir/$ca_name-cert.srl"
  chmod 600 "$ca_dir/tls-server.key"
  chmod 644 "$ca_dir/tls-server.crt"
  echo -e "${GREEN}✓ CA TLS material ready: $ca_name${NC}"
}

generate_crypto() {
  echo -e "${YELLOW}[3/5] Generating crypto material...${NC}"
  cd "$NETWORK_DIR"
  cryptogen generate --config=./crypto-config/crypto-config.yaml --output=./crypto-config

  find crypto-config -name "*_sk" -exec sh -c '
    src="$1"
    dst="$(dirname "$src")/priv_sk"
    if [ "$src" != "$dst" ]; then mv "$src" "$dst"; fi
  ' _ {} \;

  generate_ca_tls_cert "hospital.zerotrust.com" "ca.hospital.zerotrust.com"
  generate_ca_tls_cert "insurer.zerotrust.com" "ca.insurer.zerotrust.com"

  # Every cryptogen run creates new enrollment certificates. Never reuse a
  # wallet containing identities signed by an older crypto generation.
  rm -rf "$NETWORK_DIR/gateway/wallet"

  mkdir -p crypto-config/peerOrganizations/hospital.zerotrust.com/msp/admincerts
  cp crypto-config/peerOrganizations/hospital.zerotrust.com/users/Admin@hospital.zerotrust.com/msp/signcerts/* crypto-config/peerOrganizations/hospital.zerotrust.com/msp/admincerts/
  mkdir -p crypto-config/peerOrganizations/insurer.zerotrust.com/msp/admincerts
  cp crypto-config/peerOrganizations/insurer.zerotrust.com/users/Admin@insurer.zerotrust.com/msp/signcerts/* crypto-config/peerOrganizations/insurer.zerotrust.com/msp/admincerts/
  mkdir -p crypto-config/ordererOrganizations/zerotrust.com/msp/admincerts
  cp crypto-config/ordererOrganizations/zerotrust.com/users/Admin@zerotrust.com/msp/signcerts/* crypto-config/ordererOrganizations/zerotrust.com/msp/admincerts/

  echo -e "${GREEN}✓ Crypto material generated and gateway wallet reset${NC}"
}

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

start_network() {
  echo -e "${YELLOW}[5/5] Starting Docker network...${NC}"
  cd "$NETWORK_DIR"
  docker-compose stop || true
  docker-compose rm -f || true
  docker-compose up -d
  echo ""
  echo -e "${GREEN}✓ Network started!${NC}"
  echo ""
  echo "Services running:"
  docker-compose ps
}

teardown() {
  echo -e "${YELLOW}Tearing down network...${NC}"
  cd "$NETWORK_DIR"
  docker stop chaincode.zerotrust.com 2>/dev/null || true
  docker rm chaincode.zerotrust.com 2>/dev/null || true

  # CA containers write their bind-mounted keystores as root. Normalize the
  # workspace ownership before deleting generated crypto so reset is repeatable
  # without sudo/manual chown. Keep IPFS untouched because it is separate.
  if [ -d "$NETWORK_DIR/crypto-config" ]; then
    docker run --rm -v "$NETWORK_DIR/crypto-config:/data" alpine:latest \
      sh -c 'chown -R '"$(id -u):$(id -g)"' /data' >/dev/null 2>&1 || true
  fi

  docker-compose down --volumes
  rm -rf "$NETWORK_DIR/crypto-config/peerOrganizations"
  rm -rf "$NETWORK_DIR/crypto-config/ordererOrganizations"
  rm -f "$NETWORK_DIR/configtx/*.block" "$NETWORK_DIR/configtx/*.tx"
  echo -e "${GREEN}✓ Network torn down${NC}"
}

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
