#!/bin/bash
# ZeroTrustBlock - Full Lifecycle Deployment (TLS Mode with Hostnames)
set -e

# Setup paths
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH=$PATH:${PROJECT_DIR}/fabric-samples/bin
export FABRIC_CFG_PATH=${PROJECT_DIR}/fabric-samples/config

# Global Environment
export CORE_PEER_TLS_ENABLED=true
export ORDERER_CA=${PROJECT_DIR}/crypto-config/ordererOrganizations/zerotrust.com/orderers/orderer1.zerotrust.com/tls/ca.crt

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}=== 1. Creating Channel (healthchannel) ===${NC}"
export CORE_PEER_LOCALMSPID="HospitalMSP"
export CORE_PEER_MSPCONFIGPATH=${PROJECT_DIR}/crypto-config/peerOrganizations/hospital.zerotrust.com/users/Admin@hospital.zerotrust.com/msp
export CORE_PEER_ADDRESS=peer0.hospital.zerotrust.com:7051
export CORE_PEER_TLS_ROOTCERT_FILE=${PROJECT_DIR}/crypto-config/peerOrganizations/hospital.zerotrust.com/peers/peer0.hospital.zerotrust.com/tls/ca.crt

# Use orderer hostname
peer channel create -o orderer1.zerotrust.com:7050 -c healthchannel --ordererTLSHostnameOverride orderer1.zerotrust.com -f ./configtx/channel.tx --outputBlock ./configtx/healthchannel.block --tls --cafile $ORDERER_CA

echo -e "${GREEN}=== 2. Joining Hospital Peers to Channel ===${NC}"
# Peer0 Hospital
peer channel join -b ./configtx/healthchannel.block
peer channel update -o orderer1.zerotrust.com:7050 --ordererTLSHostnameOverride orderer1.zerotrust.com -c healthchannel -f ./configtx/HospitalMSPanchors.tx --tls --cafile $ORDERER_CA

# Peer1 Hospital
export CORE_PEER_ADDRESS=peer1.hospital.zerotrust.com:8051
export CORE_PEER_TLS_ROOTCERT_FILE=${PROJECT_DIR}/crypto-config/peerOrganizations/hospital.zerotrust.com/peers/peer1.hospital.zerotrust.com/tls/ca.crt
peer channel join -b ./configtx/healthchannel.block

echo -e "${GREEN}=== 3. Joining Insurer Peers to Channel ===${NC}"
# Peer0 Insurer
export CORE_PEER_LOCALMSPID="InsurerMSP"
export CORE_PEER_ADDRESS=peer0.insurer.zerotrust.com:9051
export CORE_PEER_MSPCONFIGPATH=${PROJECT_DIR}/crypto-config/peerOrganizations/insurer.zerotrust.com/users/Admin@insurer.zerotrust.com/msp
export CORE_PEER_TLS_ROOTCERT_FILE=${PROJECT_DIR}/crypto-config/peerOrganizations/insurer.zerotrust.com/peers/peer0.insurer.zerotrust.com/tls/ca.crt
peer channel join -b ./configtx/healthchannel.block
peer channel update -o orderer1.zerotrust.com:7050 --ordererTLSHostnameOverride orderer1.zerotrust.com -c healthchannel -f ./configtx/InsurerMSPanchors.tx --tls --cafile $ORDERER_CA

# Peer1 Insurer
export CORE_PEER_ADDRESS=peer1.insurer.zerotrust.com:10051
export CORE_PEER_TLS_ROOTCERT_FILE=${PROJECT_DIR}/crypto-config/peerOrganizations/insurer.zerotrust.com/peers/peer1.insurer.zerotrust.com/tls/ca.crt
peer channel join -b ./configtx/healthchannel.block

echo -e "${GREEN}=== 4. Packaging Chaincode ===${NC}"
rm -f health.tar.gz
peer lifecycle chaincode package health.tar.gz --path chaincode --lang golang --label health_1.0

echo -e "${GREEN}=== 5. Installing Chaincode on All Peers ===${NC}"
# Insurer Peer 1 & Peer 0
peer lifecycle chaincode install health.tar.gz
export CORE_PEER_ADDRESS=peer0.insurer.zerotrust.com:9051
export CORE_PEER_TLS_ROOTCERT_FILE=${PROJECT_DIR}/crypto-config/peerOrganizations/insurer.zerotrust.com/peers/peer0.insurer.zerotrust.com/tls/ca.crt
peer lifecycle chaincode install health.tar.gz

# Hospital Peer 0 & Peer 1
export CORE_PEER_LOCALMSPID="HospitalMSP"
export CORE_PEER_ADDRESS=peer0.hospital.zerotrust.com:7051
export CORE_PEER_MSPCONFIGPATH=${PROJECT_DIR}/crypto-config/peerOrganizations/hospital.zerotrust.com/users/Admin@hospital.zerotrust.com/msp
export CORE_PEER_TLS_ROOTCERT_FILE=${PROJECT_DIR}/crypto-config/peerOrganizations/hospital.zerotrust.com/peers/peer0.hospital.zerotrust.com/tls/ca.crt
peer lifecycle chaincode install health.tar.gz

export CORE_PEER_ADDRESS=peer1.hospital.zerotrust.com:8051
export CORE_PEER_TLS_ROOTCERT_FILE=${PROJECT_DIR}/crypto-config/peerOrganizations/hospital.zerotrust.com/peers/peer1.hospital.zerotrust.com/tls/ca.crt
peer lifecycle chaincode install health.tar.gz

echo -e "${GREEN}=== 6. Approving Chaincode for Both Orgs (Multi-Org Policy) ===${NC}"
PACKAGE_ID=$(peer lifecycle chaincode queryinstalled | grep -oP 'health_1.0:\K[0-9a-fA-F]+' | head -n 1)
FULL_PACKAGE_ID="health_1.0:$PACKAGE_ID"

# Hospital Approve (requires AND policy across HospitalMSP & InsurerMSP)
export CORE_PEER_ADDRESS=localhost:7051
export CORE_PEER_TLS_ROOTCERT_FILE=${PROJECT_DIR}/crypto-config/peerOrganizations/hospital.zerotrust.com/peers/peer0.hospital.zerotrust.com/tls/ca.crt
peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer1.zerotrust.com --tls --cafile $ORDERER_CA --channelID healthchannel --name health --version 1.0 --package-id $FULL_PACKAGE_ID --sequence 1 --signature-policy "AND('HospitalMSP.member','InsurerMSP.member')"

# Insurer Approve
export CORE_PEER_LOCALMSPID="InsurerMSP"
export CORE_PEER_ADDRESS=localhost:9051
export CORE_PEER_MSPCONFIGPATH=${PROJECT_DIR}/crypto-config/peerOrganizations/insurer.zerotrust.com/users/Admin@insurer.zerotrust.com/msp
export CORE_PEER_TLS_ROOTCERT_FILE=${PROJECT_DIR}/crypto-config/peerOrganizations/insurer.zerotrust.com/peers/peer0.insurer.zerotrust.com/tls/ca.crt
peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer1.zerotrust.com --tls --cafile $ORDERER_CA --channelID healthchannel --name health --version 1.0 --package-id $FULL_PACKAGE_ID --sequence 1 --signature-policy "AND('HospitalMSP.member','InsurerMSP.member')"

echo -e "${GREEN}=== 7. Committing Chaincode Definition ===${NC}"
export CORE_PEER_LOCALMSPID="HospitalMSP"
export CORE_PEER_ADDRESS=localhost:7051
export CORE_PEER_MSPCONFIGPATH=${PROJECT_DIR}/crypto-config/peerOrganizations/hospital.zerotrust.com/users/Admin@hospital.zerotrust.com/msp
export CORE_PEER_TLS_ROOTCERT_FILE=${PROJECT_DIR}/crypto-config/peerOrganizations/hospital.zerotrust.com/peers/peer0.hospital.zerotrust.com/tls/ca.crt

peer lifecycle chaincode commit -o localhost:7050 --ordererTLSHostnameOverride orderer1.zerotrust.com --tls --cafile $ORDERER_CA --channelID healthchannel --name health --version 1.0 --sequence 1 --signature-policy "AND('HospitalMSP.member','InsurerMSP.member')" \
  --peerAddresses localhost:7051 --tlsRootCertFiles ${PROJECT_DIR}/crypto-config/peerOrganizations/hospital.zerotrust.com/peers/peer0.hospital.zerotrust.com/tls/ca.crt \
  --peerAddresses localhost:9051 --tlsRootCertFiles ${PROJECT_DIR}/crypto-config/peerOrganizations/insurer.zerotrust.com/peers/peer0.insurer.zerotrust.com/tls/ca.crt

echo -e "${GREEN}✓ ZeroTrustBlock Chaincode is Active across all 4 peers with AND('HospitalMSP.member', 'InsurerMSP.member') endorsement!${NC}"
