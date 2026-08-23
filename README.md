# 🛡️ ZeroTrustBlock — Hyperledger Fabric + ZKP

[![Hyperledger Fabric](https://img.shields.io/badge/Hyperledger_Fabric-v2.4.9-2F3136?logo=hyperledger&logoColor=white)](https://www.hyperledger.org/use/fabric)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![Node.js](https://img.shields.io/badge/Node.js-18+-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Docker](https://img.shields.io/badge/Docker-20.10+-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**ZeroTrustBlock** is an enterprise-grade, privacy-preserving healthcare data sharing platform combining **Hyperledger Fabric v2.4** and **Zero-Knowledge Proofs (ZKP)** built with [gnark](https://github.com/Consensys/gnark) (BN254 curve, Groth16 zk-SNARKs).

---

## 🌟 Architecture & Key Features

- **Multi-Org Enterprise Topology**: 2 Organizations (`HospitalMSP` & `InsurerMSP`) spanning 4 peer nodes and a Raft consensus orderer cluster (`etcdraft`).
- **End-to-End ZKP Integration**: Real zero-knowledge range circuits (`AgeRangeCircuit`, `DiagnosisCategoryCircuit`) compiled and verified client-side in the Go Gateway SDK before Fabric invocation.
- **Enforced Zero Trust Policy**: Chaincode validates JSON access policies, client MSP identity (via Fabric `cid` package), consent status, and ZKP proof validity on every transaction.
- **Deterministic Smart Contract**: Chaincode utilizes Fabric proposal timestamps (`GetTxTimestamp()`) ensuring 100% deterministic execution across endorsing peers.
- **Multi-Org Endorsement Policy**: Strict `AND('HospitalMSP.member', 'InsurerMSP.member')` policy requiring multi-organization validation.
- **Revocation Safety**: Real-time patient consent revocation immediately blocks subsequent read attempts across all organizations.

---

## 🏗 System Topology

```mermaid
graph TD
    Client[Client / Healthcare Application] -->|1. Raw Data + Age Claim| Gateway[Go Gateway SDK]
    Gateway -->|2. Generate & Verify zk-SNARK| ZKP[gnark ZKP Engine (Groth16/BN254)]
    Gateway -->|3. Submit Proof + SHA-256 Hash| PeerH0[Peer0 Hospital (7051)]
    Gateway -->|3. Submit Proof + SHA-256 Hash| PeerI0[Peer0 Insurer (9051)]
    PeerH0 -->|4. AND Endorsement| Orderer[Raft Orderers (orderer1:7050, orderer2:8050)]
    PeerI0 -->|4. AND Endorsement| Orderer
    Orderer -->|5. Commit Block| Ledger[(Fabric Ledger State)]
```

---

## 📊 Benchmarking Breakdown

ZeroTrustBlock includes two distinct benchmark suites:

1. **Go Stress Engine (`benchmark/`)**:
   - Tests end-to-end Gateway ingestion, `gnark` ZKP generation, verification, and Fabric block commits.
   - **Simulation Mode**: Local development harness simulating high-concurrency loads.
   - **Real Mode (`cmd/real/main.go`)**: Direct high-concurrency execution against live Fabric peers.
   
2. **Hyperledger Caliper Suite (`caliper/`)**:
   - Evaluates peer network saturation and transaction throughput under flood stress.
   - **Target Rate**: 2,500 TPS
   - **Verified Achieved Throughput**: ~1,000 TPS (with 100% transaction success rate)

---

## 📋 Prerequisites

- **OS**: Linux (Ubuntu 20.04/22.04 LTS recommended) or macOS
- **Docker**: `v20.10+` & **Docker Compose** `v2.0+`
- **Go**: `v1.22+`
- **Node.js**: `v18+` & `npm v9+`

---

## 🚀 Quick Start

### Master Automated Reset & Run
Executes full network cleanup, certificate generation, Raft network bootstrap, chaincode lifecycle deployment on all 4 peers, wallet population, and Caliper benchmarking:

```bash
chmod +x full_reset.sh network.sh deploy.sh caliper_test.sh
./full_reset.sh
```

### Manual Component Steps

1. **Start Network**:
   ```bash
   ./network.sh up
   ```

2. **Deploy Chaincode**:
   ```bash
   ./deploy.sh
   ```

3. **Populate Gateway Wallet**:
   ```bash
   cd gateway
   go run cmd/populate/main.go
   cd ..
   ```

4. **Execute Real Network Benchmark**:
   ```bash
   cd benchmark
   go run cmd/real/main.go
   ```

5. **Run Caliper Benchmark**:
   ```bash
   ./caliper_test.sh
   ```

---

## 📁 Repository Structure

```
.
├── benchmark/               # Go stress test harness (Real & Simulation modes)
├── caliper/                 # Hyperledger Caliper v0.7 benchmark suite
├── chaincode/               # Smart contract (Go fabric-contract-api)
│   └── main.go              # Zero Trust logic, consent checks & GetTxTimestamp()
├── configtx/                # Network topology & channel profiles
├── crypto-config/           # Identity certificates configuration
├── gateway/                 # Client gateway SDK (Fabric SDK Go + ZKP integration)
│   ├── connection-profile.yaml # Network connection profile (fixed structure)
│   └── gateway.go           # High-level client API & ZKP pipeline
├── zkp/                     # Zero-Knowledge Proof circuits (gnark)
│   └── health_circuits.go   # Groth16 age range & diagnosis circuits
├── docker-compose.yml       # Raft orderers & 4 peer containers
├── deploy.sh                # Multi-org lifecycle chaincode installer
├── full_reset.sh            # Automated end-to-end deployment script
└── network.sh               # Cryptogen & configtxgen network bootstrapper
```

---

## 🔐 Security & Architecture Notes

- **Off-Chain Data & IPFS**: Actual medical record payloads are stored in off-chain encrypted storage (e.g. IPFS), while only SHA-256 data hashes, IPFS CIDs, and ZKP proof hashes are committed on-chain.
- **Docker Socket**: Local development containers mount `/var/run/docker.sock` for peer chaincode container management. Production deployments should utilize external Chaincode-as-a-Service (CCaaS).

---

## 🛡️ License

Apache 2.0 License.
