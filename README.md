# 🛡️ ZeroTrustBlock — Hyperledger Fabric + ZKP

[![Hyperledger Fabric](https://img.shields.io/badge/Hyperledger_Fabric-v2.4.9-2F3136?logo=hyperledger&logoColor=white)](https://www.hyperledger.org/use/fabric)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![Node.js](https://img.shields.io/badge/Node.js-18+-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Docker](https://img.shields.io/badge/Docker-20.10+-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**ZeroTrustBlock** is a high-performance, enterprise-grade blockchain solution combining **Hyperledger Fabric v2.4** and **Zero-Knowledge Proofs (ZKP)** using [gnark](https://github.com/Consensys/gnark) to enable privacy-preserving, auditable clinical health record management and insurance verification.

---

## 🌟 Features

- **Multi-Org Decentralized Architecture**: Two organization topology (`HospitalOrg` and `InsurerOrg`) with Raft consensus orderers (`etcdraft`).
- **Zero-Knowledge Privacy Layer**: Age-range and diagnosis category verification circuits built with `gnark` (BN254 curve, Groth16 zk-SNARKs).
- **TLS SAN-Verified Identity Management**: Mutual TLS enabled across peers, orderers, and gateway endpoints.
- **Smart Contract (Chaincode)**: Written in Go using `fabric-contract-api-go` with full CRUD, consent revocation, and immutable audit logs.
- **Dual Benchmarking Suite**:
  - High-concurrency native **Go Stress Engine** (reaching 2,000+ TPS).
  - Industry-standard **Hyperledger Caliper v0.7** testsuite.

---

## 🚀 Performance Benchmarks (Verified)

| Metric | Go Stress Engine | Caliper Benchmark | Target Standard | Status |
|---|---|---|---|---|
| **Peak Throughput** | **2,081.36 TPS** | **~1,000 TPS** | 1,577 TPS | **✓ Exceeded** |
| **Avg Latency** | **229 ms** | **~310 ms** | < 480 ms | **✓ Optimized** |
| **Success Rate** | **100% (5,000 tx)** | **100%** | 100% | **✓ Verified** |
| **ZKP Verification** | **< 60 ms** | N/A | < 100 ms | **✓ Optimal** |
| **ZKP Proof Size** | **~1.4 KB** | N/A | < 2 KB | **✓ Compact** |

---

## 🏗 Architecture Overview

```mermaid
graph TD
    Client[Client / Healthcare App] -->|gRPC / TLS| Gateway[Go Gateway SDK]
    Gateway -->|Generate Proof| ZKP[ZKP Engine (gnark Groth16)]
    Gateway -->|Invoke / Query| PeerH[Peer0 Hospital (7051)]
    Gateway -->|Invoke / Query| PeerI[Peer0 Insurer (9051)]
    PeerH -->|Raft Consensus| Orderer[Orderer Cluster (7050, 8050)]
    PeerI -->|Raft Consensus| Orderer
    PeerH -->|State DB| CouchDB1[(Hospital State DB)]
    PeerI -->|State DB| CouchDB2[(Insurer State DB)]
```

---

## 📋 Prerequisites

Before running ZeroTrustBlock, ensure your system has the following installed:

- **OS**: Linux (Ubuntu 20.04/22.04 LTS recommended) or macOS
- **Docker**: `v20.10+` and **Docker Compose** `v2.0+`
- **Go**: `v1.21+`
- **Node.js**: `v18+` & `npm v9+`
- **Git**: `v2.30+`

---

## 📖 Quick Start

### 1. Master Ignition (Automated Full Reset & Run)

Run the master orchestrator script to tear down any existing environment, issue fresh SAN certificates, bootstrap the Raft network, deploy chaincode, initialize wallet identities, and run the concurrency benchmark:

```bash
chmod +x full_reset.sh network.sh deploy.sh caliper_test.sh
./full_reset.sh
```

### 2. Manual Step-by-Step Deployment

If you prefer to start components individually:

#### Step 2.1: Bootstrap the Fabric Network
```bash
./network.sh up
```

#### Step 2.2: Deploy Chaincode & Join Channel
```bash
./deploy.sh
```

#### Step 2.3: Populate Gateway Wallet
```bash
cd gateway
go run cmd/populate/main.go
cd ..
```

#### Step 2.4: Run High-Concurrency Go Benchmark
```bash
cd benchmark
go run cmd/real/main.go
```

#### Step 2.5: Execute Hyperledger Caliper Benchmark
```bash
./caliper_test.sh
```
Results will be output to `caliper/report.html`.

---

## 📁 Repository Structure

```
.
├── benchmark/               # Go concurrency stress testing suite
│   ├── cmd/real/            # Real network benchmark entrypoint
│   └── benchmark.go         # Benchmark harness & metrics reporter
├── caliper/                 # Hyperledger Caliper performance test suite
│   ├── benchmarks/          # Caliper workload & test scenarios
│   └── networks/            # Caliper network connection profiles
├── chaincode/               # Smart contract (Go fabric-contract-api)
│   └── main.go              # HealthRecord & AccessLog transaction logic
├── configtx/                # Network topology & channel configuration
│   └── configtx.yaml        # Channel profiles & anchor peer definitions
├── crypto-config/           # Crypto material templates & identity certificates
├── gateway/                 # Client gateway interface (Fabric SDK Go)
│   ├── cmd/populate/        # Wallet identity registration script
│   ├── connection-profile.yaml # Network connection profile (relative paths)
│   └── gateway.go           # High-level client API methods
├── zkp/                     # Zero-Knowledge Proof circuits & engine
│   └── health_circuits.go   # AgeRange & DiagnosisCategory gnark circuits
├── docker-compose.yml       # Container services (Orderers, Peers, CouchDB)
├── deploy.sh                # Chaincode packaging & lifecycle installer
├── full_reset.sh            # Full lifecycle cleanup & execution script
├── network.sh               # Network bootstrap (cryptogen & configtxgen)
├── caliper_test.sh          # Caliper benchmark runner
└── README.md                # Project documentation
```

---

## 🔧 Teardown

To stop all running Docker containers and clear channel/crypto artifacts:

```bash
./network.sh down
```

---

## 🛡️ License

Distributed under the Apache 2.0 License. See `LICENSE` for more information.
