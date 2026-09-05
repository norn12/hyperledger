# ZeroTrustBlock — Experimental Evaluation

This directory defines the experimental evaluation of **ZeroTrustBlock**, a privacy-preserving healthcare data-sharing platform built with Hyperledger Fabric and Groth16 zero-knowledge proofs.

The evaluation is divided into five complementary experiments:

| Experiment | Evaluation | Primary purpose |
|---|---|---|
| **A** | Groth16 cryptographic cost | Measure proof-generation and verification cost |
| **B** | Fabric baseline | Measure Fabric performance without real ZKP generation |
| **C** | Privacy-enabled end-to-end performance | Measure the complete ZKP + Gateway + Fabric path |
| **D** | Fabric scalability | Evaluate throughput, latency, and success rate under increasing load |
| **E** | Zero-Trust security matrix | Verify MSP, role, ZKP, and fail-closed access control |

> **Important:** Experimental results must be reported together with the exact software versions, hardware configuration, worker count, transaction count, offered load, network topology, and configuration used for the run. No measured value should be presented as a universal Hyperledger Fabric limit.

---

## 1. Experimental Objectives

### RQ1 — Cryptographic overhead

**What computational overhead does the Groth16 privacy mechanism introduce?**

Experiment A isolates the ZKP engine from Fabric and measures proof-generation and proof-verification costs.

### RQ2 — Fabric baseline performance

**How does the underlying Fabric network perform without real ZKP generation?**

Experiment B provides a baseline using Fabric transactions without performing Groth16 proof generation.

### RQ3 — End-to-end privacy cost

**What is the performance of the complete privacy-enabled healthcare transaction path?**

Experiment C measures:

```text
Client
  ↓
Go Gateway
  ↓
Groth16 proof generation
  ↓
Proof verification
  ↓
Proof hashing
  ↓
Fabric transaction submission
  ↓
Multi-organization endorsement
  ↓
Raft ordering
  ↓
Block commit
```

### RQ4 — Scalability

**How does the Fabric deployment behave as offered transaction load increases?**

Experiment D progressively increases offered TPS and observes achieved throughput, latency, and transaction success rate.

### RQ5 — Zero-Trust security

**Does the system correctly enforce identity-, role-, organization-, and ZKP-based access decisions?**

Experiment E evaluates these security properties using Fabric identities and access policies.

---

# 2. Experiment A — Groth16 Cryptographic Cost

## Objective

Measure the computational cost of the `AgeRangeCircuit` independently of Fabric network latency.

The benchmark uses Groth16 over the BN254 curve.

## Execution

```bash
cd benchmark
go run ./cmd/zkp 100
```

The experiment writes:

```text
benchmark/zkp-results.json
```

## Measurements

The benchmark records:

- Setup time
- Number of samples
- Valid proofs
- Failed proofs
- Average proving time
- P50 proving time
- P95 proving time
- P99 proving time
- Average verification time
- P50 verification time
- P95 verification time
- P99 verification time
- Average proof size
- Total benchmark duration

A warm-up proof is executed before measured samples so the initial proving/verification path is not mixed directly into the reported samples.

## Interpretation

Experiment A represents the **cryptographic component** of the system. It should be used to establish ZKP generation cost, ZKP verification cost, and proof size. It should not be interpreted as Fabric transaction latency.

---

# 3. Experiment B — Fabric Baseline

## Objective

Measure the performance of the Fabric network without real Groth16 proof generation.

The workload invokes:

```text
CreateHealthRecord
```

using Hyperledger Caliper.

The workload intentionally submits an empty ZKP artifact so Fabric endorsement, ordering, validation, and commit performance can be measured independently of Groth16 proving.

## Execution

```bash
cd caliper
npm install
npm run baseline
```

Equivalent benchmark command:

```bash
npm run benchmark
```

## Current Configuration

The current Caliper configuration uses:

```text
Workers: 5
```

Measured offered loads:

```text
100 TPS
250 TPS
500 TPS
1000 TPS
1500 TPS
2000 TPS
2500 TPS
```

Each measured round currently contains 1000 transactions, preceded by a warm-up round.

## Metrics

For each load level, record:

- Offered TPS
- Achieved TPS
- Transaction success rate
- Transaction failure count
- Latency
- Resource utilization where available

## Purpose

Experiment B establishes the **Fabric-only baseline** against which the privacy-enabled workload can be compared.

It deliberately does not claim to represent real Groth16-enabled healthcare transactions.

---

# 4. Experiment C — Privacy-Enabled End-to-End Performance

## Objective

Measure the complete ZeroTrustBlock transaction path using real ZKP generation.

Unlike Experiment B, this experiment uses the Go Gateway and the actual ZKP service.

## Execution

Ensure that the Fabric network is running and the chaincode is deployed.

```bash
cd benchmark
go run ./cmd/real
```

## Current Benchmark Configuration

The current implementation uses:

```text
Concurrent transactions: 500
Total transactions:       5000
```

The benchmark submits `WriteHealthRecord` transactions through the Gateway. For each transaction it creates transaction data, generates an age-range Groth16 proof, performs the Gateway ZKP pipeline, submits the health-record transaction to Fabric, and records the result and latency.

## Metrics

Record:

- Successful transactions
- Failed transactions
- Total duration
- Average transaction latency
- Achieved throughput in TPS
- ZKP proving/verification timing where exposed by Gateway metrics
- Proof size where exposed by Gateway metrics

## Comparison

The principal comparison is:

```text
Experiment B: Fabric baseline
        vs.
Experiment C: Fabric + real ZKP pipeline
```

This allows privacy overhead to be evaluated experimentally rather than assumed.

---

# 5. Experiment D — Fabric Scalability

## Objective

Determine how the deployed Fabric network behaves under progressively increasing transaction load.

This is a **load-response study**, not a claim of a universal Fabric throughput limit.

## Offered Loads

The current configuration tests:

```text
100 TPS
250 TPS
500 TPS
1000 TPS
1500 TPS
2000 TPS
2500 TPS
```

with 5 Caliper workers and 1000 transactions per measured round.

## Required Measurements

| Offered TPS | Achieved TPS | Latency | Success Rate |
|---:|---:|---:|---:|
| 100 | — | — | — |
| 250 | — | — | — |
| 500 | — | — | — |
| 1000 | — | — | — |
| 1500 | — | — | — |
| 2000 | — | — | — |
| 2500 | — | — | — |

Populate these values only from actual Caliper runs.

## Saturation Point

Identify saturation experimentally. A typical saturation pattern is:

```text
Increasing offered load
        ↓
Increasing achieved throughput
        ↓
Throughput growth slows
        ↓
Latency rises sharply
        ↓
Success rate may begin to decrease
```

Do not predetermine the saturation point.

## Recommended Figures

### Figure D1 — Offered vs achieved throughput

```text
X-axis: Offered TPS
Y-axis: Achieved TPS
```

### Figure D2 — Offered load vs latency

```text
X-axis: Offered TPS
Y-axis: Transaction latency
```

### Figure D3 — Offered load vs success rate

```text
X-axis: Offered TPS
Y-axis: Success rate (%)
```

---

# 6. Experiment E — Zero-Trust Security Matrix

## Objective

Verify that access to healthcare records is controlled using:

- Fabric MSP identity
- Certificate role attribute
- ZKP artifact
- Access policy
- Fail-closed behavior

## Security Policy

The experiment creates a record with:

```json
{
  "requireZKP": true,
  "allowedMSPs": ["HospitalMSP"],
  "allowedRoles": ["doctor"]
}
```

The intended successful access condition is:

```text
HospitalMSP
     +
doctor role
     +
non-empty ZKP artifact
     ↓
ALLOW
```

## Create Test Record

```bash
cd gateway/cmd/security
go run . create
```

Save the printed `RECORD_ID`.

## Test 1 — Authorized Doctor

```bash
ZT_IDENTITY=doctor go run . read <RECORD_ID>
```

Expected:

```text
RESULT=ALLOW
IDENTITY=doctor
```

The `doctor` identity is provisioned with `HospitalMSP` and the `doctor` role, and the read operation generates a real age-range Groth16 proof.

## Test 2 — Hospital Administrator

The `appAdmin` identity is provisioned with the `admin` role rather than `doctor`.

```bash
ZT_IDENTITY=appAdmin go run . read <RECORD_ID>
```

Expected:

```text
RESULT=DENY
```

This demonstrates that Hospital organization membership alone is insufficient when the policy additionally requires the `doctor` role.

## Test 3 — Insurer

```bash
ZT_IDENTITY=insurer go run . read <RECORD_ID>
```

Expected:

```text
RESULT=DENY
```

because `InsurerMSP` is not included in `allowedMSPs`.

## Security Matrix

| Identity | MSP | Role | ZKP | Expected |
|---|---|---|---|---|
| `doctor` | HospitalMSP | doctor | valid | **ALLOW** |
| `appAdmin` | HospitalMSP | admin | valid | **DENY** |
| `insurer` | InsurerMSP | insurer | valid | **DENY** |

## Fail-Closed Behavior

The chaincode is designed so access is denied when required security information is invalid or unavailable:

```text
Missing/invalid policy → DENY
Unauthorized MSP       → DENY
Missing role           → DENY
Unauthorized role      → DENY
Missing required ZKP   → DENY
```

This demonstrates that a valid Fabric identity alone does not automatically grant access.

---

# 7. Experimental Execution Order

For a clean evaluation:

```text
Network deployment
       ↓
Experiment A — ZKP cost
       ↓
Experiment B — Fabric baseline
       ↓
Experiment C — Privacy-enabled E2E
       ↓
Experiment D — Scalability
       ↓
Experiment E — Security matrix
```

Experiments A and B establish isolated baselines. Experiment C combines the privacy mechanism with Fabric. Experiment D evaluates network behavior under load. Experiment E evaluates Zero-Trust authorization.

---

# 8. Reproducibility Requirements

Every thesis result should record:

### Hardware

```text
CPU:
RAM:
GPU:
Storage:
Operating system:
```

### Software

```text
Hyperledger Fabric:
Fabric CA:
Docker:
Docker Compose:
Go:
Node.js:
Hyperledger Caliper:
gnark:
```

### Fabric Topology

```text
Organizations: 2
Hospital peers: 2
Insurer peers: 2
Raft orderers: 3
Channel: healthchannel
Chaincode: health
Endorsement policy:
AND('HospitalMSP.member','InsurerMSP.member')
```

### Benchmark Configuration

Record:

```text
Caliper workers
Transaction count
Offered TPS
Batch timeout
Block parameters
Concurrency
Network configuration
Chaincode version
```

### Results

For performance experiments, preserve the complete measurements needed to reproduce the result:

```text
Throughput
Latency
Success rate
Transaction count
Offered load
Configuration
```

---

# 9. Interpretation Guidelines

These experiments measure **this ZeroTrustBlock implementation under the specified test configuration**.

Do not write:

```text
Hyperledger Fabric can process X TPS.
```

Prefer:

```text
Under the evaluated ZeroTrustBlock configuration, the network achieved X TPS at Y offered TPS with Z% successful transactions.
```

Similarly, do not claim that ZeroTrustBlock is linearly scalable unless the measured results demonstrate approximately proportional throughput growth over the evaluated range.

Interpret scalability from the observed relationship between:

```text
offered load
      ↓
achieved throughput
      ↓
latency
      ↓
success rate
```

---

# 10. Evidence Status

The repository contains implementation support for five experimental categories:

- **A:** Groth16 benchmark implementation
- **B:** Caliper baseline workload and load configuration
- **C:** Real Go/Fabric benchmark
- **D:** Caliper multi-load scalability configuration
- **E:** Security test runner and enrolled role identities

### Results policy

A result should be described as **measured** only when it corresponds to an actual run of the current repository configuration.

Previously documented performance numbers should not automatically be reused if the worker count, configuration, topology, or software version has changed.

---

# 11. Quick Reference

```bash
# Experiment A — ZKP
cd benchmark
go run ./cmd/zkp 100

# Experiment B — Fabric baseline
cd caliper
npm install
npm run baseline

# Experiment C — Real privacy-enabled benchmark
cd benchmark
go run ./cmd/real

# Experiment D — Scalability
cd caliper
npm run benchmark

# Experiment E — Security matrix
cd gateway/cmd/security
go run . create

ZT_IDENTITY=doctor go run . read <RECORD_ID>
ZT_IDENTITY=appAdmin go run . read <RECORD_ID>
ZT_IDENTITY=insurer go run . read <RECORD_ID>
```

---

## Experimental Principle

ZeroTrustBlock is evaluated along three independent dimensions:

```text
                 ZeroTrustBlock
                      │
        ┌─────────────┼─────────────┐
        │             │             │
     Privacy       Performance    Security
        │             │             │
        A             B             E
        │             │             │
        C             D             │
        │             │             │
     Groth16       Fabric        Access
     overhead      scaling       control
```

Together, the experiments evaluate:

1. **what the privacy mechanism costs,**
2. **how the underlying Fabric network performs,**
3. **how the complete privacy-enabled path behaves,**
4. **how performance changes under increasing load,**
5. **whether Zero-Trust authorization is correctly enforced.**
