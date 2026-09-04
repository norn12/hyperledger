# ZeroTrustBlock Thesis Experiments

This branch separates the evaluation into six experiments.

## A — Groth16 cryptographic cost

Measures the AgeRangeCircuit proving and verification cost without Fabric network latency.

```bash
cd benchmark
 go run ./cmd/zkp 100
```

Output is also written to `benchmark/zkp-results.json`.

Metrics: setup time, average/p50/p95/p99 proving time, average/p50/p95/p99 verification time, proof size, valid/failed proofs.

## B — Fabric baseline

Runs Caliper against `CreateHealthRecord` without real Groth16 proof generation.

```bash
cd caliper
npm install
npm run baseline
```

The workload targets the deployed `health` chaincode and uses the complete two-organization connection profile so the chaincode's multi-org endorsement policy can be exercised.

## C — Privacy-enabled end-to-end performance

Run the real Go benchmark after the Fabric network is up and chaincode is deployed:

```bash
cd benchmark
go run ./cmd/real
```

This measures the complete path: Groth16 proving + verification + hashing + Fabric submission/commit. The benchmark records overall throughput and latency; the Gateway also records ZKP proving/verification time and proof size.

## D — Fabric scalability

The Caliper configuration runs measured rounds at 100, 250, 500, 1000, 1500, 2000 and 2500 offered TPS.

Use Caliper's round-by-round report to plot:

- offered TPS vs achieved TPS
- offered TPS vs latency
- success rate vs load

The saturation point is the region where increasing offered load no longer produces a proportional increase in achieved throughput and latency begins to rise sharply.

## E — Zero Trust security matrix

Create a test record with a policy requiring:

- HospitalMSP
- doctor role
- non-empty ZKP artifact

Create:

```bash
cd gateway/cmd/security
go run . create
```

Copy the printed `RECORD_ID`, then run the same read test with different identities:

```bash
ZT_IDENTITY=appAdmin go run . read <RECORD_ID>
ZT_IDENTITY=<hospital-non-doctor> go run . read <RECORD_ID>
ZT_IDENTITY=<insurer-identity> go run . read <RECORD_ID>
```

Expected outcomes depend on the certificate attributes configured in the wallet, but the policy should demonstrate:

- valid HospitalMSP + doctor + ZKP -> ALLOW
- HospitalMSP without doctor role -> DENY
- InsurerMSP against Hospital-only policy -> DENY

The chaincode fails closed when a required role attribute is missing/invalid or the MSP is not allowed.

## F — Consent revocation and auditability

Run:

```bash
cd gateway/cmd/test_gateway
go run .
```

The test performs:

1. Create record
2. Read while consent is active -> ALLOW
3. Revoke consent -> COMMITTED
4. Read after revocation -> DENY
5. Query `GetAccessLogs` -> audit entries

The read operation uses a Fabric transaction rather than a query so the access decision can be persisted as an audit event.

## Reporting rules

Do not present any result as a universal Fabric limit. Report the exact configuration, hardware, worker count, offered load, transaction count, and software versions used for each run.

Caliper is the Fabric baseline/load tool. The Go benchmark is the privacy-enabled end-to-end benchmark. The Caliper workload deliberately does not claim to generate or verify a real Groth16 proof.
