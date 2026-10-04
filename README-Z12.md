# Z12 end-to-end evaluation

Z12 evaluates the existing HealthClaimHardened + Gateway + Fabric flow. It does not modify HealthClaimCore or HealthClaimHardened. The Gateway cryptographically verifies the Groth16 proof before Fabric submission. Chaincode enforces identity/role authorization, trusted public-state bindings, challenge lifecycle, nullifier uniqueness, state transitions, and audit recording; it does not verify Groth16 or recompute Poseidon.

## Configuration observed in the repository

- Organizations: HospitalMSP and InsurerMSP.
- Peers: four total, two per organization.
- Orderers: three `etcdraft` nodes; Raft is crash-fault tolerant (CFT), not Byzantine fault tolerant.
- Channel and contract: `healthchannel`, chaincode `health`.
- `network.sh` declares Fabric 2.4.9 and CA 1.5.7; compose tags peers/orderers as Fabric 2.4.
- `deploy.sh` declares chaincode version 1.0, sequence 1, with `AND('HospitalMSP.member','InsurerMSP.member')`. Its TLS flag is enabled and the Gateway profile uses TLS endpoints.
- Expected registry identity: HospitalMSP `appAdmin` with `role=admin`. Expected proof submitter: InsurerMSP `zkpVerifier` with `role=zkpVerifier`.

These are repository declarations, not proof of live ledger state. The existing `deploy.sh` creates the channel and commits sequence 1. Do not rerun it against an existing committed channel. Use the correct Fabric lifecycle upgrade sequence after querying the live definition and reviewing the deployment procedure.

## Prerequisites for live tests

A Docker daemon accessible to the current user, Docker Compose, Fabric 2.4.9 peer CLI, generated TLS/crypto materials, a reachable `healthchannel`, the updated Z11/Z12 chaincode installed and committed, and provisioned identities with the expected role attributes. The recorded host has standalone Docker Compose 1.29.2, but the Docker daemon socket is inaccessible. The tests write permanent claim, challenge, root, nullifier, and audit state. Use a disposable evaluation network/channel; scripts do not reset or deploy the network.

The tagged live test defaults to `gateway/connection-profile-abs.yaml`, `gateway/wallet`, `healthchannel`, `health`, `appAdmin`, and `zkpVerifier`. Override with:

- `ZT_Z12_CONNECTION_PROFILE`
- `ZT_Z12_WALLET_DIR`
- `ZT_Z12_CHANNEL`
- `ZT_Z12_CHAINCODE`
- `ZT_Z12_HOSPITAL_ADMIN_IDENTITY`
- `ZT_Z12_VERIFIER_IDENTITY`

The verifier enrollment source adds the `role=zkpVerifier` attribute; a pre-existing wallet identity may not have it. Confirm wallet enrollment and attribute before testing. Never print wallet contents or private keys into results.

## Reproduction

From repository root:

```sh
scripts/z12/collect-environment.sh
scripts/z12/network-preflight.sh
scripts/z12/run-local-validation.sh
scripts/z12/run-local-benchmarks.sh
scripts/z12/run-live-e2e.sh
scripts/z12/run-live-negative.sh
ZT_Z12_SEQUENTIAL_N=5 scripts/z12/run-live-performance.sh
scripts/z12/collect-results.sh
```

`run-local-validation.sh` runs the HealthClaimHardened suite, Gateway suite, chaincode contract tests, and compiles the gated live tests. `run-local-benchmarks.sh` runs 10 independent samples with 10 timed operations per sample for the ZKP prover/verifier and Gateway-local pipeline. P95 is nearest-rank (the maximum with N=10); P99 is not reported for N<100. These local numbers do not include Fabric.

The live scripts first run a read-only Docker/network preflight. They do not run `network.sh`, `deploy.sh`, or any reset script. If the Docker daemon is inaccessible they write `Not measured - live Fabric network unavailable in the evaluation environment.` and exit nonzero. The gated tests use `-tags=z12integration` and require `ZT_Z12_LIVE=1`:

- `TestZ12LiveValidClaimAndReplay` submits a signed, membership-proven claim, waits for the Fabric commit event, queries claim/audit/challenge/nullifier state, checks no witness fields were serialized, then checks local invalid-proof fail-closed and a sequential duplicate-nullifier rejection.
- `TestZ12LiveSequentialClaimsAndDuplicateNullifierRace` submits independent sequential claims and creates a genuinely concurrent pair of valid submissions with the same nullifier and different claim IDs; exactly one should commit.

These live tests are compiled locally but not executed because Docker socket access is denied. The local chaincode stub does not simulate endorsement, MVCC, orderer behavior, or a ledger commit.

## Result artifacts

Raw observations are in `output/z12/`: `environment.txt`, `network-preflight.txt`, `security-results.txt`, separate suite outputs, `zkp-benchmarks.txt`, `gateway-benchmarks.txt`, `performance-results.txt`, `e2e-results.txt`, `security-results-live.txt`, `live-performance-results.txt`, `storage-results.txt`, and a SHA-256 manifest. Local JSON byte sizes are serializer measurements using a deterministic test fixture with a 164-byte placeholder proof; they are not a live ledger observation.

## Current environment limitation

In the recorded Z12 environment, Docker client 29.1.3 was present, but `docker info` failed with permission denied for `/var/run/docker.sock`; Docker Compose was unavailable. Consequently network health, actual identities, committed lifecycle definition, channel/chaincode state, endorsement/order/commit latency, full E2E, sequential live claims, and a concurrent MVCC race were not measured. IPFS is not part of the validated HealthClaimHardened claim path and was not included in Z12 latency measurements.
