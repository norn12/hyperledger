# Z11 Fabric integration

## Scope and trust boundary

`HealthClaimHardened` proof generation and verification remain in the Go Gateway. Before submitting, the Gateway calls `VerifyHealthClaimProof`; a failed local check makes no Fabric call. Fabric records the proof bytes, SHA-256 identifier, the 13 public inputs, authority reference, verifier identity, state bindings, and audit metadata. Chaincode checks exact circuit/version, canonical field and version encodings, 64-bit claim amount, 164-byte proof encoding, proof hash, configured authority key, root/version, policy/version, challenge binding and expiry, and replay keys. It does **not** verify Groth16, recompute Poseidon, or establish proof/public-input consistency itself. `VerificationTrust=GATEWAY_VERIFIER_IDENTITY` explicitly records this trust model.

The private witness (diagnosis, laboratory value, patient secret, policy details, coverage ceiling, signature, Merkle siblings and directions) is not included in the Fabric submission or claim record. The proof and public inputs are on the channel ledger and visible to channel members unless a separate private data collection is introduced.

## Ledger controls

- HospitalMSP role `admin` manages prototype authority, accepted root, and policy registries.
- Authority registration validates canonical coordinates and rejects off-curve, identity, and non-prime-subgroup BN254 twisted-Edwards points (added in Z12 to close the Z8/Z11 trust-anchor observation).
- InsurerMSP roles `insurer` or `zkpVerifier` may issue an on-ledger challenge; only `zkpVerifier` may submit a proof.
- Challenges bind numeric recipient/deployment IDs and root/policy versions, expire after five minutes, and transition `ISSUED -> CONSUMED` with claim acceptance.
- Nullifier, challenge consumption, claim record, and audit record are written in one chaincode invocation. Fabric's transaction validation/MVCC handles competing writes to the same keys; the test stub does not simulate MVCC.
- Claim and audit reads are role-gated. `GetAccessLogs` is restricted to HospitalMSP admins. The legacy record reader still makes its ZKP decision outside chaincode; a nonempty legacy proof hash is not cryptographic verification.
- Existing network orderer is etcdraft/Raft, which is crash-fault tolerant, not Byzantine fault tolerant. Existing chaincode lifecycle/deploy scripts use `health` on `healthchannel`; inspect those scripts for the current channel and endorsement policy before deployment.

The enrolled verifier identity is `zkpVerifier` in InsurerMSP. Run the existing `gateway/cmd/enroll` enrollment command after configuring its environment. If an identity already exists in the wallet, re-enrollment/migration may be required to add the role attribute; do not assume an old wallet identity has it. The chaincode registry administrator is the HospitalMSP admin identity. The repository's existing chaincode deployment script is for initial installation. On an already committed network, use Fabric's normal version/sequence upgrade lifecycle after reviewing the current committed definition; do not redeploy sequence 1 over a live channel.

## Reproducible local validation

From repository root:

```sh
GOCACHE=/tmp/ztb-z11-chaincode-cache go -C chaincode test -count=1 -v ./...
GOCACHE=/tmp/ztb-z11-gateway-cache go -C gateway test -count=1 ./...
```

These are contract-logic and Gateway unit tests, not a live Fabric integration run. The chaincode mock does not simulate endorsement, ordering, MVCC, TLS, wallet enrollment, or commit events. The Gateway no-submit test verifies that a locally invalid proof cannot invoke its Fabric transport. A live run additionally requires the configured 2.4.9 network, deployed updated chaincode, funded identities, and live ledger registries. Docker was unavailable in the validation environment, so no live submission or Fabric latency is reported.

## Fabric transaction measurements

No endorsement, ordering, commit, throughput, or complete Gateway-to-Fabric latency was measured. The existing Z9 local ZKP measurements remain separate: HealthClaimHardened proof generation mean 73.575 ms; proof verification approximately 0.7 ms; proof size 164 bytes. These values are local cryptographic benchmarks, not Fabric/network measurements.
