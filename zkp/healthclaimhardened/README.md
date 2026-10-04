# HealthClaimHardened v1

An isolated Go module for the Z7 hardened Groth16 relation. It copies the
Core-v1 cryptographic gadgets into a separate package and composes them with
request, deployment, root-version, and policy-version binding. The frozen
`../healthclaimcore/` module is not imported or modified, so its circuit and
vectors remain an independent baseline.

## Reproducible commands

Requires the Go toolchain pinned in `go.mod` and module access on first setup.

```sh
./scripts/setup.sh
./scripts/test.sh
./scripts/benchmark.sh
```

The benchmark times proof generation and verification separately after compile,
setup, and witness preparation. It uses Groth16 on BN254 and reports circuit
constraints, latency, allocations, and bytes/op. The setup script performs a
local in-memory setup/prove/verify smoke run; no production key ceremony is
implemented.

## Security goal and exact relation

The circuit proves the Core predicates: domain-separated Poseidon2 secret
commitment and record leaf; authority EdDSA signature over the leaf; 8-level
Poseidon2 Merkle membership with Boolean directions; fixed four-entry diagnosis
membership; explicit 64-bit range constraints; lab bounds; coverage and policy
maximum checks; recomputed policy commitment; and a record-index-bound nullifier.

It additionally enforces `ProtocolDomain == 202610041` and recomputes:

```text
ContextCommitment = Poseidon2(
  tag_context=106,
  ProtocolDomain, Challenge, RecipientID, DeploymentID,
  PolicyVersion, RootVersion, PolicyCommitment, RegistryRoot,
  AuthorityKeyX, AuthorityKeyY, Nullifier, ClaimAmount
)
```

Every item is a separate canonical BN254 scalar field input in this fixed
order. There is no string concatenation, implicit delimiter, or variable-length
encoding. Context identifiers are scalar IDs assigned/derived by the caller and
must be canonical (`0 <= value < BN254 scalar modulus`). `ContextDigest` checks
canonical values and 64-bit root/policy versions. Existing Core tags 101-105
remain for secret, record, policy, Merkle, and nullifier hashes; tag 106 is for
the context digest.

The policy commitment continues to cover PolicyID, lab minimum and maximum,
maximum claim, and the ordered fixed-size covered-diagnosis set. PolicyVersion
is separately bound by the context commitment.

## Inputs and trust boundaries

**Public inputs (13):** RegistryRoot, RootVersion, PolicyCommitment,
PolicyVersion, ClaimAmount, AuthorityKeyX, AuthorityKeyY, Nullifier,
ProtocolDomain, Challenge, RecipientID, DeploymentID, ContextCommitment.

**Private witness (31):** Diagnosis, LabValue, PolicyID, CoverageCeiling,
PatientSecret, LabMin, LabMax, PolicyMaxClaim, four CoveredDiagnosis values,
signature `(R,S)`, eight Merkle siblings, and eight Merkle direction bits.

Diagnosis, lab values, patient secret, signature, and Merkle path remain
private. ClaimAmount and statement/context fields are public. Challenge,
recipient, deployment, policy/root versions, root, policy commitment, authority
key, and claim amount must be supplied by the verifier/request and compared to
its expected context; they are not trusted merely because the proof contains
them.

The trusted registry/verifier boundary must authenticate the issuer key and
status, check that `(RootVersion, RegistryRoot)` is an accepted registry entry,
check `(PolicyVersion, PolicyCommitment)` against authoritative policy state,
check deployment/channel and recipient IDs, and compare the challenge to one it
issued. Circuit satisfiability cannot establish any of those external facts.
The circuit checks that the supplied key and signature points satisfy the
signature relation; it does not certify issuer registration. Key registration
must reject the identity and enforce the intended prime-order subgroup as well
as authority/status policy.

## Freshness, expiry, and replay

The proof is bound to the exact challenge field value. This establishes
statement binding, not challenge freshness. The verifier must create an
unpredictable challenge, enforce a short acceptance window, and mark it used
(or otherwise reject reuse). The verifier/Fabric boundary must decide whether
root and policy versions are current/accepted and whether issuer status is
valid. No wall-clock timestamp or expiry check is implemented in-circuit.

The nullifier remains `Poseidon2(tag_nullifier=105, PatientSecret,
RecordIndex)`, where RecordIndex is derived from the authenticated Merkle
direction bits. The nullifier is included in the context digest, but is stable
for that record across requests. A nullifier is an identifier, not replay
prevention: external UsedNullifiers state must reject a second claim.

## Tests and known limitations

Tests cover valid proof witnesses; challenge, recipient, domain, deployment,
root-version, policy-version and context-digest mutations; wrong root, policy,
nullifier, or issuer key; invalid signature; malformed Merkle direction;
diagnosis, lab, claim and coverage violations; 64-bit overflow; canonical input
validation; and Groth16 verification rejection after mutation of every public
input. A self-selected-authority-key test demonstrates the external trust-anchor
requirement.

See [`SECURITY-TEST-MATRIX.md`](SECURITY-TEST-MATRIX.md) for each mutation, its
expected and observed result, and the security property demonstrated.

## Z6 comparison benchmark

Measured on the same host and with 10 benchmark iterations (`-benchtime=10x`):
Linux amd64, AMD Ryzen 7 PRO 8840HS, Go 1.25.8, gnark 0.16.3, gnark-crypto
0.21.0. Setup and witness preparation are excluded from timed regions. These
are local measurements, not paper-reported figures.

| Metric | Core v1 (Z6) | Hardened v1 (Z7) | Change |
|---|---:|---:|---:|
| R1CS constraints | 19,657 | 22,021 | +2,364 (+12.0%) |
| Public variables | 6 | 13 | +7 |
| Secret variables | 31 | 31 | unchanged |
| Proof generation | 64.80 ms/op | 69.72 ms/op | +4.92 ms (+7.6%) |
| Generation bytes/op | 21,163,069 | 21,697,900 | +534,831 |
| Generation allocations/op | 2,644 | 2,635 | -9 |
| Proof verification | 0.635 ms/op | 0.638 ms/op | +0.003 ms (+0.5%) |
| Verification bytes/op | 30,384 | 33,130 | +2,746 |
| Verification allocations/op | 165 | 183 | +18 |
| Serialized proof size | Not measured in Z6 | 164 bytes | Hardened measured with gnark `Proof.WriteTo` |

The Z6 figures are the recorded Z6 baseline. Z6 proof size was not measured,
so no direct proof-size comparison is claimed. Groth16 proof size remains fixed
for this circuit's proof format; verification-key public-input structure grows
with the expanded public interface.

Not implemented: Gateway, Fabric, IPFS integration changes, federated learning,
production deployment, production key ceremony, trusted-registry lookup,
challenge issuance/storage, expiry enforcement, or used-nullifier storage.
The four-entry diagnosis policy and depth-eight Merkle path are fixed circuit
parameters. Numeric recipient/deployment/domain IDs need a canonical mapping
in any later application integration.
