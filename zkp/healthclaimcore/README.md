# HealthClaimCore v1

An isolated Go module implementing only the Core ZKP circuit. The parent
`zkp/` gnark 0.9.1 implementation remains the unchanged legacy baseline.

## Reproducible commands

Requires Go 1.25.8 (pinned in `go.mod`) and network access for the first module
download.

```sh
./scripts/setup.sh
./scripts/test.sh
./scripts/benchmark.sh
```

The test compiles the BN254 R1CS and prints its constraint and signal counts.
The benchmark excludes compile/setup and witness construction from the timed
sections. It reports proof generation and proof verification separately.
Groth16 setup is circuit-specific and uses gnark's local setup API; no ceremony
or production key-management workflow is provided here. `setup.sh` performs a
one-shot setup/prove/verify smoke path; generated keys remain in process memory.

## Relation

Public inputs: `RegistryRoot`, `PolicyCommitment`, `ClaimAmount`, authority
EdDSA public key `(x,y)`, and `Nullifier`.

Private witness: diagnosis, lab value, record policy ID, signed coverage ceiling,
patient secret, policy lab bounds and maximum claim, four covered diagnosis codes, EdDSA
signature, and an eight-level Merkle path (siblings and direction bits).

Core checks a domain-tagged Poseidon2 secret commitment and record leaf, an
authority EdDSA signature over that leaf, Merkle membership, Boolean path
directions, diagnosis membership in the four-entry policy set, 64-bit lab and
claim range discipline, `LabMin <= LabValue <= LabMax`,
`CoverageCeiling <= PolicyMaxClaim`, `ClaimAmount <= CoverageCeiling`, policy commitment consistency, and a domain-tagged nullifier
over the secret and the path-derived record index.

Poseidon2 is used because gnark 0.16.3 exposes a maintained BN254 circuit
gadget for it. It is a Poseidon-family variant; it is not bit-for-bit compatible
with unspecified Poseidon parameterizations in the source literature.

## Boundaries

This circuit does not implement challenge, recipient, deployment/domain,
root-version, expiry, treatment, or revocation binding. It does not implement
`HealthClaimHardened`, Gateway or Fabric integration, issuance, key ceremony,
or replay-state storage. A nullifier is deterministic and proof-bound, but
replay rejection requires an external authoritative registry to remember used
nullifiers. Diagnosis membership is intentionally fixed to four policy entries
in this version.

The circuit accepts the authority key, registry root, and policy commitment as
public inputs. A verifier must compare all three with trusted registered state;
otherwise a prover can choose its own signing key, root, and policy commitment.
Issuer-key registration must also reject the identity and require membership
in the intended prime-order subgroup; the in-circuit checks enforce curve
membership, while verifier-side registration remains the trust anchor.
The test suite includes a self-selected-key witness to make this trust-anchor
requirement explicit.

`testdata/core-v1-vectors.json` documents the fixed sample vector. It is a
synthetic test fixture and contains no real clinical data.
