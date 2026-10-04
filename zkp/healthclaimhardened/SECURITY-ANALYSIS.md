# Z8 security analysis: HealthClaimHardened v1

## Scope and decision

This analysis evaluates the existing Z7 HealthClaimHardened relation without
changing its circuit semantics. The test suite includes proof-level mutations
for every public input, mutations of every private witness field, malformed
and boundary values, deterministic vectors, and tests that expose external
trust and replay obligations.

**Decision: PASS WITH OBSERVATIONS.** The implemented relation rejects the
tested false claims and binds all 13 public inputs. Observations remain at the
trust boundary: the circuit accepts identity and order-2 torsion authority
points; therefore the verifier must authenticate keys and enforce intended
subgroup membership. Challenge freshness, root/policy trust, key setup,
revocation, expiry, and replay storage also remain external.

## Architecture and relation under review

The isolated module uses Groth16 over BN254, Poseidon2 commitments, EdDSA with
MiMC challenge, a fixed depth-8 Poseidon2 Merkle path, a four-entry diagnosis
set, explicit 64-bit encodings for bounded fields/versions, lab interval
checks, coverage checks, policy commitment verification, and a deterministic
record-index nullifier. It recomputes a context commitment over the protocol
domain, challenge, recipient, deployment, policy/root versions, policy/root
commitments, authority key, nullifier, and claim amount.

The public inputs are RegistryRoot, RootVersion, PolicyCommitment,
PolicyVersion, ClaimAmount, AuthorityKeyX, AuthorityKeyY, Nullifier,
ProtocolDomain, Challenge, RecipientID, DeploymentID, ContextCommitment.
The private witness contains Diagnosis, LabValue, PolicyID, CoverageCeiling,
PatientSecret, LabMin, LabMax, PolicyMaxClaim, four CoveredDiagnosis values,
EdDSA signature R and S, eight Merkle siblings, and eight direction bits.

## Threat model and trust boundaries

| Actor/component | Capability or assumption | Circuit guarantee / boundary |
|---|---|---|
| Malicious claimant/prover | Knows and may alter private witness; may choose proof attempt. | Cannot satisfy tested false record/policy/range/path mutations without breaking the relation or underlying cryptography. Zero knowledge hides witness under Groth16 assumptions. |
| Malicious verifier/client | May substitute any public input. | A proof verifies only against its original statement: proof verification rejected mutation of each of the 13 public inputs. The caller must compare them to expected request state. |
| Dishonest/compromised authority | Can sign false records or disclose keys. | The relation authenticates a record under the supplied key; it cannot decide whether the issuer is honest, authorized, current, or non-revoked. |
| Untrusted ledger/storage | May expose metadata, replay data, or return false roots/policies. | Merkle membership authenticates only relative to the supplied root. Trusted registry and policy state must authenticate root/commitment and versions. |
| Network attacker | Can replay/alter requests, but is assumed unable to break cryptography. | Public statement binding detects altered proof inputs; freshness and replay rejection need verifier state and transport/application controls. |
| Trusted authority-key registry | Must authenticate issuer, status, curve/subgroup and key identity. | External trust anchor; the circuit accepts self-selected and certain exceptional points. |
| Trusted root and policy registries | Must provide accepted root/version and policy commitment/version. | External trust anchors; circuit checks internal consistency only. |
| Verifier and challenge generator | Must validate expected context and issue unpredictable fresh challenges. | External trusted components. Challenge inclusion does not prove freshness. |
| UsedNullifiers state | Must atomically reject reused nullifiers. | External replay state; circuit derives a deterministic identifier only. |
| Groth16 setup/key custody | Must ensure proving/verification keys correspond to intended circuit and setup assumptions. | No production ceremony or key governance is implemented. |

## Security property and test results

See [`SECURITY-TEST-MATRIX.md`](SECURITY-TEST-MATRIX.md) for the full input-to-
test mapping, expected and observed result, and conclusions. The critical
findings are:

* Every one of 13 public-input mutations rejects the original proof at
  Groth16 verification.
* All 31 private-witness-field mutations are rejected by constraint solving.
  These fields are bound through the record hash/signature, policy commitment
  and predicates, Merkle root, direction-derived index, or nullifier.
* Invalid signature, wrong authority key, wrong root/path, non-Boolean path
  selector, uncovered diagnosis, out-of-range lab, excessive claim/coverage,
  malformed context, and over-width values are rejected in existing/new tests.
* The self-selected authority key test and the newly added exceptional-point
  tests show that issuer authorization, identity-point rejection, and
  subgroup validation are verifier/registry obligations. The identity and
  order-2 torsion proofs are accepted by the circuit; this is explicitly
  recorded rather than hidden.
* A valid unchanged proof verifies twice. Repeated verification is possible;
  freshness/replay resistance is not an in-circuit property.

### Under-constrainedness review

The regression matrix changes each private variable independently. Diagnosis,
lab, policy ID, coverage ceiling, patient secret, lab bounds, maximum claim,
all four covered diagnoses, signature coordinates/scalar, all eight siblings,
and all eight direction bits each cause the mutated witness to fail. The
Merkle direction bits are Boolean-constrained and determine both branch order
and record index. The nullifier changes with secret/index and is public and
context-bound. The test demonstrates single-coordinate sensitivity for the
fixed deterministic fixture; it is not a formal proof against all possible
collisions or coordinated witness replacements, which rely on cryptographic
assumptions and the circuit relation.

The nullifier stability test changes challenge and recipient while retaining
the same record and confirms the same nullifier with a different context
digest. Thus a record may be recognized consistently across requests, but
actual uniqueness enforcement requires external UsedNullifiers state.

### Boundary and encoding analysis

Valid tests cover LabValue equal to either endpoint, ClaimAmount equal to
CoverageCeiling, CoverageCeiling equal to PolicyMaxClaim, every one of the
four allowed diagnosis values, zero/small values, and maximum 64-bit values.
Negative and over-64-bit adversarial cases are rejected across applicable
fields. Native context helpers reject noncanonical field values and versions
that exceed 64 bits. The implemented checks cover these tested boundaries;
expiry and temporal freshness are not encoded in the relation.

## Public-input tampering and context binding

The proof-level test alters RegistryRoot, RootVersion, PolicyCommitment,
PolicyVersion, ClaimAmount, both authority key coordinates, Nullifier,
ProtocolDomain, Challenge, RecipientID, DeploymentID, and ContextCommitment,
one at a time. Each original proof is rejected against the changed public
witness. This establishes statement binding, not correctness of an external
mapping from numeric IDs to real identities/deployments or trusted state.

## Nullifier, replay, and external limitations

The nullifier is Poseidon2 over the patient secret and direction-derived
record index. It is deterministic and included in context. The circuit does
not maintain a spent-nullifier set. A verifier must issue unpredictable
challenges, enforce their freshness/use window, atomically record accepted
challenges/nullifiers, and reject duplicates. Expiry and revocation are not
implemented. Root and policy currency, authority registration/status,
recipient and deployment mapping, and authority subgroup checks are external.

The Merkle depth (8) and diagnosis set size (4) are fixed prototype
parameters. Numeric protocol/recipient/deployment identifiers need canonical
application-level mappings. `ProtocolDomain = 202610041` is enforced as a
constant, but is opaque/date-like; a future version should use a documented
stable protocol identifier mapped canonically to a field constant. Changing
the current constant in place would change the circuit relation and keys.

The deterministic record nullifier is stable only while the registry
preserves a stable record index for the same record. Rebuilding/reindexing the
tree may change that index and therefore the nullifier; registry lifecycle
rules must define this behavior.

No production trusted setup/key ceremony, production issuer/root/policy
registry, replay database, revocation service, or expiry enforcement is
implemented. Those remain explicit system-level assumptions and work items.

## Test execution

On the recorded Linux amd64 host, using Go 1.25.8, gnark 0.16.3, and
gnark-crypto 0.21.0, `go mod verify` succeeded and the complete hardened test
suite passed with `GOCACHE=/tmp/healthclaim-hardened-cache go test -count=1
-v ./...`. The suite reported 22,021 constraints, 13 public variables, 31
secret variables, and a 164-byte serialized proof in its corresponding
checks. The Z7 benchmark run is reported separately in the Z9 evaluation.
