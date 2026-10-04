# HealthClaimHardened security test matrix

Run with `./scripts/test.sh`. Every negative circuit case below expects an
unsatisfied witness. The recorded result is that the test observed a non-nil
constraint-solving error. Every public-input mutation expects Groth16
verification of the original proof to reject the changed public witness; each
listed case passed that rejection assertion.

## Adversarial witness mutations

| Test mutation | Expected / observed result | Security property |
|---|---|---|
| `wrong_challenge`: challenge 777 -> 778 | Unsatisfied / passed | Exact request challenge is included in context commitment. |
| `wrong_recipient`: recipient 12 -> 13 | Unsatisfied / passed | Recipient binding prevents recipient substitution. |
| `wrong_domain`: protocol domain -> 999 | Unsatisfied / passed | Circuit fixes the protocol identifier and domain-separates context. |
| `wrong_deployment_context`: deployment 9 -> 10 | Unsatisfied / passed | Deployment/channel context is bound. |
| `wrong_root_version`: root version 5 -> 6 | Unsatisfied / passed | Context is bound to a versioned root statement. |
| `wrong_policy_version`: policy version 3 -> 4 | Unsatisfied / passed | Context is bound to a versioned policy statement. |
| `wrong_Merkle_root`: public root changed | Unsatisfied / passed | Public root is bound to both context and authenticated path. |
| `wrong_registry_root_path`: Merkle sibling changed | Unsatisfied / passed | Merkle membership requires the path to reconstruct the root. |
| `wrong_policy_commitment`: commitment changed | Unsatisfied / passed | Policy commitment must recompute and match context. |
| `wrong_nullifier`: public nullifier changed | Unsatisfied / passed | Nullifier is derived from secret and path-derived record index, then context-bound. |
| `wrong_authority_public_key`: key coordinate changed | Unsatisfied / passed | Signature key and context key must match the proof statement. |
| `invalid_authority_signature`: signature scalar changed | Unsatisfied / passed | Issuer signature must verify over the record leaf. |
| `non-Boolean_Merkle_direction`: selector 0 -> 2 | Unsatisfied / passed | Merkle selector is constrained to Boolean. |
| `diagnosis_not_covered`: diagnosis 41 -> 42 | Unsatisfied / passed | Diagnosis must belong to the committed four-entry policy set. |
| `lab_below_minimum`: lab 6 -> 2 | Unsatisfied / passed | Lower lab bound is enforced. |
| `lab_above_maximum`: lab 6 -> 9 | Unsatisfied / passed | Upper lab bound is enforced. |
| `claim_above_coverage_ceiling`: claim 900 -> 1001 | Unsatisfied / passed | Claim cannot exceed record coverage. |
| `coverage_ceiling_exceeds_policy_maximum`: ceiling 1000 -> 1201 | Unsatisfied / passed | Record coverage cannot exceed policy maximum. |
| `lab_exceeds_64_bits` | Unsatisfied / passed | Lab value cannot wrap the field outside 64-bit range. |
| `claim_exceeds_64_bits` | Unsatisfied / passed | Claim cannot wrap the field outside 64-bit range. |
| `coverage_ceiling_exceeds_64_bits` | Unsatisfied / passed | Coverage ceiling cannot wrap the field outside 64-bit range. |
| `root_version_exceeds_64_bits` | Unsatisfied / passed | Root version has explicit width. |
| `policy_version_exceeds_64_bits` | Unsatisfied / passed | Policy version has explicit width. |
| `wrong_context_digest` | Unsatisfied / passed | Context digest must equal the canonical recomputation. |

## Groth16 public-input mutations

Each row mutates only the named public input in the verifier witness for the
original valid proof. Expected and observed result: verification rejects; all
13 subtests passed.

| Public input mutated | Security property demonstrated |
|---|---|
| RegistryRoot | Proof cannot be transplanted to another root. |
| RootVersion | Proof cannot be transplanted to another root version. |
| PolicyCommitment | Policy statement is proof-bound. |
| PolicyVersion | Proof cannot be transplanted to another policy version. |
| ClaimAmount | Claim amount is proof-bound. |
| AuthorityKeyX | Issuer key is proof-bound. |
| AuthorityKeyY | Issuer key is proof-bound. |
| Nullifier | Record nullifier is proof-bound. |
| ProtocolDomain | Domain value is proof-bound; circuit also fixes the protocol ID. |
| Challenge | Proof is bound to its exact challenge. |
| RecipientID | Proof is bound to the intended recipient. |
| DeploymentID | Proof is bound to its deployment/channel context. |
| ContextCommitment | The committed context statement is proof-bound. |

## Boundary and encoding tests

| Test | Expected / observed result | Security property |
|---|---|---|
| Self-selected authority key with a valid signature and recomputed context | Satisfiable / passed intentionally | Demonstrates the verifier must authenticate the authority key outside the circuit. |
| Negative/noncanonical challenge field element | Native helper rejects / passed | Context helper does not silently reduce malformed scalar inputs. |
| Policy version above 64 bits | Native helper rejects / passed | Context helper enforces version width before hashing. |
| Fixed fixture vector | Exact values match / passed | Native and circuit-facing statement values remain deterministic. |
| Public signal count | 13 / passed | Public/private interface stays explicit and regression-checked. |
