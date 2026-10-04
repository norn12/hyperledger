# Z10 Gateway HealthClaimHardened integration

`HealthClaimGateway` is a Fabric-independent API inside the existing Gateway Go
module. Construct it with explicit authority, root, policy, identifier,
challenge, and nullifier providers. The existing `ZeroTrustGateway` Fabric
methods and legacy age-range proof path remain unchanged; this Z10 path does not
submit transactions.

## Flow

1. Register canonical recipient/deployment mappings and trusted authority,
   root/version, and policy/version state.
2. Call `IssueChallenge(recipient, deployment)`. The prototype generates a
   cryptographically random BN254 scalar challenge, binds it to those IDs, and
   gives it a five-minute lifetime.
3. A private-record provider supplies `HealthClaimWitness`. The witness type
   rejects JSON serialization and all fields are excluded from JSON tags.
4. `GenerateHealthClaimProof` resolves the trusted anchors, checks challenge
   binding, computes the Poseidon commitment, context and record nullifier,
   builds the Z7 assignment, creates a Groth16 proof, and locally verifies it.
5. Only after successful local verification does it consume the challenge and
   record the nullifier in the supplied state provider. It returns a
   `ProofEnvelope` containing the 13 public signals, binary proof (base64 when
   JSON encoded), circuit/version, and SHA-256 proof identifier.
6. `VerifyHealthClaimProof(request, envelope)` checks request-to-statement and
   registered-anchor bindings, recomputes context, then verifies Groth16.

Public field elements use canonical decimal strings; proof bytes are Go
`[]byte` (base64 in JSON). The envelope has no witness property. Private values
must not be logged by callers; the Gateway path itself does not log them.

## Prototype boundaries

`MemoryRegistries`, `MemoryChallengeStore`, and `MemoryUsedNullifiers` are
explicit process-local prototypes and lose state on restart. Challenge freshness
and durable one-time acceptance require shared authenticated storage and atomic
consumption. Expiry/revocation and policy/root lifecycle remain external.
`VerifyHealthClaimProof` confirms supplied request bindings and the configured
anchors but does not itself reserve a fresh challenge or atomically accept a
nullifier; the caller must enforce freshness/replay policy for independently
received envelopes.

The stable symbolic protocol identifier `zerotrustblock.healthclaim.v1` maps
inside the Gateway to the frozen Z7 field value `202610041`; callers cannot
select a different numeric domain. Recipient and deployment names resolve
through explicit deterministic identifier mappings.

The in-memory engine runs Groth16 setup when constructed and retains keys only
in memory. Production setup, key custody, stable key/version distribution, and
authenticated external registries are not implemented. Authority registration
does reject off-curve, identity, and non-subgroup keys, but who is authorized to
register an authority remains an external trust decision. The proof hash is an
identifier/integrity field; it is not a substitute for proof verification.

## Commands

From `gateway/`:

```sh
GOCACHE=/tmp/ztb-z10-gocache go test -count=1 -v ./...
GOCACHE=/tmp/ztb-z10-gocache go test -count=1 -run '^$' -bench '^BenchmarkGatewayLocalZKPProcessing$' -benchtime=10x -benchmem
```

The benchmark reports assignment construction, proof generation, local proof
verification, and total local Gateway processing. It excludes Fabric and all
network/chaincode/Docker/IPFS latency.
