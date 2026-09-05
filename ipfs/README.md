# ZeroTrustBlock IPFS Layer

ZeroTrustBlock uses IPFS as an **off-chain encrypted storage layer**. Hyperledger Fabric stores the record metadata, integrity hash, and IPFS CID; the medical payload itself is encrypted before it is uploaded.

## Architecture

```text
Medical JSON
    |
    v
Go Gateway
    |
    +--> SHA-256(data) --------------------> Fabric dataHash
    |
    +--> AES-256-GCM encryption
             |
             v
          Kubo/IPFS
             |
             v
            CID ---------------------------> Fabric offChainPointer
```

The current Fabric `HealthRecord` already contains `dataHash` and `offChainPointer`, so no new ledger field is required for the CID.

## Why encryption?

IPFS is content-addressed and data may be retrievable by CID from participating nodes. Healthcare payloads therefore must not be uploaded in plaintext. The Gateway encrypts the JSON with AES-256-GCM before calling the local Kubo HTTP RPC API.

## Start IPFS

From the repository root:

```bash
docker-compose -f docker-compose.ipfs.yml up -d
```

Check the node. Kubo's RPC endpoints are POST endpoints:

```bash
curl -s -X POST http://127.0.0.1:5001/api/v0/id
```

The RPC API is intentionally bound to `127.0.0.1` by the supplied compose file.

## Generate an encryption key

Generate a 32-byte AES-256 key and keep it outside Git:

```bash
openssl rand -hex 32
```

Then configure the Gateway process:

```bash
export ZT_IPFS_ENABLED=true
export ZT_IPFS_API_URL=http://127.0.0.1:5001/api/v0
export ZT_IPFS_ENCRYPTION_KEY=<64-hex-character-key>
```

Do not commit the key to the repository.

**Keep the same key while existing encrypted IPFS objects are needed.** The IPFS volume is persistent, so changing the encryption key makes previously stored ZeroTrustBlock payloads undecryptable.

If `.env.local` is present, `full_reset.sh` loads it and reuses `ZT_IPFS_ENCRYPTION_KEY`. If IPFS is enabled and no key exists, the reset script generates one and persists it in `.env.local`.

## Gateway behavior

When `ZT_IPFS_ENABLED=true`, `WriteHealthRecord`:

1. Serializes the medical payload to JSON.
2. Computes the SHA-256 data hash.
3. Generates and verifies the Groth16 proof.
4. Encrypts the JSON using AES-256-GCM.
5. Uploads the encrypted payload to IPFS with pinning enabled.
6. Receives the CID.
7. Stores `ipfs://<CID>` as `offChainPointer` in Fabric.

When IPFS is disabled, the existing `offChainPointer` argument is preserved for backward compatibility.

## Authorized retrieval

Use the Gateway's `GetAuthorizedOffChainData(recordID, patientAge)` method for application retrieval. It performs the Fabric authorization transaction first and fetches the IPFS object only after access is granted.

The retrieval path:

1. Generate and verify the caller's ZKP proof.
2. Submit `ReadHealthRecord` to Fabric.
3. Enforce consent, MSP, role, and ZKP policy in chaincode.
4. Fetch the IPFS CID only after authorization succeeds.
5. Decrypt and authenticate the object with AES-GCM.
6. Recalculate the SHA-256 hash.
7. Compare it with the ledger's `dataHash`.
8. Return the original JSON only if integrity verification succeeds.

The low-level IPFS fetch is intentionally internal to the Gateway so callers cannot accidentally treat an arbitrary record map as an already-authorized retrieval context.

This provides two independent protections:

- **Confidentiality:** AES-256-GCM protects the off-chain payload.
- **Integrity:** the ledger's SHA-256 hash detects a modified payload.
- **Authorization:** Fabric remains the gatekeeper before off-chain retrieval.

## Consent and access control

IPFS is not the authorization mechanism. Fabric remains responsible for MSP/role policy, consent state, and audit events. A revoked record is therefore denied before its CID is fetched through the authorized Gateway path, even though the CID may still exist on the IPFS network.

## End-to-end test

With Fabric deployed, identities enrolled, IPFS running, and the environment configured:

```bash
cd gateway
source ../.env.local
go run ./cmd/test_ipfs
```

The test writes a real health record through ZKP + encryption + IPFS + Fabric, authorizes a read through Fabric, retrieves the CID, decrypts it, verifies `dataHash`, and checks that the recovered JSON exactly matches the original payload.

## Important limitation

This integration uses a local Kubo node for reproducible development. It does not claim production-grade key management, private-IPFS cluster management, or enterprise key rotation. Those are future hardening tasks.
