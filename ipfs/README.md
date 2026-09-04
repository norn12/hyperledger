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

Check the node:

```bash
curl -s http://127.0.0.1:5001/api/v0/id | head
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

After an authorized `ReadHealthRecord` result is obtained, the Gateway can call `GetOffChainData(record)` to:

1. Extract the IPFS CID.
2. Retrieve the encrypted object.
3. Decrypt and authenticate it with AES-GCM.
4. Recalculate the SHA-256 hash.
5. Compare it with the ledger's `dataHash`.
6. Return the original JSON only if integrity verification succeeds.

This provides two independent protections:

- **Confidentiality:** AES-256-GCM protects the off-chain payload.
- **Integrity:** the ledger's SHA-256 hash detects a modified payload.

## Consent and access control

IPFS is not used as the authorization mechanism. Fabric remains responsible for MSP/role policy, consent state, and audit events. A revoked record should therefore be denied by the application even if its CID remains available on the IPFS network.

## Important limitation

This integration uses a local Kubo node for reproducible development. It does not claim production-grade key management, private-IPFS cluster management, or enterprise key rotation. Those are future hardening tasks.
