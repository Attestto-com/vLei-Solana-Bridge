# vLEI Solana Bridge

Open-source Solana program for on-chain vLEI credential attestation. Verifies [GLEIF](https://www.gleif.org/)-issued verifiable LEI credentials via Groth16 zero-knowledge proofs and stores soulbound attestation PDAs — permissionless, non-transferable, and revocable.

## Program

| | |
|---|---|
| **Program ID** | `AT2PmPv9tJkKyR9u1nQ2YvXXEeMrLCQUhtDeiKSwxgkp` |
| **Network** | Solana Devnet |
| **Framework** | Anchor 0.32.1 |
| **License** | Apache-2.0 |

## Overview

The vLEI Solana Bridge allows any party holding a valid vLEI credential to create an on-chain attestation proving their identity — without revealing the credential itself. The program uses Groth16 zero-knowledge proof verification (BN254) to validate credential authenticity on-chain before writing the attestation PDA.

### How it works

1. **Off-chain**: A vLEI credential holder generates a Groth16 ZKP proving they hold a valid, non-expired credential with a specific role level
2. **On-chain**: The program verifies the proof against the embedded verification key and, if valid, creates a soulbound PDA storing the attestation
3. **Verification**: Any protocol can read the PDA to confirm the attestation is active and non-expired

### Key properties

- **Permissionless** — anyone with a valid ZKP proof can create an attestation
- **Soulbound** — attestations are non-transferable PDAs bound to a specific LEI + credential subject
- **Revocable** — only the original authority can revoke an attestation
- **Privacy-preserving** — the vLEI credential never goes on-chain; only the ZKP proof hash is stored
- **PQ-ready** — supports post-quantum identity root binding (ML-DSA-65 / Dilithium)

## Instructions

### `create_attestation`

Creates a new attestation PDA after verifying the Groth16 ZKP on-chain.

**PDA seeds**: `['vlei-attestation', lei_hash, subject_aid]`

| Argument | Type | Description |
|---|---|---|
| `lei_hash` | `[u8; 32]` | SHA-256 of the 20-character LEI number |
| `subject_aid` | `[u8; 32]` | SHA-256 of the KERI AID (prevents same-LEI collisions) |
| `proof_a` | `[u8; 64]` | Groth16 proof point A (G1) |
| `proof_b` | `[u8; 128]` | Groth16 proof point B (G2) |
| `proof_c` | `[u8; 64]` | Groth16 proof point C (G1) |
| `public_signals` | `[[u8; 32]; 4]` | ZKP public inputs: timestamp, credential hash, wallet hash, role level |
| `attested_at` | `i64` | Unix timestamp of attestation creation |
| `expires_at` | `i64` | Unix timestamp of attestation expiry |
| `metadata_uri` | `String` | Off-chain metadata URI (max 2048 bytes) |

### `revoke_attestation`

Revokes an existing attestation by setting `flag = 0x01`. Only the original authority can revoke.

### `set_pq_identity_root`

Stores a 64-byte post-quantum identity root hash (SHA-512/SHAKE-256 of ML-DSA-65 public key) on an active attestation. Enables future PQ verification without storing the full 1312-byte key on-chain.

## ZKP Circuit

The Groth16 circuit (`vlei_verification.circom`) enforces 5 constraints:

1. **Credential hash** — Poseidon commitment matches the credential
2. **Expiry** — credential is not expired at attestation time
3. **Non-revocation** — credential is not revoked
4. **Role level** — credential holder meets minimum role level (ISO 5009: CEO=4, exec/board=3, rep=2, officer=1)
5. **Wallet binding** — proof is bound to the submitting wallet

## Account Layout

```
VleiAttestation (353 + metadata_uri bytes)
+------------------+------+
| Field            | Size |
+------------------+------+
| discriminator    |   8  |
| flag             |   1  |
| lei_hash         |  32  |
| subject_aid      |  32  |
| zkp_proof_hash   |  32  |
| public_signals   | 128  |
| attested_at      |   8  |
| expires_at       |   8  |
| metadata_uri_len |   2  |
| metadata_uri     | 4+N  |
| authority        |  32  |
| bump             |   1  |
| pq_root_set      |   1  |
| pq_identity_root |  64  |
+------------------+------+
```

## Build

```bash
# Install dependencies
pnpm install

# Build the program (skip IDL due to anchor-syn 0.32.1 bug)
anchor build --no-idl

# Run tests
anchor test
```

### Docker

```bash
docker compose build
docker compose up
```

## Security

See [SECURITY.md](./SECURITY.md) for vulnerability disclosure policy.

On-chain security metadata: `2XU1p6eMBsHKzLTSqQSzokZPq5YWCEsnoKasZVmHBpV1`

## License

Apache-2.0
