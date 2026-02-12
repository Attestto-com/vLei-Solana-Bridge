# vLEI Solana Bridge

Open-source Solana program for on-chain vLEI credential attestation. Verifies [GLEIF](https://www.gleif.org/)-issued verifiable LEI credentials via Groth16 zero-knowledge proofs and stores soulbound attestation PDAs — permissionless, non-transferable, and revocable.

The world's first GLEIF-to-blockchain identity bridge: converts a verified vLEI credential (off-chain, KERI/ACDC) into a Solana Soulbound Token (SBT) backed by an on-chain attestation PDA, enabling any DeFi smart contract to verify institutional identity with a single instruction.

**No PII is stored on-chain.** A Zero-Knowledge Proof (ZKP) proves vLEI validity and role without revealing the underlying credential data.

## Program

| | |
|---|---|
| **Program ID** | `AT2PmPv9tJkKyR9u1nQ2YvXXEeMrLCQUhtDeiKSwxgkp` |
| **Network** | Solana Devnet |
| **Framework** | Anchor 0.32.1 |
| **License** | Apache-2.0 |

## Architecture

### Three-Layer Model

```
 OFF-CHAIN (GLEIF/KERI)           ATTESTTO BACKEND              ON-CHAIN (SOLANA)
 ========================         ========================       ========================

 +--------------------+          +----------------------+       +----------------------+
 | GLEIF Root of Trust|          |                      |       |                      |
 |   (KERI Witness)   |          |  VleiBridgeService   |       |  Attestation PDA     |
 +--------+-----------+          |  ==================  |       |  ==================  |
          |                      |                      |       |  [flag 1B]           |
          v                      |  1. Load vLEI cred   |       |  [lei_hash 32B]      |
 +--------------------+          |  2. Re-verify GLEIF  |       |  [zkp_hash 32B]      |
 | QVI (Qualified     |          |  3. Generate ZKP     |       |  [attested_at 8B]    |
 |  vLEI Issuer)      |          |  4. Write PDA        |       |  [expires_at 8B]     |
 +--------+-----------+          |  5. Mint SBT         |       |  [metadata_uri]      |
          |                      |                      |       |                      |
          v                      +----------+-----------+       +----------+-----------+
 +--------------------+                     |                              |
 | Legal Entity (LE)  |                     v                              v
 |  vLEI Credential   |          +----------------------+       +----------------------+
 |  (ACDC format)     |          |                      |       |                      |
 |  - LEI number      |          |  ZkpService          |       |  Soulbound Token     |
 |  - Role (OOR/ECR)  |          |  ==================  |       |  (Token-2022)        |
 |  - Subject AID     |          |  Circom/SnarkJS      |       |  ==================  |
 |  - Issuer chain    |          |  circuit proves:     |       |  - Non-Transferable  |
 +--------------------+          |  "wallet X holds     |       |  - Metaplex metadata |
                                 |   valid vLEI for     |       |  - Links to PDA      |
                                 |   LEI #Y with role Z"|       |  - Burnable on revoke|
                                 |  NO PII disclosed    |       |                      |
                                 +----------------------+       +----------------------+
```

### How It Works

1. **Off-chain**: A vLEI credential holder generates a Groth16 ZKP proving they hold a valid, non-expired credential with a specific role level
2. **On-chain**: The program verifies the proof against the embedded verification key and, if valid, creates a soulbound PDA storing the attestation
3. **Verification**: Any protocol can read the PDA to confirm the attestation is active and non-expired

### Key Properties

- **Permissionless** — anyone with a valid ZKP proof can create an attestation
- **Soulbound** — attestations are non-transferable PDAs bound to a specific LEI + credential subject
- **Revocable** — only the original authority can revoke an attestation
- **Privacy-preserving** — the vLEI credential never goes on-chain; only the ZKP proof hash is stored
- **PQ-ready** — supports post-quantum identity root binding (ML-DSA-65 / Dilithium)

## Bridge Flow

### Full Mint Sequence

```
 User                    Frontend              VleiBridgeController     VleiBridgeService
  |                         |                         |                        |
  |  1. "Bridge my vLEI"   |                         |                        |
  |------------------------>|                         |                        |
  |                         |  POST /vlei-bridge/     |                        |
  |                         |  attest                 |                        |
  |                         |  { vleiCredentialId,    |                        |
  |                         |    walletAddress }      |                        |
  |                         |------------------------>|                        |
  |                         |                         |  bridge(ctx, credId,   |
  |                         |                         |         wallet)        |
  |                         |                         |----------------------->|
  |                         |                         |                        |
  |                         |                         |        STEP 1: LOAD + VALIDATE
  |                         |                         |        ========================
  |                         |                         |        | VleiCredential.find()
  |                         |                         |        | Check: tenant match
  |                         |                         |        | Check: status = 'verified'
  |                         |                         |        |
  |                         |                         |        STEP 1b: GLEIF RE-VERIFY
  |                         |                         |        =========================
  |                         |                         |        | GleifService.lookupLei()
  |                         |                         |        | Confirm LEI still ACTIVE
  |                         |                         |        |
  |                         |                         |        STEP 1c: DEDUP CHECK
  |                         |                         |        ====================
  |                         |                         |        | findByLei() — return
  |                         |                         |        | existing if minted
  |                         |                         |        |
  |                         |                         |        STEP 2: CREATE RECORD
  |                         |                         |        =====================
  |                         |                         |        | VleiBridgeAttestation
  |                         |                         |        |   .create({
  |                         |                         |        |     status: pending_zkp
  |                         |                         |        |   })
  |                         |                         |        |
  |                         |                         |        STEP 3: ZKP
  |                         |                         |        ==========
  |                         |                         |        | ZkpService
  |                         |                         |        |   .generateVleiProof({
  |                         |                         |        |     credential,
  |                         |                         |        |     userId, ip, ua
  |                         |                         |        |   })
  |                         |                         |        | status -> zkp_generated
  |                         |                         |        |
  |                         |                         |        STEP 4: ON-CHAIN PDA
  |                         |                         |        ====================
  |                         |                         |        | SolanaAttestationService
  |                         |                         |        |   .createAttestation({
  |                         |                         |        |     leiNumber,
  |                         |                         |        |     zkpProofHash,
  |                         |                         |        |     jurisdiction,
  |                         |                         |        |     expiresAt
  |                         |                         |        |   })
  |                         |                         |        | Gasless relayer pays fees
  |                         |                         |        | status -> attested
  |                         |                         |        |
  |                         |                         |        STEP 5: MINT SBT
  |                         |                         |        ================
  |                         |                         |        | SovereignPassService
  |                         |                         |        |   .mintVleiBridgeSbt(
  |                         |                         |        |     wallet, pda,
  |                         |                         |        |     metadata
  |                         |                         |        |   )
  |                         |                         |        | Token-2022 NonTransferable
  |                         |                         |        | status -> minted
  |                         |                         |        |
  |                         |                         |<-----------------------|
  |                         |                         |  { success, attestation }
  |                         |<------------------------|                        |
  |                         |  201 Created             |                        |
  |<------------------------|                         |                        |
  |  SBT in wallet          |                         |                        |
```

### State Machine

```
                +-------------+
                | pending_zkp |
                +------+------+
                       |
              ZkpService.generateVleiProof()
                       |
                +------v-------+
                | zkp_generated |
                +------+-------+
                       |
            SolanaAttestationService
              .createAttestation()
                       |
                +------v------+
                |  attesting  |
                +------+------+
                       |
              PDA written on-chain
                       |
                +------v------+
                |  attested   |
                +------+------+
                       |
            SovereignPassService
              .mintVleiBridgeSbt()
                       |
                +------v------+
                |   minting   |
                +------+------+
                       |
              SBT minted to wallet
                       |
                +------v------+       +----------+
                |   minted    |------>|  revoked  |
                +------+------+       +----------+
                       |              (burn SBT +
                   [active]            invalidate PDA)
                       |
                +------v------+
                |   failed    |  <-- any step can fail
                +-------------+
```

## Instructions

### `create_attestation`

Creates a new attestation PDA after verifying the Groth16 ZKP on-chain.

**PDA seeds**: `['vlei-attestation', lei_hash, subject_aid]`

Adding `subject_aid` (KERI AID of the credential subject) to the PDA seeds prevents collision when multiple officers hold credentials under the same LEI.

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

## Account Layout

```
VleiAttestation (353 + metadata_uri bytes)

 Byte Offset    Size     Field               Description
 ===========    ====     =====               ===========
 0              8        discriminator       Anchor 8-byte account discriminator
 8              1        flag                0x00 = active, 0x01 = revoked
 9              32       lei_hash            SHA-256 of LEI number
 41             32       subject_aid         SHA-256 of KERI AID (credential subject)
 73             32       zkp_proof_hash      SHA-256 of Groth16 proof (proof_a||b||c)
 105            128      public_signals      4 x 32-byte ZKP public inputs (audit)
 233            8        attested_at         Unix timestamp (LE int64)
 241            8        expires_at          Unix timestamp (LE int64)
 249            2        metadata_uri_len    Length of metadata URI (LE uint16)
 251            4+N      metadata_uri        Borsh String (4-byte len prefix + UTF-8)
 255+N          32       authority           Pubkey of fee payer (Attestto backend)
 287+N          1        bump                PDA bump seed
 288+N          1        pq_identity_root_set  Whether PQ root has been set
 289+N          64       pq_identity_root    SHA-512 hash of ML-DSA-65 public key

 Total: 8 + 353 + N bytes (N = metadata URI length, max 2048)

 Privacy: NO entity name, NO jurisdiction, NO PII stored on-chain.
          Only hashes, timestamps, and ZKP public signals.
```

### Soulbound Token (SBT)

```
 Token Standard:   SPL Token-2022 with NonTransferable extension
 Metadata:         Metaplex Token Metadata

 +----------------------------------+
 | Token-2022 Mint                  |
 | ================================ |
 | supply:         1                |
 | decimals:       0                |
 | mint_authority: Attestto         |
 | freeze_auth:    Attestto         |
 | extensions:                      |
 |   - NonTransferable (soulbound)  |
 +----------------------------------+
          |
          v
 +----------------------------------+
 | Metaplex Metadata                |
 | ================================ |
 | name:     "Attestto vLEI Pass"   |
 | symbol:   "AVLEI"               |
 | uri:      -> metadata JSON       |
 |   {                              |
 |     leiNumber,                   |
 |     jurisdiction,                |
 |     attestedAt,                  |
 |     expiresAt,                   |
 |     attestationPda               |
 |   }                              |
 +----------------------------------+
```

## ZKP Circuit

The Groth16 circuit (`vlei_verification.circom`) enforces 5 constraints:

1. **Credential hash** — Poseidon commitment matches the credential
2. **Expiry** — credential is not expired at attestation time
3. **Non-revocation** — credential is not revoked
4. **Role level** — credential holder meets minimum role level (ISO 5009: CEO=4, exec/board=3, rep=2, officer=1)
5. **Wallet binding** — proof is bound to the submitting wallet

### What the ZKP Proves (Without Revealing)

```
 +========================================+
 |          PUBLIC INPUTS (on-chain)       |
 | ====================================== |
 | credentialHashCommitment  Poseidon hash |
 | walletAddress             Solana pubkey |
 | roleLevel                 1-4 numeric  |
 | expirationTimestamp       Unix seconds |
 | issuerCommitment          Poseidon hash |
 +========================================+
                    |
      ZKP Circuit   |  Proves relationship
      ===========   |  without revealing
                    |
 +========================================+
 |         PRIVATE INPUTS (hidden)        |
 | ====================================== |
 | credentialSAID   Full ACDC identifier  |
 | leiNumber        20-char LEI           |
 | subjectName      Entity legal name     |
 | roleName         ISO 5009 role string  |
 | issuerAID        QVI identifier        |
 | issuerChain      Full trust chain      |
 +========================================+

 Statement proven:
   "The controller of wallet [walletAddress] holds a
    valid vLEI credential for LEI #[hidden] with role
    authority level [roleLevel], issued by a GLEIF-
    authorized QVI [hidden], expiring at [timestamp]."
```

## Role Level Mapping (ISO 5009)

```
 vLEI Role (ISO 5009)                  Level   On-Chain Permissions
 ====================                  =====   ====================

 BO  (Beneficial Owner)       -----+
 DIR (Director)                    |
 SEC (Secretary)                   +--- 1     Read attestations,
 TRE (Treasurer)              -----+          view compliance status

 CO  (Compliance Officer)     -----+
 AO  (Authorized Officer)     -----+--- 2     Sign compliance docs,
                                              approve transfers

 CFO, COO, CIO, CTO,         -----+
 CISO, LR (Legal Rep),            +--- 3     Approve KYB, sign
 BD  (Board Director)         -----+          regulatory reports

 CEO (Chief Executive)        --------- 4     Full authority: override,
                                              governance votes,
                                              multisig admin
```

## Verification

### On-Chain (DeFi Protocol Perspective)

```rust
require(attestto_sbt.has_valid_vlei(user_wallet))
```

```
 DeFi Protocol (Rust/Anchor)                    Solana
 ===========================                    ======

 1. Derive PDA:
    seeds = ['vlei-attestation', sha256(lei), sha256(subject_aid)]
    program = VLEI_ATTESTATION_PROGRAM_ID
         |
         v
 2. Read PDA account data:
    +------------------------------------------+
    | if account not found:                    |
    |   REJECT - no attestation exists         |
    |                                          |
    | if flag == 0x01:                         |
    |   REJECT - attestation revoked           |
    |                                          |
    | if expires_at < clock.unix_timestamp:    |
    |   REJECT - attestation expired           |
    |                                          |
    | else:                                    |
    |   ALLOW - valid vLEI attestation         |
    +------------------------------------------+

 Cost: 1 account read (~0.000005 SOL)
 Latency: <400ms (Solana slot time)
```

### Off-Chain (REST API)

```
 GET /vlei-bridge/verify/:lei

 1. DB lookup: VleiBridgeAttestation.findByLei(lei, tenant)
    -> Check status = 'minted' and not expired

 2. On-chain read: SolanaAttestationService.verifyAttestation(lei)
    -> Derive PDA, read account, check flag + expiry

 3. Result: valid = (dbValid AND onChainValid)

 Response:
 {
   "valid": true,
   "attestation": { id, leiNumber, entityName, status, ... },
   "onChain": { "valid": true }
 }
```

## Revocation

### Manual Revocation

```
 Trigger: vLEI credential revoked/expired off-chain
          OR admin manual revocation

 VleiBridgeService                SolanaAttestationService         Solana
 ================                ========================         ======
       |                                  |                          |
  revoke(id, reason)                      |                          |
       |                                  |                          |
       |--- Check: canRevoke() -----------|                          |
       |    (status in [attested,minted]) |                          |
       |                                  |                          |
       |--- revokeAttestation(pda) ------>|                          |
       |                                  |--- TX: write 0x01 ----->|
       |                                  |    flag to PDA           |
       |                                  |                          |
       |                                  |<--- tx signature -------|
       |<---------------------------------|                          |
       |                                  |                          |
       |--- markRevoked(reason)           |                          |
       |    status -> 'revoked'           |                          |
       |    revokedAt = now               |                          |
       |                                  |                          |

 Result: PDA flag = 0x01 (revoked)
         SBT remains in wallet but attestation is invalid
         DeFi protocols reading PDA see revoked status
```

### Oracle Sync (Scheduled Job)

```
 VleiSolanaRevocationSyncJob (every 6 hours)
 =============================================

 1. Query vlei_bridge_attestations
    WHERE status = 'minted'
      AND linked vlei_credential.status IN ('revoked', 'expired')

 2. For each stale attestation:
    a) Revoke on-chain PDA (flag = 0x01)
    b) Burn SBT (SovereignPassService.burnSovereignPass)
    c) Update DB: status -> 'revoked'
    d) Create audit log entry
    e) Notify user via SSE + email

 3. Query vlei_bridge_attestations
    WHERE status = 'minted'
      AND expiresAt < NOW()

 4. For each expired attestation:
    Same as above with revocationReason = 'vlei_expired'
```

### Refresh (Re-Attestation)

```
 POST /vlei-bridge/attestations/:id/refresh

 1. Load existing attestation
 2. Re-verify LEI with GLEIF API
    |
    +-- If GLEIF says invalid:
    |   Mark attestation as revoked
    |   Return error: GLEIF_INVALID
    |
    +-- If GLEIF says valid:
        3. Revoke old attestation (PDA + DB)
        4. Run full bridge() again:
           new ZKP -> new PDA -> new SBT
        5. Return new attestation
```

## Gasless Transaction Relay

Entities never need to hold SOL. Attestto sponsors all on-chain transaction fees.

```
 Entity (no SOL)          Attestto Backend            Gasless Relayer           Solana
 ===============          ================            ===============           ======
       |                         |                          |                      |
       |  bridge request         |                          |                      |
       |------------------------>|                          |                      |
       |                         |  Build TX instruction    |                      |
       |                         |  (PDA write / SBT mint)  |                      |
       |                         |                          |                      |
       |                         |  relayTransaction(tx,    |                      |
       |                         |    'credential_issue',   |                      |
       |                         |    userId)               |                      |
       |                         |------------------------->|                      |
       |                         |                          |  Fee payer signs TX  |
       |                         |                          |  + submits to RPC    |
       |                         |                          |--------------------->|
       |                         |                          |                      |
       |                         |                          |<--- tx signature ----|
       |                         |<-------------------------|                      |
       |                         |  { success, signature }  |                      |
       |<------------------------|                          |                      |
       |  SBT in wallet          |                          |                      |
```

## REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/vlei-bridge/attest` | Full bridge flow (ZKP + PDA + SBT) |
| `GET` | `/vlei-bridge/attestations` | List attestations (paginated) |
| `GET` | `/vlei-bridge/attestations/:id` | Single attestation detail |
| `POST` | `/vlei-bridge/attestations/:id/refresh` | Re-verify + re-attest |
| `DELETE` | `/vlei-bridge/attestations/:id` | Revoke attestation |
| `GET` | `/vlei-bridge/verify/:lei` | Public LEI verification |

### POST /vlei-bridge/attest

```json
// Request
{
  "vleiCredentialId": 42,
  "walletAddress": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
}

// Response (201)
{
  "id": 1,
  "tenantId": 5,
  "vleiCredentialId": 42,
  "leiNumber": "5493001KJTIIGC8Y1R12",
  "entityName": "Attestto S.A.",
  "jurisdiction": "CR",
  "walletAddress": "7xKXtg...",
  "status": "minted",
  "attestationPda": "3Fmb...",
  "sbtMintAddress": "9Gkp...",
  "sbtTokenAccount": "ATokenGPvb...",
  "onChainTxSignature": "5eykt...",
  "mintTxSignature": "4bGSx...",
  "attestedAt": "2026-02-09T...",
  "mintedAt": "2026-02-09T...",
  "expiresAt": "2027-02-09T..."
}
```

**Error codes**: `CREDENTIAL_NOT_FOUND`, `TENANT_MISMATCH`, `CREDENTIAL_INACTIVE`, `GLEIF_INVALID`, `ZKP_FAILED`, `ATTESTATION_FAILED`, `SBT_MINT_FAILED`

### DELETE /vlei-bridge/attestations/:id

```json
// Request
{ "reason": "vLEI credential revoked by QVI" }

// Response (200)
{ "...attestation", "status": "revoked", "revokedAt": "..." }
```

## SAS (Solana Attestation Service) Integration

### Dual-Issuance Architecture

After the custom Attestto PDA (Step 4) and SBT (Step 5) are written, the bridge optionally mirrors the attestation to the ecosystem-wide [Solana Attestation Service](https://github.com/solana-foundation/solana-attestation-service) (SAS) as a tokenized attestation. This is controlled by a tenant-level setting.

```
 VleiBridgeService.bridge()
   Step 1-3: [unchanged — validate, GLEIF, ZKP]
   Step 4:   Custom PDA write (attestto_vlei_sbt program)
   Step 5:   SBT mint via SovereignPass (Token-2022)
   Step 6:   IF SAS_ATTESTATION_ENABLED → mirror to SAS    ← NEW
             ELSE skip

 Both attestations coexist:
   - Custom PDA = source of truth for ZKP verification
   - SAS attestation = ecosystem discoverability (Civic, SumSub, Range, etc.)

 SAS failure is NON-FATAL: custom PDA + SBT remain valid.
```

### SAS Program Details

| | |
|---|---|
| **SAS Program ID** | `22zoJMtdu4tQc2PzL74ZUT7FrwgB1Udec8DdW4yw4BdG` |
| **SDK** | `sas-lib` (npm) — uses `@solana/kit` (Web3.js v2) |
| **Attestation Type** | Tokenized — mints a soulbound Token-2022 NFT to the recipient |

### SAS Schema

The Attestto vLEI schema registered on SAS:

```
 Credential: "Attestto vLEI Bridge"
 Schema:     "vLEI Attestation" (v1)

 Field             Type      Description
 =====             ====      ===========
 lei_hash          String    SHA-256 of 20-char LEI number
 subject_aid       String    SHA-256 of KERI AID
 zkp_proof_hash    String    SHA-256 of Groth16 proof
 role_level        U8        ISO 5009 authority level (1-4)
 jurisdiction      String    ISO 3166-1 alpha-2 country code
 attested_at       I64       Unix timestamp of attestation
 expires_at        I64       Unix timestamp of expiry
 custom_pda        String    Address of our custom attestation PDA
 metadata_uri      String    Off-chain metadata JSON URI
```

### SAS Bootstrap

One-time setup per environment:

```bash
# Create credential + schema + tokenize on SAS
node ace sas:bootstrap --network=devnet

# Output:
# SAS_CREDENTIAL_PDA=<credential>
# SAS_SCHEMA_PDA=<schema>
# SAS_SCHEMA_MINT=<schemaMint>
# SAS_ATTESTATION_ENABLED=true
```

### SAS Revocation Sync

When an Attestto attestation is revoked (manual or oracle sync), the SAS attestation is also closed:

```
 VleiBridgeService.revoke()
   1. Revoke custom PDA (flag = 0x01)
   2. IF sas_status = 'created':
      Close SAS attestation (CloseAttestation instruction)
      sas_status -> 'closed'
   3. Mark DB record as revoked
```

### SAS Environment Variables

```
SAS_PROGRAM_ID=22zoJMtdu4tQc2PzL74ZUT7FrwgB1Udec8DdW4yw4BdG
SAS_CREDENTIAL_PDA=<from bootstrap>
SAS_SCHEMA_PDA=<from bootstrap>
SAS_SCHEMA_MINT=<from bootstrap>
SAS_ATTESTATION_ENABLED=false   # default off, enable per tenant
```

### SAS Database Columns

Added to `vlei_bridge_attestations`:

```
 Column                  Type          Description
 ======                  ====          ===========
 sas_attestation_pda     varchar(255)  SAS attestation PDA address
 sas_mint_address        varchar(255)  SAS Token-2022 mint address
 sas_tx_signature        varchar(255)  SAS creation tx signature
 sas_status              varchar(20)   pending | created | failed | closed
```

## Regulatory Alignment

| Standard | How the Bridge Addresses It |
|---|---|
| **GLEIF vLEI (ACDC/KERI)** | Full credential verification, chain-of-trust validation back to GLEIF Root of Trust |
| **EU MiCA** | On-chain identity attestation enables institutional DeFi access with verifiable corporate identity |
| **FATF Travel Rule** | Verifiable corporate identity for cross-border crypto transactions via SBT |
| **FATF Recommendation 16** | Originator/beneficiary identification in virtual asset transfers via PDA lookup |
| **ISO 5009** | Role-level mapping from vLEI roles to on-chain numeric authority levels (1-4) |

## Security

| Threat | Mitigation |
|---|---|
| PII leakage on-chain | ZKP masks all sensitive data; only hashes and timestamps stored in PDA |
| Stale credentials | Oracle job runs every 6h; GLEIF re-verified on refresh; PDA has expiry timestamp |
| Unauthorized minting | Only Attestto's fee payer can write PDAs; vLEI must be status='verified' in DB |
| SBT transfer | Token-2022 NonTransferable extension enforced at protocol level |
| Replay attacks | ZKP includes wallet pubkey binding; PDA is keyed to specific LEI + subject AID |
| Key compromise | Revocation sync burns SBT + invalidates PDA within 6h; manual revoke is instant |
| Tenant isolation | All queries scoped by tenantId; cross-tenant access returns error |

See [SECURITY.md](./SECURITY.md) for vulnerability disclosure policy.

On-chain security metadata: `2XU1p6eMBsHKzLTSqQSzokZPq5YWCEsnoKasZVmHBpV1`

## Build

### Circuit

```bash
# Install Circom compiler
git clone https://github.com/iden3/circom.git /tmp/circom
cd /tmp/circom && cargo build --release && cargo install --path circom

# Build the circuit
cd circuits
npm install          # installs circomlib, snarkjs
./build.sh           # compile + trusted setup + export vkey
```

This produces three artifacts in `api/storage/zkp/circuits/`:
- `vlei_verification.wasm` — circuit witness generator
- `vlei_verification.zkey` — proving key (Groth16)
- `vlei_verification_vkey.json` — verification key

### Verification Key Conversion

The Anchor program embeds the verification key as a Rust `const`. After building the circuit, convert the snarkjs JSON vkey into byte arrays:

| Point type | Encoding order | Size |
|---|---|---|
| G1 | `x (32B BE) \|\| y (32B BE)` | 64 bytes |
| G2 | `x_imaginary (32B BE) \|\| x_real (32B BE) \|\| y_imaginary (32B BE) \|\| y_real (32B BE)` | 128 bytes |

> For G2, the **imaginary** component comes **before** the real component in each pair. This matches the Ethereum/Solana `alt_bn128` precompile encoding.

**Automated conversion script:**

```bash
node -e "
const vkey = require('./circuits/build/vlei_verification_vkey.json');

function bigintToBytes32BE(s) {
  let n = BigInt(s);
  const bytes = [];
  for (let i = 0; i < 32; i++) {
    bytes.unshift(Number(n & 0xFFn));
    n >>= 8n;
  }
  return bytes;
}

function g1ToBytes(pt) {
  return [...bigintToBytes32BE(pt[0]), ...bigintToBytes32BE(pt[1])];
}

function g2ToBytes(pt) {
  return [
    ...bigintToBytes32BE(pt[0][1]), ...bigintToBytes32BE(pt[0][0]),
    ...bigintToBytes32BE(pt[1][1]), ...bigintToBytes32BE(pt[1][0]),
  ];
}

console.log('vk_alpha_g1:', JSON.stringify(g1ToBytes(vkey.vk_alpha_1)));
console.log('vk_beta_g2:', JSON.stringify(g2ToBytes(vkey.vk_beta_2)));
console.log('vk_gamma_g2:', JSON.stringify(g2ToBytes(vkey.vk_gamma_2)));
console.log('vk_delta_g2:', JSON.stringify(g2ToBytes(vkey.vk_delta_2)));
vkey.IC.forEach((ic, i) => console.log('vk_ic[' + i + ']:', JSON.stringify(g1ToBytes(ic))));
"
```

Paste the output into the `VERIFYING_KEY` const in `lib.rs`. Rebuild with `anchor build`.

### Program

```bash
# Install Anchor CLI
cargo install --git https://github.com/coral-xyz/anchor avm --force
avm install 0.30.1 && avm use 0.30.1

# Build and test
pnpm install
anchor build --no-idl
anchor test
```

### Docker

```bash
docker compose build
docker compose up
```

### Deploy to Devnet

```bash
solana config set --url https://api.devnet.solana.com
solana airdrop 5

cd contracts
anchor build
solana address -k target/deploy/attestto_vlei_sbt-keypair.json
# Update declare_id!() in lib.rs and [programs.devnet] in Anchor.toml

anchor build
anchor deploy --provider.cluster devnet
solana program show <PROGRAM_ID>
```

## License

Apache-2.0
