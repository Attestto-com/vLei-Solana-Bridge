use anchor_lang::prelude::*;
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use sha2::{Sha256, Digest};

declare_id!("AT2PmPv9tJkKyR9u1nQ2YvXXEeMrLCQUhtDeiKSwxgkp");

/// Maximum length of a metadata URI (2 KB)
const MAX_METADATA_URI_LEN: usize = 2048;

/// PDA seed prefix — must match TypeScript `solana_attestation_service.ts`
const PDA_SEED_PREFIX: &[u8] = b"vlei-attestation";

/// Attestation flag values
const FLAG_ACTIVE: u8 = 0x00;
const FLAG_REVOKED: u8 = 0x01;

/// Number of public inputs for the vLEI verification circuit.
///
/// Public inputs order:
///   [0] currentTimestamp
///   [1] credentialHashCommitment
///   [2] walletPubkeyHash
///   [3] minRoleLevel
const NR_PUBLIC_INPUTS: usize = 4;

/// Verification key for the vLEI verification Groth16 circuit (BN254).
///
/// IC points: NR_PUBLIC_INPUTS + 1 = 5 (base + one per public input).
/// Replace these placeholder values after running `circuits/build.sh`
/// and exporting the vkey with `snarkjs zkey export verificationkey`.
const VERIFYING_KEY: Groth16Verifyingkey = Groth16Verifyingkey {
    nr_pubinputs: NR_PUBLIC_INPUTS,
    vk_alpha_g1: [
        45, 77, 154, 167, 227, 2, 217, 223, 65, 116, 157, 85, 7, 148, 157, 5,
        219, 234, 51, 251, 177, 108, 100, 59, 34, 245, 153, 162, 190, 109, 242, 226,
        20, 190, 221, 80, 60, 55, 206, 176, 97, 216, 236, 96, 32, 159, 227, 69,
        206, 137, 131, 10, 25, 35, 3, 1, 240, 118, 202, 255, 0, 77, 25, 38,
    ],
    vk_beta_g2: [
        9, 103, 3, 47, 203, 247, 118, 209, 175, 201, 133, 248, 136, 119, 241, 130,
        211, 132, 128, 166, 83, 242, 222, 202, 169, 121, 76, 188, 59, 243, 6, 12,
        14, 24, 120, 71, 173, 76, 121, 131, 116, 208, 214, 115, 43, 245, 1, 132,
        125, 214, 139, 192, 224, 113, 36, 30, 2, 19, 188, 127, 193, 61, 183, 171,
        48, 76, 251, 209, 224, 138, 112, 74, 153, 245, 232, 71, 217, 63, 140, 60,
        170, 253, 222, 196, 107, 122, 13, 55, 157, 166, 154, 77, 17, 35, 70, 167,
        23, 57, 193, 177, 164, 87, 168, 199, 49, 49, 35, 210, 77, 47, 145, 146,
        248, 150, 183, 198, 62, 234, 5, 169, 213, 127, 6, 84, 122, 208, 206, 200,
    ],
    vk_gamme_g2: [
        25, 142, 147, 147, 146, 13, 72, 58, 114, 96, 191, 183, 49, 251, 93, 37,
        241, 170, 73, 51, 53, 169, 231, 18, 151, 228, 133, 183, 174, 243, 18, 194,
        24, 0, 222, 239, 18, 31, 30, 118, 66, 106, 0, 102, 94, 92, 68, 121,
        103, 67, 34, 212, 247, 94, 218, 221, 70, 222, 189, 92, 217, 146, 246, 237,
        9, 6, 137, 208, 88, 95, 240, 117, 236, 158, 153, 173, 105, 12, 51, 149,
        188, 75, 49, 51, 112, 179, 142, 243, 85, 172, 218, 220, 209, 34, 151, 91,
        18, 200, 94, 165, 219, 140, 109, 235, 74, 171, 113, 128, 141, 203, 64, 143,
        227, 209, 231, 105, 12, 67, 211, 123, 76, 230, 204, 1, 102, 250, 125, 170,
    ],
    vk_delta_g2: [
        38, 159, 186, 163, 75, 176, 40, 23, 134, 122, 169, 32, 120, 177, 58, 49,
        139, 140, 81, 51, 119, 78, 54, 91, 28, 226, 238, 73, 252, 53, 183, 121,
        4, 231, 44, 253, 46, 24, 236, 58, 113, 49, 240, 15, 42, 77, 125, 19,
        150, 225, 122, 28, 65, 93, 225, 50, 207, 65, 212, 90, 24, 107, 202, 70,
        9, 220, 3, 28, 70, 70, 205, 60, 220, 143, 28, 251, 40, 155, 148, 109,
        240, 190, 25, 239, 217, 73, 165, 125, 194, 69, 234, 172, 51, 217, 216, 19,
        37, 31, 180, 95, 83, 208, 232, 36, 125, 32, 151, 106, 229, 244, 254, 214,
        252, 189, 87, 69, 143, 180, 124, 92, 19, 243, 151, 17, 129, 124, 255, 40,
    ],
    vk_ic: &[
        [
            19, 103, 75, 85, 174, 197, 55, 95, 29, 49, 43, 174, 5, 208, 157, 49,
            181, 108, 55, 188, 134, 151, 108, 119, 117, 219, 124, 84, 193, 69, 196, 195,
            42, 71, 98, 240, 0, 54, 212, 152, 147, 162, 209, 177, 116, 116, 7, 57,
            171, 36, 107, 32, 112, 48, 66, 48, 200, 184, 194, 207, 3, 76, 78, 31,
        ],
        [
            35, 114, 133, 97, 44, 220, 154, 147, 14, 108, 225, 251, 78, 174, 228, 196,
            135, 135, 167, 117, 136, 6, 193, 226, 175, 134, 240, 119, 141, 205, 214, 186,
            4, 66, 252, 126, 85, 135, 48, 176, 106, 170, 101, 65, 159, 246, 129, 192,
            233, 76, 106, 78, 199, 103, 212, 248, 73, 74, 20, 135, 178, 180, 55, 233,
        ],
        [
            29, 251, 22, 123, 22, 52, 195, 56, 9, 254, 2, 37, 255, 216, 172, 45,
            136, 244, 214, 11, 50, 217, 89, 154, 126, 231, 62, 24, 101, 226, 151, 115,
            43, 114, 165, 138, 194, 173, 72, 174, 21, 146, 225, 15, 181, 80, 215, 17,
            60, 82, 121, 156, 156, 236, 36, 227, 246, 212, 19, 245, 133, 226, 229, 80,
        ],
        [
            23, 133, 85, 27, 117, 104, 117, 69, 169, 185, 182, 183, 97, 38, 153, 107,
            29, 211, 74, 34, 31, 240, 217, 129, 167, 238, 103, 101, 242, 143, 143, 50,
            12, 48, 139, 181, 39, 84, 166, 244, 43, 50, 26, 135, 70, 255, 94, 190,
            4, 72, 182, 5, 120, 129, 179, 102, 7, 99, 41, 42, 102, 22, 59, 255,
        ],
        [
            16, 253, 73, 123, 217, 104, 76, 172, 246, 222, 148, 12, 157, 189, 176, 72,
            152, 132, 144, 179, 119, 244, 115, 23, 19, 108, 105, 11, 130, 118, 67, 25,
            43, 231, 31, 143, 192, 174, 117, 237, 215, 159, 162, 166, 57, 203, 200, 55,
            23, 252, 65, 209, 199, 25, 46, 68, 102, 44, 142, 108, 36, 184, 164, 65,
        ],
    ],
};

#[program]
pub mod attestto_vlei_sbt {
    use super::*;

    /// Create a new vLEI attestation PDA with on-chain ZK proof verification.
    ///
    /// PDA seeds: `['vlei-attestation', lei_hash, subject_aid]` where
    /// `lei_hash` = SHA-256(LEI number) and `subject_aid` = SHA-256(KERI AID).
    /// Adding `subject_aid` prevents PDA collision when multiple officers
    /// hold credentials under the same LEI.
    ///
    /// The Groth16 proof is verified on-chain before the attestation is written.
    /// After verification, only the proof hash is stored to minimize rent.
    ///
    /// Only the authorized `authority` (Attestto fee payer) can call this.
    pub fn create_attestation(
        ctx: Context<CreateAttestation>,
        lei_hash: [u8; 32],
        subject_aid: [u8; 32],
        proof_a: [u8; 64],
        proof_b: [u8; 128],
        proof_c: [u8; 64],
        public_signals: [[u8; 32]; NR_PUBLIC_INPUTS],
        attested_at: i64,
        expires_at: i64,
        metadata_uri: String,
    ) -> Result<()> {
        let attestation = &mut ctx.accounts.attestation;

        require!(
            metadata_uri.len() <= MAX_METADATA_URI_LEN,
            VleiError::MetadataUriTooLong
        );
        require!(expires_at > attested_at, VleiError::InvalidExpiry);

        // ── On-chain Groth16 ZK proof verification ──────────────────────────
        let mut verifier = Groth16Verifier::new(
            &proof_a,
            &proof_b,
            &proof_c,
            &public_signals,
            &VERIFYING_KEY,
        )
        .map_err(|_| VleiError::InvalidZkProof)?;

        verifier
            .verify()
            .map_err(|_| VleiError::InvalidZkProof)?;
        // ────────────────────────────────────────────────────────────────────

        // Compute proof hash for compact on-chain storage
        let proof_bytes = [
            proof_a.as_ref(),
            proof_b.as_ref(),
            proof_c.as_ref(),
        ]
        .concat();
        let zkp_proof_hash: [u8; 32] = Sha256::digest(&proof_bytes).into();

        attestation.flag = FLAG_ACTIVE;
        attestation.lei_hash = lei_hash;
        attestation.subject_aid = subject_aid;
        attestation.zkp_proof_hash = zkp_proof_hash;
        attestation.public_signals = public_signals;
        attestation.attested_at = attested_at;
        attestation.expires_at = expires_at;
        attestation.metadata_uri_len = metadata_uri.len() as u16;
        attestation.metadata_uri = metadata_uri;
        attestation.authority = ctx.accounts.authority.key();
        attestation.bump = ctx.bumps.attestation;
        attestation.pq_identity_root_set = false;
        attestation.pq_identity_root = [0u8; 64];

        emit!(AttestationCreated {
            lei_hash,
            subject_aid,
            authority: ctx.accounts.authority.key(),
            attested_at,
            expires_at,
        });

        msg!(
            "vLEI attestation created with ZK proof verified: attested_at={}, expires_at={}",
            attested_at,
            expires_at
        );

        Ok(())
    }

    /// Set the post-quantum identity root on an existing attestation.
    ///
    /// The `pq_identity_root` is a 64-byte hash (SHA-512 or SHAKE-256) of the
    /// ML-DSA-65 (Dilithium) public key associated with this credential subject.
    /// Storing the hash instead of the full key (1312 bytes) keeps rent costs low
    /// while enabling future PQ verification by comparing against the hash.
    ///
    /// Only the original authority can set this field.
    pub fn set_pq_identity_root(
        ctx: Context<UpdateAttestation>,
        pq_identity_root: [u8; 64],
    ) -> Result<()> {
        let attestation = &mut ctx.accounts.attestation;

        require!(
            attestation.flag == FLAG_ACTIVE,
            VleiError::AlreadyRevoked
        );

        attestation.pq_identity_root = pq_identity_root;
        attestation.pq_identity_root_set = true;

        emit!(PqIdentityRootSet {
            lei_hash: attestation.lei_hash,
            subject_aid: attestation.subject_aid,
            authority: ctx.accounts.authority.key(),
        });

        msg!("PQ identity root set for attestation");

        Ok(())
    }

    /// Revoke an existing vLEI attestation by setting the flag to 0x01.
    ///
    /// Only the original `authority` that created the attestation can revoke it.
    /// Once revoked, any DeFi protocol reading the PDA will see `flag = 0x01`
    /// and reject the attestation.
    pub fn revoke_attestation(ctx: Context<RevokeAttestation>) -> Result<()> {
        let attestation = &mut ctx.accounts.attestation;

        require!(
            attestation.flag == FLAG_ACTIVE,
            VleiError::AlreadyRevoked
        );

        attestation.flag = FLAG_REVOKED;

        emit!(AttestationRevoked {
            lei_hash: attestation.lei_hash,
            subject_aid: attestation.subject_aid,
            authority: ctx.accounts.authority.key(),
            revoked_at: Clock::get()?.unix_timestamp,
        });

        msg!("vLEI attestation revoked");

        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ACCOUNTS
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Accounts)]
#[instruction(lei_hash: [u8; 32], subject_aid: [u8; 32])]
pub struct CreateAttestation<'info> {
    /// The attestation PDA account to be created.
    /// Seeds: ['vlei-attestation', lei_hash, subject_aid]
    #[account(
        init,
        payer = authority,
        space = VleiAttestation::space(MAX_METADATA_URI_LEN),
        seeds = [PDA_SEED_PREFIX, &lei_hash, &subject_aid],
        bump,
    )]
    pub attestation: Account<'info, VleiAttestation>,

    /// The authorized fee payer (Attestto backend).
    /// Must be a signer — only Attestto can create attestations.
    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateAttestation<'info> {
    /// The attestation PDA to update.
    #[account(
        mut,
        has_one = authority @ VleiError::UnauthorizedRevocation,
    )]
    pub attestation: Account<'info, VleiAttestation>,

    /// Must be the same authority that created the attestation.
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct RevokeAttestation<'info> {
    /// The attestation PDA to revoke.
    #[account(
        mut,
        has_one = authority @ VleiError::UnauthorizedRevocation,
    )]
    pub attestation: Account<'info, VleiAttestation>,

    /// Must be the same authority that created the attestation.
    pub authority: Signer<'info>,
}

// ═══════════════════════════════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════════════════════════════

/// On-chain attestation account data.
///
/// Layout (Anchor-serialized with Borsh):
///   [flag 1B] [lei_hash 32B] [subject_aid 32B] [zkp_proof_hash 32B]
///   [public_signals 128B] [attested_at 8B] [expires_at 8B]
///   [metadata_uri_len 2B] [metadata_uri String]
///   [authority 32B] [bump 1B]
///   [pq_identity_root_set 1B] [pq_identity_root 64B]
#[account]
pub struct VleiAttestation {
    /// 0x00 = active, 0x01 = revoked
    pub flag: u8,

    /// SHA-256 hash of the LEI number (20-char string)
    pub lei_hash: [u8; 32],

    /// SHA-256 hash of the KERI AID of the credential subject.
    /// Included in PDA seeds to prevent collision for same-LEI officers.
    pub subject_aid: [u8; 32],

    /// SHA-256 hash of the concatenated Groth16 proof (proof_a || proof_b || proof_c).
    /// The full proof is verified on-chain during `create_attestation` but only the
    /// hash is stored to minimize rent costs.
    pub zkp_proof_hash: [u8; 32],

    /// The 4 public signals from the ZK proof, stored for audit.
    /// [0] currentTimestamp, [1] credentialHashCommitment,
    /// [2] walletPubkeyHash, [3] minRoleLevel
    pub public_signals: [[u8; 32]; 4],

    /// Unix timestamp when the attestation was created
    pub attested_at: i64,

    /// Unix timestamp when the attestation expires
    pub expires_at: i64,

    /// Length of the metadata URI string
    pub metadata_uri_len: u16,

    /// Off-chain metadata URI (e.g., Arweave/IPFS link to JSON)
    pub metadata_uri: String,

    /// The authority (Attestto fee payer) that created this attestation.
    /// Only this pubkey can revoke it.
    pub authority: Pubkey,

    /// PDA bump seed for re-derivation
    pub bump: u8,

    /// Whether `pq_identity_root` has been set.
    pub pq_identity_root_set: bool,

    /// Post-quantum identity root — SHA-512 or SHAKE-256 hash of the
    /// ML-DSA-65 (Dilithium) public key. Set to zero initially; populated
    /// via `set_pq_identity_root` when PQ keys are provisioned.
    /// Storing a 64-byte hash instead of the full 1312-byte key keeps
    /// rent costs manageable while enabling PQ identity binding.
    pub pq_identity_root: [u8; 64],
}

impl VleiAttestation {
    /// Calculate account space for a given max metadata URI length.
    ///
    /// Anchor discriminator (8) + flag (1) + lei_hash (32) + subject_aid (32)
    /// + zkp_proof_hash (32) + public_signals (128) + attested_at (8) + expires_at (8)
    /// + metadata_uri_len (2) + metadata_uri (4 + max_len) + authority (32) + bump (1)
    /// + pq_identity_root_set (1) + pq_identity_root (64)
    pub fn space(max_metadata_uri_len: usize) -> usize {
        8     // Anchor discriminator
        + 1   // flag
        + 32  // lei_hash
        + 32  // subject_aid
        + 32  // zkp_proof_hash
        + 128 // public_signals (4 × 32)
        + 8   // attested_at
        + 8   // expires_at
        + 2   // metadata_uri_len
        + 4 + max_metadata_uri_len // String (4-byte length prefix + content)
        + 32  // authority
        + 1   // bump
        + 1   // pq_identity_root_set
        + 64  // pq_identity_root
    }

    /// Check if this attestation is currently valid.
    pub fn is_valid(&self, current_timestamp: i64) -> bool {
        self.flag == FLAG_ACTIVE && self.expires_at > current_timestamp
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// EVENTS
// ═══════════════════════════════════════════════════════════════════════════

#[event]
pub struct AttestationCreated {
    pub lei_hash: [u8; 32],
    pub subject_aid: [u8; 32],
    pub authority: Pubkey,
    pub attested_at: i64,
    pub expires_at: i64,
}

#[event]
pub struct AttestationRevoked {
    pub lei_hash: [u8; 32],
    pub subject_aid: [u8; 32],
    pub authority: Pubkey,
    pub revoked_at: i64,
}

#[event]
pub struct PqIdentityRootSet {
    pub lei_hash: [u8; 32],
    pub subject_aid: [u8; 32],
    pub authority: Pubkey,
}

// ═══════════════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════════════

#[error_code]
pub enum VleiError {
    #[msg("Metadata URI exceeds maximum length of 2048 bytes")]
    MetadataUriTooLong,

    #[msg("Expiry timestamp must be after attestation timestamp")]
    InvalidExpiry,

    #[msg("Attestation is already revoked")]
    AlreadyRevoked,

    #[msg("Only the original authority can revoke this attestation")]
    UnauthorizedRevocation,

    #[msg("ZK proof verification failed — invalid proof or public signals")]
    InvalidZkProof,
}
