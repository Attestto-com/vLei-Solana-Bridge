import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { AttesttoVleiSbt } from "../target/types/attestto_vlei_sbt";
import { createHash } from "crypto";
import { expect } from "chai";

describe("attestto-vlei-sbt", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.AttesttoVleiSbt as Program<AttesttoVleiSbt>;

  const leiNumber = "9845008661B99CC9FD07";
  const leiHash = createHash("sha256").update(leiNumber).digest();
  const leiHashArray = Array.from(leiHash) as number[];

  const subjectAidStr = "EBfxc4RiVY6GXCJov8YQs-qqjOP-uck06NHHzWy-sE9B";
  const subjectAid = createHash("sha256").update(subjectAidStr).digest();
  const subjectAidArray = Array.from(subjectAid) as number[];

  // Dummy Groth16 proof components (64 + 128 + 64 = 256 bytes)
  const proofA = Array.from(Buffer.alloc(64, 0x01)) as number[];
  const proofB = Array.from(Buffer.alloc(128, 0x02)) as number[];
  const proofC = Array.from(Buffer.alloc(64, 0x03)) as number[];

  // 4 public signals — 32 bytes each
  const publicSignals = [
    Array.from(Buffer.alloc(32, 0x10)),
    Array.from(Buffer.alloc(32, 0x20)),
    Array.from(Buffer.alloc(32, 0x30)),
    Array.from(Buffer.alloc(32, 0x40)),
  ] as number[][];

  const now = Math.floor(Date.now() / 1000);
  const oneYearFromNow = now + 365 * 24 * 60 * 60;
  const metadataUri = "https://attestto.com/meta/test.json";

  function derivePda(lei: string, aid: string): [anchor.web3.PublicKey, number] {
    const hash = createHash("sha256").update(lei).digest();
    const aidHash = createHash("sha256").update(aid).digest();
    return anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("vlei-attestation"), hash, aidHash],
      program.programId
    );
  }

  it("creates an attestation PDA with ZK proof verification", async () => {
    const [pda] = derivePda(leiNumber, subjectAidStr);

    await program.methods
      .createAttestation(
        leiHashArray,
        subjectAidArray,
        proofA,
        proofB,
        proofC,
        publicSignals,
        new anchor.BN(now),
        new anchor.BN(oneYearFromNow),
        metadataUri
      )
      .accounts({
        attestation: pda,
        authority: provider.wallet.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const account = await program.account.vleiAttestation.fetch(pda);

    expect(account.flag).to.equal(0x00); // active
    expect(Buffer.from(account.leiHash)).to.deep.equal(leiHash);
    expect(Buffer.from(account.subjectAid)).to.deep.equal(subjectAid);
    expect(account.attestedAt.toNumber()).to.equal(now);
    expect(account.expiresAt.toNumber()).to.equal(oneYearFromNow);
    expect(account.metadataUri).to.equal(metadataUri);
    expect(account.metadataUriLen).to.equal(metadataUri.length);
    expect(account.authority.toBase58()).to.equal(
      provider.wallet.publicKey.toBase58()
    );
    expect(account.pqIdentityRootSet).to.equal(false);
  });

  it("sets PQ identity root on an active attestation", async () => {
    const [pda] = derivePda(leiNumber, subjectAidStr);
    const pqRoot = Array.from(Buffer.alloc(64, 0xAB)) as number[];

    await program.methods
      .setPqIdentityRoot(pqRoot)
      .accounts({
        attestation: pda,
        authority: provider.wallet.publicKey,
      })
      .rpc();

    const account = await program.account.vleiAttestation.fetch(pda);
    expect(account.pqIdentityRootSet).to.equal(true);
    expect(Buffer.from(account.pqIdentityRoot)).to.deep.equal(Buffer.alloc(64, 0xAB));
  });

  it("revokes an attestation", async () => {
    const [pda] = derivePda(leiNumber, subjectAidStr);

    await program.methods
      .revokeAttestation()
      .accounts({
        attestation: pda,
        authority: provider.wallet.publicKey,
      })
      .rpc();

    const account = await program.account.vleiAttestation.fetch(pda);
    expect(account.flag).to.equal(0x01); // revoked
  });

  it("rejects double revocation", async () => {
    const [pda] = derivePda(leiNumber, subjectAidStr);

    try {
      await program.methods
        .revokeAttestation()
        .accounts({
          attestation: pda,
          authority: provider.wallet.publicKey,
        })
        .rpc();
      expect.fail("Should have thrown");
    } catch (err: any) {
      expect(err.toString()).to.include("AlreadyRevoked");
    }
  });

  it("rejects unauthorized revocation", async () => {
    const lei2 = "529900T8BM49AURSDO55";
    const lei2Hash = createHash("sha256").update(lei2).digest();
    const lei2HashArray = Array.from(lei2Hash) as number[];
    const aid2 = "EKYLRMhg0qIYA-H2FjEEL8xSIPxabxK6v_fMOvKKHZbi";
    const aid2Hash = createHash("sha256").update(aid2).digest();
    const aid2HashArray = Array.from(aid2Hash) as number[];
    const [pda2] = derivePda(lei2, aid2);

    await program.methods
      .createAttestation(
        lei2HashArray,
        aid2HashArray,
        proofA,
        proofB,
        proofC,
        publicSignals,
        new anchor.BN(now),
        new anchor.BN(oneYearFromNow),
        ""
      )
      .accounts({
        attestation: pda2,
        authority: provider.wallet.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const attacker = anchor.web3.Keypair.generate();

    try {
      await program.methods
        .revokeAttestation()
        .accounts({
          attestation: pda2,
          authority: attacker.publicKey,
        })
        .signers([attacker])
        .rpc();
      expect.fail("Should have thrown");
    } catch (err: any) {
      expect(err.toString()).to.include("UnauthorizedRevocation");
    }
  });

  it("rejects invalid expiry (expires_at <= attested_at)", async () => {
    const lei3 = "INVALIDEXPIRYTESTLEI";
    const lei3Hash = createHash("sha256").update(lei3).digest();
    const lei3HashArray = Array.from(lei3Hash) as number[];
    const aid3 = "EINVALIDEXPIRYAIDTEST";
    const aid3Hash = createHash("sha256").update(aid3).digest();
    const aid3HashArray = Array.from(aid3Hash) as number[];
    const [pda3] = derivePda(lei3, aid3);

    try {
      await program.methods
        .createAttestation(
          lei3HashArray,
          aid3HashArray,
          proofA,
          proofB,
          proofC,
          publicSignals,
          new anchor.BN(now),
          new anchor.BN(now - 100),
          ""
        )
        .accounts({
          attestation: pda3,
          authority: provider.wallet.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc();
      expect.fail("Should have thrown");
    } catch (err: any) {
      expect(err.toString()).to.include("InvalidExpiry");
    }
  });

  it("rejects metadata URI exceeding max length", async () => {
    const lei4 = "TOOLONGMETADATATEST00";
    const lei4Hash = createHash("sha256").update(lei4).digest();
    const lei4HashArray = Array.from(lei4Hash) as number[];
    const aid4 = "ETOOLONGMETAURIAIDTST";
    const aid4Hash = createHash("sha256").update(aid4).digest();
    const aid4HashArray = Array.from(aid4Hash) as number[];
    const [pda4] = derivePda(lei4, aid4);

    const longUri = "x".repeat(2049);

    try {
      await program.methods
        .createAttestation(
          lei4HashArray,
          aid4HashArray,
          proofA,
          proofB,
          proofC,
          publicSignals,
          new anchor.BN(now),
          new anchor.BN(oneYearFromNow),
          longUri
        )
        .accounts({
          attestation: pda4,
          authority: provider.wallet.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc();
      expect.fail("Should have thrown");
    } catch (err: any) {
      expect(err.toString()).to.include("MetadataUriTooLong");
    }
  });
});
