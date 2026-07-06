import { describe, expect, it } from "vitest";
import { validateMicroledger } from "../src/microledger.js";
import { DID, rootDoc, secondDoc } from "./fixtures/microledger.js";

describe("validateMicroledger", () => {
  it("accepts the reference implementation's example microledger", async () => {
    const result = await validateMicroledger([rootDoc, secondDoc], { expectedDid: DID });
    expect(result.errors).toEqual([]);
    expect(result.valid).toBe(true);
  });

  it("rejects an empty microledger", async () => {
    const result = await validateMicroledger([]);
    expect(result.valid).toBe(false);
  });

  it("rejects a root document whose selfHash does not match the DID", async () => {
    const badRoot = { ...rootDoc, selfHash: "uHiCH05FmexvfpT8lxesItafqipzHvm_npUt4PRRCc8scEw" };
    const result = await validateMicroledger([badRoot], { expectedDid: DID });
    expect(result.valid).toBe(false);
    expect(result.errors[0]?.message).toMatch(/does not match DID component/);
  });

  it("rejects a broken hash chain", async () => {
    const broken = { ...secondDoc, prevDIDDocumentSelfHash: "uHiC_wrong_hash_wrong_hash_wrong_hash_wrongAAA" };
    const result = await validateMicroledger([rootDoc, broken], { expectedDid: DID });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.message.includes("prevDIDDocumentSelfHash"))).toBe(true);
  });

  it("rejects non-contiguous versionIds", async () => {
    const skipped = { ...secondDoc, versionId: 2 };
    const result = await validateMicroledger([rootDoc, skipped], { expectedDid: DID });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.message.includes("expected versionId 1"))).toBe(true);
  });

  it("rejects a non-root document without proofs", async () => {
    const { proofs: _proofs, ...withoutProofs } = secondDoc;
    const result = await validateMicroledger([rootDoc, withoutProofs], { expectedDid: DID });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.message.includes("proof"))).toBe(true);
  });

  it("rejects non-increasing validFrom timestamps", async () => {
    const stale = { ...secondDoc, validFrom: rootDoc.validFrom };
    const result = await validateMicroledger([rootDoc, stale], { expectedDid: DID });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.message.includes("validFrom"))).toBe(true);
  });

  it("invokes a supplied CryptoVerifier and surfaces its failures", async () => {
    const result = await validateMicroledger([rootDoc, secondDoc], {
      expectedDid: DID,
      verifier: {
        verifySelfHash: async () => true,
        verifyProofs: async () => false,
      },
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.message.includes("updateRules"))).toBe(true);
  });
});