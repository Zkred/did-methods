import { describe, expect, it } from "vitest";
import { placeholderMbHash, parseMbHash } from "../src/multiformat.js";
import { proofSigningInput, verifyDocumentSelfHash } from "../src/selfhash.js";
import { validProofKeys } from "../src/verifier.js";
import { evaluateUpdateRules } from "../src/updateRules.js";
import { DID, rootDoc, secondDoc } from "./fixtures/microledger.js";
import { blake3RootDoc, sha224RootDoc } from "./fixtures/hash-function-vectors.js";

describe("multiformat", () => {
  it("parses BLAKE3 multihashes from reference vectors", () => {
    const parsed = parseMbHash(rootDoc.selfHash);
    expect(parsed.code).toBe(0x1e);
    expect(parsed.length).toBe(32);
  });

  it("parses SHA2-224 multihashes from reference vectors", () => {
    const parsed = parseMbHash(sha224RootDoc.selfHash);
    expect(parsed.code).toBe(0x1013);
    expect(parsed.length).toBe(28);
  });

  it("builds the all-zeros placeholder for a hash function", () => {
    const placeholder = placeholderMbHash(rootDoc.selfHash);
    const parsed = parseMbHash(placeholder);
    expect(parsed.code).toBe(0x1e);
    expect(Array.from(parsed.digest).every((b) => b === 0)).toBe(true);
    expect(placeholder).toMatch(/^uHiA/);
  });
});

describe("self-hash verification against Rust reference vectors", () => {
  it("verifies the microledger example root document (BLAKE3)", () => {
    expect(verifyDocumentSelfHash(rootDoc)).toEqual({ valid: true });
  });

  it("verifies the microledger example non-root document (BLAKE3)", () => {
    expect(verifyDocumentSelfHash(secondDoc)).toEqual({ valid: true });
  });

  it("verifies the hash-function-selection root document (BLAKE3, with proofs)", () => {
    expect(verifyDocumentSelfHash(blake3RootDoc)).toEqual({ valid: true });
  });

  it("verifies the hash-function-selection root document (SHA2-224, with proofs)", () => {
    expect(verifyDocumentSelfHash(sha224RootDoc)).toEqual({ valid: true });
  });

  it("rejects a tampered document", () => {
    const tampered = structuredClone(rootDoc);
    tampered.validFrom = "2025-11-19T01:43:27.000Z";
    const result = verifyDocumentSelfHash(tampered);
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/computed self-hash/);
  });

  it("rejects mismatched self-hash slots", () => {
    const tampered = structuredClone(secondDoc);
    tampered.verificationMethod = structuredClone(rootDoc.verificationMethod);
    const result = verifyDocumentSelfHash(tampered);
    expect(result.valid).toBe(false);
  });
});

describe("proof verification against Rust reference vectors", () => {
  it("verifies the Ed25519 JWS proof on the microledger update (versionId 1)", () => {
    const keys = validProofKeys(secondDoc);
    expect(keys).toEqual(["u7QG2O2Vm22e1g4v6VRxjY9Qgm9XqJAKf_b3cH6Oc4R0bhw"]);
  });

  it("the valid proof key satisfies the root document's hashedKey updateRules", () => {
    const keys = validProofKeys(secondDoc);
    expect(evaluateUpdateRules(rootDoc.updateRules!, keys)).toBe(true);
  });

  it("verifies the root-level proofs from the hash-function-selection vectors", () => {
    expect(validProofKeys(blake3RootDoc)).toEqual([
      "u7QHLEZwETcmBt6ikJvzRI7puzIiK-CpCp9FTtI5xOUy4Ow",
    ]);
    expect(validProofKeys(sha224RootDoc)).toEqual([
      "u7QFCJ3tyvQdSwGJk8berxy9n083_qp0q27gszGboiGCLDg",
    ]);
  });

  it("rejects a proof whose payload was tampered with", () => {
    const tampered = structuredClone(secondDoc);
    tampered.updateRules = { key: "u7QG2O2Vm22e1g4v6VRxjY9Qgm9XqJAKf_b3cH6Oc4R0bhw" };
    expect(validProofKeys(tampered)).toEqual([]);
  });

  it("proof signing input excludes proofs and uses placeholder hashes", () => {
    const input = new TextDecoder().decode(proofSigningInput(secondDoc));
    expect(input).not.toContain("proofs");
    expect(input).not.toContain(secondDoc.selfHash);
    expect(input).toContain(placeholderMbHash(secondDoc.selfHash));
    // the base DID (root self-hash) is primary data, not a slot, in non-root docs
    expect(input).toContain(DID);
  });
});

describe("evaluateUpdateRules", () => {
  const KEY = "u7QG2O2Vm22e1g4v6VRxjY9Qgm9XqJAKf_b3cH6Oc4R0bhw";
  const OTHER = "u7QHLEZwETcmBt6ikJvzRI7puzIiK-CpCp9FTtI5xOUy4Ow";

  it("evaluates key rules by exact match", () => {
    expect(evaluateUpdateRules({ key: KEY }, [KEY])).toBe(true);
    expect(evaluateUpdateRules({ key: KEY }, [OTHER])).toBe(false);
  });

  it("evaluates any/all composition", () => {
    expect(evaluateUpdateRules({ any: [{ key: KEY }, { key: OTHER }] }, [OTHER])).toBe(true);
    expect(evaluateUpdateRules({ all: [{ key: KEY }, { key: OTHER }] }, [OTHER])).toBe(false);
    expect(evaluateUpdateRules({ all: [{ key: KEY }, { key: OTHER }] }, [KEY, OTHER])).toBe(true);
  });

  it("evaluates weighted thresholds", () => {
    const rules = { atLeast: 3, of: [{ key: KEY, weight: 2 }, { key: OTHER }] };
    expect(evaluateUpdateRules(rules, [KEY])).toBe(false);
    expect(evaluateUpdateRules(rules, [KEY, OTHER])).toBe(true);
  });

  it("treats an empty object as updates-disallowed", () => {
    expect(evaluateUpdateRules({}, [KEY])).toBe(false);
  });

  it("rejects unknown rule forms", () => {
    expect(() => evaluateUpdateRules({ bogus: true } as never, [KEY])).toThrow(/unrecognized/);
  });
});