import { describe, expect, it } from "vitest";
import {
  createDidDocument,
  hashedKeyRule,
  keyRule,
  microledgerUrl,
  registerDid,
  submitDidUpdate,
  updateDidDocument,
} from "../src/controller.js";
import { ed25519KeyPair } from "../src/sign.js";
import { parseDid } from "../src/did.js";
import { validateMicroledger } from "../src/microledger.js";
import { verifyDocumentSelfHash } from "../src/selfhash.js";
import { validProofKeys } from "../src/verifier.js";

const seed = (n: number) => Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + n) & 0xff);
const key0 = ed25519KeyPair(seed(1)); // initial verification key
const updateKey = ed25519KeyPair(seed(2)); // pre-rotated update key
const key1 = ed25519KeyPair(seed(3)); // rotated-in verification key
const strangerKey = ed25519KeyPair(seed(4));

function createRoot(overrides: Partial<Parameters<typeof createDidDocument>[0]> = {}) {
  return createDidDocument({
    host: "example.com",
    keys: [{ publicKey: key0.publicKey }],
    updateRules: hashedKeyRule(updateKey.publicKey),
    validFrom: "2026-07-06T12:00:00.000Z",
    ...overrides,
  });
}

describe("createDidDocument", () => {
  it("creates a root document that passes full cryptographic verification", async () => {
    const root = createRoot();
    expect(root.versionId).toBe(0);
    expect(parseDid(root.id).rootSelfHash).toBe(root.selfHash);
    expect(verifyDocumentSelfHash(root)).toEqual({ valid: true });

    const result = await validateMicroledger([root]);
    expect(result.errors).toEqual([]);
  });

  it("supports ports, paths, SHA-2 hash functions, and root-level proofs", async () => {
    const root = createRoot({
      host: "localhost",
      port: 8085,
      path: ["dids"],
      hashFunction: "sha2-256",
      signers: [key0],
    });
    expect(root.id).toMatch(/^did:webplus:localhost%3A8085:dids:u/);
    expect(verifyDocumentSelfHash(root)).toEqual({ valid: true });
    expect(validProofKeys(root)).toEqual([key0.mbPubKey]);
  });

  it("assigns key purposes per key", () => {
    const root = createRoot({
      keys: [
        { publicKey: key0.publicKey, purposes: ["authentication", "capabilityInvocation"] },
        { publicKey: key1.publicKey, purposes: ["assertionMethod", "keyAgreement"] },
      ],
    });
    expect(root.authentication).toEqual(["#0"]);
    expect(root.assertionMethod).toEqual(["#1"]);
    expect(root.verificationMethod).toHaveLength(2);
  });
});

describe("updateDidDocument", () => {
  it("round-trips: create, rotate keys, and pass full microledger verification", async () => {
    const root = createRoot();
    const next = updateDidDocument(root, {
      keys: [{ publicKey: key1.publicKey }],
      updateRules: keyRule(key1.publicKey),
      signers: [updateKey],
      validFrom: "2026-07-06T12:00:01.000Z",
    });

    expect(next.versionId).toBe(1);
    expect(next.prevDIDDocumentSelfHash).toBe(root.selfHash);
    expect(verifyDocumentSelfHash(next)).toEqual({ valid: true });

    const result = await validateMicroledger([root, next], { expectedDid: root.id });
    expect(result.errors).toEqual([]);

    // and a second update authorized by the rotated-in key rule
    const third = updateDidDocument(next, {
      keys: [{ publicKey: key1.publicKey }],
      updateRules: keyRule(key1.publicKey),
      signers: [key1],
      validFrom: "2026-07-06T12:00:02.000Z",
    });
    expect((await validateMicroledger([root, next, third])).errors).toEqual([]);
  });

  it("rejects an update signed by an unauthorized key", async () => {
    const root = createRoot();
    const forged = updateDidDocument(root, {
      keys: [{ publicKey: strangerKey.publicKey }],
      updateRules: keyRule(strangerKey.publicKey),
      signers: [strangerKey],
      validFrom: "2026-07-06T12:00:01.000Z",
    });
    // the forged document is internally consistent (valid self-hash)...
    expect(verifyDocumentSelfHash(forged)).toEqual({ valid: true });
    // ...but its proofs cannot satisfy the root's updateRules
    const result = await validateMicroledger([root, forged]);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.message.includes("updateRules"))).toBe(true);
  });
});

describe("VDR client", () => {
  it("derives the did-documents.jsonl URL from the DID", () => {
    const root = createRoot({ host: "localhost", port: 8085, path: ["dids"] });
    expect(microledgerUrl(root.id, { scheme: "http" })).toBe(
      `http://localhost:8085/dids/${root.selfHash}/did-documents.jsonl`,
    );
  });

  it("POSTs creations and PUTs updates to the VDR", async () => {
    const requests: Array<{ method?: string; url: string; body?: unknown }> = [];
    const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
      requests.push({
        method: init?.method,
        url: String(input),
        body: JSON.parse(String(init?.body)),
      });
      return new Response("", { status: 200 });
    }) as typeof fetch;

    const root = createRoot();
    await registerDid(root, { fetchImpl });
    const next = updateDidDocument(root, {
      keys: [{ publicKey: key1.publicKey }],
      updateRules: keyRule(key1.publicKey),
      signers: [updateKey],
      validFrom: "2026-07-06T12:00:01.000Z",
    });
    await submitDidUpdate(next, { fetchImpl });

    expect(requests.map((r) => r.method)).toEqual(["POST", "PUT"]);
    expect(requests[0]!.url).toBe(`https://example.com/${root.selfHash}/did-documents.jsonl`);
    expect((requests[1]!.body as { versionId: number }).versionId).toBe(1);
  });

  it("surfaces VDR rejections", async () => {
    const fetchImpl = (async () => new Response("nope", { status: 400 })) as typeof fetch;
    await expect(registerDid(createRoot(), { fetchImpl })).rejects.toThrow(/HTTP 400/);
  });
});