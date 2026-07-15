import { describe, expect, it } from "vitest";
import { canonicalize } from "@zkred/did-core";
import {
  createDidDocument,
  deactivateDidDocument,
  hashedKeyRule,
  keyRule,
  registerDid,
  updateDidDocument,
} from "../src/controller.js";
import { ed25519KeyPair } from "../src/sign.js";
import { verifyDocumentSelfHash } from "../src/selfhash.js";
import { validateMicroledger } from "../src/microledger.js";
import { parseMbHash, hashWithFunction, type HashFunctionName } from "../src/multiformat.js";
import { utf8Encode } from "@zkred/did-core";

const seed = (n: number) => Uint8Array.from({ length: 32 }, (_, i) => (i * 13 + n + 2) & 0xff);
const vmKey = ed25519KeyPair(seed(1));
const updateKey = ed25519KeyPair(seed(2));

describe("SHA3 hash function support", () => {
  const cases: Array<[HashFunctionName, number, number]> = [
    ["sha3-512", 0x14, 64],
    ["sha3-384", 0x15, 48],
    ["sha3-256", 0x16, 32],
    ["sha3-224", 0x17, 28],
  ];

  it.each(cases)("computes and verifies %s MBHash values", (name, code, digestLength) => {
    const mbHash = hashWithFunction(name, utf8Encode("did:webplus sha3 support"));
    const parsed = parseMbHash(mbHash);
    expect(parsed.code).toBe(code);
    expect(parsed.digest).toHaveLength(digestLength);
  });

  it.each(cases)("self-hashes DID documents with %s", async (name) => {
    const root = createDidDocument({
      host: "example.com",
      keys: [{ publicKey: vmKey.publicKey }],
      updateRules: keyRule(updateKey.publicKey),
      validFrom: "2026-07-14T00:00:00.000Z",
      hashFunction: name,
    });
    expect(verifyDocumentSelfHash(root)).toEqual({ valid: true });
    expect((await validateMicroledger([root])).errors).toEqual([]);
  });
});

describe("JCS wire serialization", () => {
  it("POSTs the JCS form of the DID document, not insertion-order JSON", async () => {
    let body: string | undefined;
    const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      body = String(init?.body);
      return new Response("", { status: 200 });
    }) as typeof fetch;

    const root = createDidDocument({
      host: "example.com",
      keys: [{ publicKey: vmKey.publicKey }],
      updateRules: hashedKeyRule(updateKey.publicKey),
      validFrom: "2026-07-14T00:00:00.000Z",
    });
    await registerDid(root, { fetchImpl });

    expect(body).toBe(canonicalize(root));
    // sanity: JCS ordering differs from the document's insertion order
    expect(body).not.toBe(JSON.stringify(root));
    // and the payload still parses back to the same document
    expect(JSON.parse(body!)).toEqual(JSON.parse(JSON.stringify(root)));
  });
});

describe("deactivateDidDocument", () => {
  const root = createDidDocument({
    host: "example.com",
    keys: [{ publicKey: vmKey.publicKey }],
    updateRules: keyRule(updateKey.publicKey),
    validFrom: "2026-07-14T00:00:00.000Z",
  });
  const tombstone = deactivateDidDocument(root, {
    signers: [updateKey],
    validFrom: "2026-07-14T00:00:01.000Z",
  });

  it("produces the spec's tombstone shape", () => {
    expect(tombstone.updateRules).toEqual({});
    expect(tombstone.verificationMethod).toEqual([]);
    expect(tombstone.authentication).toEqual([]);
    expect(tombstone.assertionMethod).toEqual([]);
    expect(tombstone.keyAgreement).toEqual([]);
    expect(tombstone.capabilityInvocation).toEqual([]);
    expect(tombstone.capabilityDelegation).toEqual([]);
    expect(tombstone.versionId).toBe(1);
  });

  it("passes full microledger verification", async () => {
    expect((await validateMicroledger([root, tombstone])).errors).toEqual([]);
  });

  it("permanently blocks further updates", async () => {
    const zombie = updateDidDocument(tombstone, {
      keys: [{ publicKey: vmKey.publicKey }],
      updateRules: keyRule(vmKey.publicKey),
      signers: [updateKey, vmKey],
      validFrom: "2026-07-14T00:00:02.000Z",
    });
    const result = await validateMicroledger([root, tombstone, zombie]);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.message.includes("updateRules"))).toBe(true);
  });
});