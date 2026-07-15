import { describe, expect, it } from "vitest";
import { canonicalize } from "@zkred/did-core";
import { fetchMicroledger, resolve } from "../src/resolver.js";
import { validateMicroledgerBytes, parseJcsCanonicalLines } from "../src/microledger.js";
import { DID, rootDoc, secondDoc } from "./fixtures/microledger.js";
import { createDidDocument, hashedKeyRule, updateDidDocument, keyRule } from "../src/controller.js";
import { ed25519KeyPair } from "../src/sign.js";

const LEDGER_URL = `https://example.com/${rootDoc.selfHash}/did-documents.jsonl`;

/** Re-serialize a JSON object with reversed key order: semantically equal, byte-different. */
function reverseKeys(doc: unknown): string {
  return JSON.stringify(Object.fromEntries(Object.entries(doc as object).reverse()));
}

function rawFetch(body: string, url = LEDGER_URL): typeof fetch {
  return (async (input: RequestInfo | URL) =>
    String(input) === url
      ? new Response(body, { status: 200 })
      : new Response("not found", { status: 404 })) as typeof fetch;
}

const canonicalLedger = [rootDoc, secondDoc].map((d) => canonicalize(d)).join("\n");
const permutedLedger = [canonicalize(rootDoc), reverseKeys(secondDoc)].join("\n");
const whitespaceLedger = [canonicalize(rootDoc), " " + canonicalize(secondDoc)].join("\n");

describe("JCS wire-format enforcement (spec: document must equal its JCS serialization)", () => {
  it("fetchMicroledger rejects a key-order-permuted line", async () => {
    await expect(
      fetchMicroledger(DID, { fetchImpl: rawFetch(permutedLedger) }),
    ).rejects.toThrow(/not-jcs-canonical/);
  });

  it("fetchMicroledger rejects insignificant whitespace inside a line", async () => {
    await expect(
      fetchMicroledger(DID, { fetchImpl: rawFetch(whitespaceLedger) }),
    ).rejects.toThrow(/not-jcs-canonical/);
  });

  it("fetchMicroledger accepts canonical lines, including CRLF transport", async () => {
    const crlf = [rootDoc, secondDoc].map((d) => canonicalize(d)).join("\r\n") + "\r\n";
    const docs = await fetchMicroledger(DID, { fetchImpl: rawFetch(crlf) });
    expect(docs.map((d) => d.versionId)).toEqual([0, 1]);
  });

  it("resolve(verify: true) surfaces the violation as invalidDidDocument", async () => {
    const result = await resolve(DID, { verify: true, fetchImpl: rawFetch(permutedLedger) });
    expect(result.didResolutionMetadata.error).toBe("invalidDidDocument");
    expect(result.didResolutionMetadata.message).toMatch(/not-jcs-canonical/);
    expect(result.didDocument).toBeNull();
  });
});

describe("validateMicroledgerBytes", () => {
  it("rejects a key-order-permuted line, naming the versionId", async () => {
    const result = await validateMicroledgerBytes(permutedLedger, { expectedDid: DID });
    expect(result.valid).toBe(false);
    expect(
      result.errors.some((e) => e.versionId === 1 && e.message.includes("not-jcs-canonical")),
    ).toBe(true);
  });

  it("rejects extra whitespace even though parsing succeeds", async () => {
    const result = await validateMicroledgerBytes(whitespaceLedger, { expectedDid: DID });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.message.includes("not-jcs-canonical"))).toBe(true);
  });

  it("accepts the reference fixture ledger in canonical form", async () => {
    const result = await validateMicroledgerBytes(canonicalLedger, { expectedDid: DID });
    expect(result.errors).toEqual([]);
    expect(result.valid).toBe(true);
  });

  it("round-trips the package's own controller output", async () => {
    const seed = (n: number) => Uint8Array.from({ length: 32 }, (_, i) => (i * 17 + n + 3) & 0xff);
    const vmKey = ed25519KeyPair(seed(1));
    const updateKey = ed25519KeyPair(seed(2));
    const root = createDidDocument({
      host: "example.com",
      keys: [{ publicKey: vmKey.publicKey }],
      updateRules: hashedKeyRule(updateKey.publicKey),
      validFrom: "2026-07-15T00:00:00.000Z",
    });
    const next = updateDidDocument(root, {
      keys: [{ publicKey: vmKey.publicKey }],
      updateRules: keyRule(vmKey.publicKey),
      signers: [updateKey],
      validFrom: "2026-07-15T00:00:01.000Z",
    });
    const jsonl = [root, next].map((d) => canonicalize(d)).join("\n") + "\n";
    const result = await validateMicroledgerBytes(jsonl);
    expect(result.errors).toEqual([]);
  });

  it("flags unparseable lines as invalid JSON", () => {
    const { errors } = parseJcsCanonicalLines('{"a":1}\nnot json\n');
    expect(errors.some((e) => e.message.includes("not valid JSON"))).toBe(true);
  });
});