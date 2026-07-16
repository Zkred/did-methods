import { describe, expect, it } from "vitest";
import { canonicalize } from "@zkred/did-core";
import { resolve } from "../src/resolver.js";
import { InMemoryMicroledgerStore } from "../src/store.js";
import { WebplusCryptoVerifier } from "../src/verifier.js";
import type { WebplusDidDocument } from "../src/types.js";
import { createDidDocument, hashedKeyRule, keyRule, updateDidDocument } from "../src/controller.js";
import { ed25519KeyPair } from "../src/sign.js";
import { DID, rootDoc, secondDoc } from "./fixtures/microledger.js";

const LEDGER_URL = `https://example.com/${rootDoc.selfHash}/did-documents.jsonl`;
const jsonl = (docs: WebplusDidDocument[]) => docs.map((d) => canonicalize(d)).join("\n") + "\n";
const byteLen = (s: string) => new TextEncoder().encode(s).length;

/** A fake VDR serving an append-only ledger with HTTP Range support. */
function fakeVdr(getDocs: () => WebplusDidDocument[]) {
  const requests: Array<{ url: string; range?: string }> = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const range = (init?.headers as Record<string, string> | undefined)?.range;
    requests.push({ url, ...(range ? { range } : {}) });
    if (url !== LEDGER_URL) return new Response("not found", { status: 404 });
    const body = jsonl(getDocs());
    if (range) {
      const start = Number(range.replace("bytes=", "").replace("-", ""));
      const total = byteLen(body);
      if (start >= total) return new Response(null, { status: 416 });
      return new Response(new TextEncoder().encode(body).slice(start), { status: 206 });
    }
    return new Response(body, { status: 200 });
  }) as typeof fetch;
  return { fetchImpl, requests };
}

/** Counts cryptographic verifications so incremental behavior is observable. */
class CountingVerifier extends WebplusCryptoVerifier {
  selfHashCalls = 0;
  override async verifySelfHash(doc: WebplusDidDocument): Promise<boolean> {
    this.selfHashCalls += 1;
    return super.verifySelfHash(doc);
  }
}

describe("Full DID Resolver persistence", () => {
  it("re-resolution is a range GET verifying zero new documents", async () => {
    const { fetchImpl, requests } = fakeVdr(() => [rootDoc, secondDoc]);
    const store = new InMemoryMicroledgerStore();
    const verifier = new CountingVerifier();

    await resolve(DID, { store, verifier, fetchImpl });
    const callsAfterFirst = verifier.selfHashCalls;
    expect(callsAfterFirst).toBe(2);

    const result = await resolve(DID, { store, verifier, fetchImpl });
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocumentMetadata.versionId).toBe("1");
    expect(verifier.selfHashCalls).toBe(callsAfterFirst); // nothing re-verified
    expect(requests[1]!.range).toBe(`bytes=${byteLen(jsonl([rootDoc, secondDoc]))}-`);
  });

  it("ledger growth fetches and verifies only the new document", async () => {
    const seed = (n: number) => Uint8Array.from({ length: 32 }, (_, i) => (i * 19 + n + 5) & 0xff);
    const vmKey = ed25519KeyPair(seed(1));
    const updateKey = ed25519KeyPair(seed(2));
    const root = createDidDocument({
      host: "example.com",
      keys: [{ publicKey: vmKey.publicKey }],
      updateRules: hashedKeyRule(updateKey.publicKey),
      validFrom: "2026-07-16T00:00:00.000Z",
    });
    const url = `https://example.com/${root.selfHash}/did-documents.jsonl`;
    const docs: WebplusDidDocument[] = [root];
    const requests: Array<{ range?: string }> = [];
    const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const range = (init?.headers as Record<string, string> | undefined)?.range;
      requests.push(range ? { range } : {});
      if (String(input) !== url) return new Response("nf", { status: 404 });
      const body = jsonl(docs);
      if (range) {
        const start = Number(range.replace("bytes=", "").replace("-", ""));
        if (start >= byteLen(body)) return new Response(null, { status: 416 });
        return new Response(new TextEncoder().encode(body).slice(start), { status: 206 });
      }
      return new Response(body, { status: 200 });
    }) as typeof fetch;

    const store = new InMemoryMicroledgerStore();
    const verifier = new CountingVerifier();
    await resolve(root.id, { store, verifier, fetchImpl });
    expect(verifier.selfHashCalls).toBe(1);

    docs.push(
      updateDidDocument(root, {
        keys: [{ publicKey: vmKey.publicKey }],
        updateRules: keyRule(vmKey.publicKey),
        signers: [updateKey],
        validFrom: "2026-07-16T00:00:01.000Z",
      }),
    );
    const result = await resolve(root.id, { store, verifier, fetchImpl });
    expect(result.didDocumentMetadata.versionId).toBe("1");
    expect(result.didDocumentMetadata.verified).toBe(true);
    expect(verifier.selfHashCalls).toBe(2); // only the new document
  });

  it("serves historical queries offline from the verified store", async () => {
    const { fetchImpl } = fakeVdr(() => [rootDoc, secondDoc]);
    const store = new InMemoryMicroledgerStore();
    await resolve(DID, { store, fetchImpl });

    const offlineFetch = (async () => {
      throw new Error("network down");
    }) as typeof fetch;

    const byVersion = await resolve(`${DID}?versionId=0`, { store, fetchImpl: offlineFetch });
    expect(byVersion.didResolutionMetadata.error).toBeUndefined();
    expect(byVersion.didDocumentMetadata.versionId).toBe("0");
    expect(byVersion.didDocumentMetadata.cached).toBe(true);

    const bySelfHash = await resolve(`${DID}?selfHash=${rootDoc.selfHash}`, {
      store,
      fetchImpl: offlineFetch,
    });
    expect(bySelfHash.didResolutionMetadata.error).toBeUndefined();

    const byTime = await resolve(`${DID}?versionTime=2025-11-19T01:43:26.985Z`, {
      store,
      fetchImpl: offlineFetch,
    });
    expect(byTime.didResolutionMetadata.error).toBeUndefined();
    expect(byTime.didDocumentMetadata.versionId).toBe("0");
  });

  it("detects duplicity when a range update contradicts the verified tip", async () => {
    const store = new InMemoryMicroledgerStore();
    const { fetchImpl } = fakeVdr(() => [rootDoc, secondDoc]);
    await resolve(DID, { store, fetchImpl });

    const forged = structuredClone(secondDoc);
    forged.versionId = 2;
    forged.prevDIDDocumentSelfHash = "uHiC_forged_forged_forged_forged_forgedAAAAAAAA";
    const { fetchImpl: forkFetch } = fakeVdr(() => [rootDoc, secondDoc, forged]);

    const result = await resolve(DID, { store, fetchImpl: forkFetch });
    expect(result.didResolutionMetadata.error).toBe("invalidDidDocument");
    expect(result.didResolutionMetadata.message).toMatch(/duplicity/);
  });

  it("detects duplicity when a full refetch rewrites verified history", async () => {
    const store = new InMemoryMicroledgerStore();
    const { fetchImpl } = fakeVdr(() => [rootDoc, secondDoc]);
    await resolve(DID, { store, fetchImpl });

    const rewritten = structuredClone(rootDoc);
    rewritten.selfHash = secondDoc.selfHash; // history rewrite at versionId 0
    const noRangeFetch = (async (input: RequestInfo | URL) =>
      String(input) === LEDGER_URL
        ? new Response(jsonl([rewritten, secondDoc]), { status: 200 }) // ignores Range
        : new Response("nf", { status: 404 })) as typeof fetch;

    const result = await resolve(DID, { store, fetchImpl: noRangeFetch });
    expect(result.didResolutionMetadata.error).toBe("invalidDidDocument");
    expect(result.didResolutionMetadata.message).toMatch(/duplicity/);
  });

  it("detects rollback: a served ledger shorter than verified history", async () => {
    const store = new InMemoryMicroledgerStore();
    const { fetchImpl } = fakeVdr(() => [rootDoc, secondDoc]);
    await resolve(DID, { store, fetchImpl });

    const truncatedFetch = (async (input: RequestInfo | URL) =>
      String(input) === LEDGER_URL
        ? new Response(jsonl([rootDoc]), { status: 200 })
        : new Response("nf", { status: 404 })) as typeof fetch;

    const result = await resolve(DID, { store, fetchImpl: truncatedFetch });
    expect(result.didResolutionMetadata.error).toBe("invalidDidDocument");
    expect(result.didResolutionMetadata.message).toMatch(/duplicity|shorter/);
  });

  it("store: null disables persistence (no Range header on refetch)", async () => {
    const { fetchImpl, requests } = fakeVdr(() => [rootDoc, secondDoc]);
    await resolve(DID, { store: null, fetchImpl });
    await resolve(DID, { store: null, fetchImpl });
    expect(requests).toHaveLength(2);
    expect(requests.every((r) => r.range === undefined)).toBe(true);
  });
});

describe("thin mode requires a VDG", () => {
  it("errors without a vdg", async () => {
    const result = await resolve(DID, { mode: "thin" });
    expect(result.didResolutionMetadata.error).toBe("internalError");
    expect(result.didResolutionMetadata.message).toMatch(/VDG/);
  });
});