import { describe, expect, it } from "vitest";
import { canonicalize } from "@zkred/did-core";
import { fetchMicroledger, resolve, selectFromMicroledger } from "../src/resolver.js";
import { InMemoryMicroledgerStore } from "../src/store.js";
import { DID, rootDoc, secondDoc } from "./fixtures/microledger.js";

const LEDGER_URL = `https://example.com/${rootDoc.selfHash}/did-documents.jsonl`;

function jsonlFetch(docs: unknown[], url = LEDGER_URL): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    if (String(input) === url) {
      return new Response(docs.map((d) => canonicalize(d)).join("\n") + "\n", { status: 200 });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
}

describe("fetchMicroledger", () => {
  it("fetches and parses the did-documents.jsonl endpoint", async () => {
    const docs = await fetchMicroledger(DID, { fetchImpl: jsonlFetch([rootDoc, secondDoc]) });
    expect(docs.map((d) => d.versionId)).toEqual([0, 1]);
  });

  it("maps a missing ledger to notFound", async () => {
    await expect(fetchMicroledger(DID, { fetchImpl: jsonlFetch([], "https://other/x") })).rejects.toThrow(
      /not found/,
    );
  });
});

describe("selectFromMicroledger", () => {
  const docs = [rootDoc, secondDoc];

  it("selects latest, by versionId, and by selfHash", () => {
    expect(selectFromMicroledger(docs, {}).versionId).toBe(1);
    expect(selectFromMicroledger(docs, { versionId: 0 }).versionId).toBe(0);
    expect(selectFromMicroledger(docs, { selfHash: rootDoc.selfHash }).versionId).toBe(0);
  });

  it("selects by versionTime", () => {
    // between v0 (…26.979Z) and v1 (…26.992Z)
    expect(
      selectFromMicroledger(docs, { versionTime: "2025-11-19T01:43:26.985Z" }).versionId,
    ).toBe(0);
    expect(selectFromMicroledger(docs, { versionTime: "2026-01-01T00:00:00Z" }).versionId).toBe(1);
    expect(() =>
      selectFromMicroledger(docs, { versionTime: "2020-01-01T00:00:00Z" }),
    ).toThrow(/versionTime/);
  });
});

describe("resolve in full mode (default)", () => {
  it("verifies the full microledger and returns the latest document", async () => {
    const result = await resolve(DID, { store: new InMemoryMicroledgerStore(), fetchImpl: jsonlFetch([rootDoc, secondDoc]) });
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocument?.id).toBe(DID);
    expect(result.didDocumentMetadata.versionId).toBe("1");
    expect(result.didDocumentMetadata.verified).toBe(true);
    expect(result.didDocumentMetadata.created).toBe(rootDoc.validFrom);
  });

  it("resolves versionTime queries from the version history", async () => {
    const result = await resolve(`${DID}?versionTime=2025-11-19T01:43:26.985Z`, {
      store: null,
      fetchImpl: jsonlFetch([rootDoc, secondDoc]),
    });
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocumentMetadata.versionId).toBe("0");
  });

  it("rejects a tampered microledger", async () => {
    const tampered = structuredClone(secondDoc);
    tampered.updateRules = { key: "u7QG2O2Vm22e1g4v6VRxjY9Qgm9XqJAKf_b3cH6Oc4R0bhw" };
    const result = await resolve(DID, { store: null, fetchImpl: jsonlFetch([rootDoc, tampered]) });
    expect(result.didResolutionMetadata.error).toBe("invalidDidDocument");
    expect(result.didResolutionMetadata.message).toMatch(/verification failed/);
    expect(result.didDocument).toBeNull();
  });

  it("still verifies structurally when verifier is null", async () => {
    const result = await resolve(DID, {
      store: null,
      verifier: null,
      fetchImpl: jsonlFetch([rootDoc, secondDoc]),
    });
    expect(result.didResolutionMetadata.error).toBeUndefined();
  });
});