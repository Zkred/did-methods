import { describe, expect, it } from "vitest";
import { canonicalize } from "@zkred/did-core";
import { resolve } from "../src/resolver.js";
import { InMemoryMicroledgerStore } from "../src/store.js";
import type { WebplusDidDocument } from "../src/types.js";
import { createDidDocument, deactivateDidDocument, hashedKeyRule, keyRule, updateDidDocument } from "../src/controller.js";
import { ed25519KeyPair } from "../src/sign.js";

/**
 * Integration coverage for the did:webplus DID Resolution Options and
 * metadata-locality rules (interop suite: catalog group `resolution-scenario`).
 * Named `it` blocks match the scenario names LedgerDomain's interop harness
 * uses, so a failure here points at the same behavior their report would.
 */

function errorOf(result: { didResolutionMetadata: { error?: unknown } }): { type: string; detail: string } {
  return result.didResolutionMetadata.error as { type: string; detail: string };
}

/** A fake VDR serving an append-only ledger with HTTP Range support, and request counting. */
function fakeVdr(url: string, getDocs: () => WebplusDidDocument[], status = 200) {
  const jsonl = (docs: WebplusDidDocument[]) => docs.map((d) => canonicalize(d)).join("\n") + "\n";
  const byteLen = (s: string) => new TextEncoder().encode(s).length;
  let requestCount = 0;
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input) !== url) return new Response("not found", { status: 404 });
    requestCount += 1;
    if (status !== 200) return new Response("error", { status });
    const range = (init?.headers as Record<string, string> | undefined)?.range;
    const body = jsonl(getDocs());
    if (range) {
      const start = Number(range.replace("bytes=", "").replace("-", ""));
      if (start >= byteLen(body)) return new Response(null, { status: 416 });
      return new Response(new TextEncoder().encode(body).slice(start), { status: 206 });
    }
    return new Response(body, { status: 200 });
  }) as typeof fetch;
  return { fetchImpl, requestCount: () => requestCount };
}

/** Builds a 4-version microledger (root + 3 updates) for metadata/locality scenarios. */
function buildLedger() {
  const seed = (n: number) => Uint8Array.from({ length: 32 }, (_, i) => (i * 23 + n + 7) & 0xff);
  const k0 = ed25519KeyPair(seed(0));
  const k1 = ed25519KeyPair(seed(1));
  const k2 = ed25519KeyPair(seed(2));
  const k3 = ed25519KeyPair(seed(3));
  const v0 = createDidDocument({
    host: "example.com",
    keys: [{ publicKey: k0.publicKey }],
    updateRules: hashedKeyRule(k1.publicKey),
    validFrom: "2026-08-01T00:00:00.000Z",
  });
  const v1 = updateDidDocument(v0, {
    keys: [{ publicKey: k1.publicKey }],
    updateRules: keyRule(k2.publicKey),
    signers: [k1],
    validFrom: "2026-08-01T00:00:01.000Z",
  });
  const v2 = updateDidDocument(v1, {
    keys: [{ publicKey: k2.publicKey }],
    updateRules: keyRule(k3.publicKey),
    signers: [k2],
    validFrom: "2026-08-01T00:00:02.000Z",
  });
  const v3 = updateDidDocument(v2, {
    keys: [{ publicKey: k3.publicKey }],
    updateRules: keyRule(k3.publicKey),
    signers: [k3],
    validFrom: "2026-08-01T00:00:03.000Z",
  });
  const url = `https://example.com/${v0.selfHash}/did-documents.jsonl`;
  return { did: v0.id, url, docs: [v0, v1, v2, v3], lastKey: k3 };
}

describe("cold-plain-did-no-metadata", () => {
  it("a fresh plain-DID resolve fetches once and reports only the baseline fields", async () => {
    const { did, url, docs } = buildLedger();
    const { fetchImpl, requestCount } = fakeVdr(url, () => docs);
    const result = await resolve(did, { store: new InMemoryMicroledgerStore(), fetchImpl });
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocumentMetadata).toEqual({
      versionId: "3",
      updated: "2026-08-01T00:00:03Z",
      updatedMilliseconds: "2026-08-01T00:00:03Z",
    });
    expect(result.didResolutionMetadata).toMatchObject({
      fetchedUpdatesFromVDR: true,
      didDocumentResolvedLocally: false,
      didDocumentMetadataResolvedLocally: true,
    });
    expect(requestCount()).toBe(1);
  });
});

describe("conflicting-query-params", () => {
  it("fails with INVALID_DID_URL, zero fetches, when selfHash and versionId disagree locally", async () => {
    const { did, url, docs } = buildLedger();
    const store = new InMemoryMicroledgerStore();
    const { fetchImpl: warm } = fakeVdr(url, () => docs);
    await resolve(did, { store, fetchImpl: warm });

    const { fetchImpl, requestCount } = fakeVdr(url, () => docs);
    const result = await resolve(`${did}?selfHash=${docs[1]!.selfHash}&versionId=2`, { store, fetchImpl });
    expect(errorOf(result).type).toBe("https://www.w3.org/ns/did#INVALID_DID_URL");
    expect(requestCount()).toBe(0);
  });
});

describe("deactivated-all-local", () => {
  it("resolves every requested metadata group from a deactivated local tip with zero fetches", async () => {
    const { did, url, docs, lastKey } = buildLedger();
    const tombstone = deactivateDidDocument(docs[3]!, {
      signers: [lastKey],
      validFrom: "2026-08-01T00:00:04.000Z",
    });
    const allDocs = [...docs, tombstone];

    const store = new InMemoryMicroledgerStore();
    const { fetchImpl: warm } = fakeVdr(url, () => allDocs);
    await resolve(did, { store, fetchImpl: warm });

    const offlineFetch = (async () => {
      throw new Error("must not be called");
    }) as typeof fetch;

    const result = await resolve(did, {
      store,
      fetchImpl: offlineFetch,
      requestCreate: true,
      requestNext: true,
      requestLatest: true,
      requestDeactivated: true,
    });
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didResolutionMetadata.fetchedUpdatesFromVDR).toBe(false);
    expect(result.didDocumentMetadata.deactivated).toBe(true);
    expect(result.didDocumentMetadata.versionId).toBe("4");
  });
});

describe("incremental-range-fetch", () => {
  it("the first resolve sees one document; growth is a single range GET", async () => {
    const { did, url, docs } = buildLedger();
    const served: WebplusDidDocument[] = [docs[0]!];
    const { fetchImpl, requestCount } = fakeVdr(url, () => served);
    const store = new InMemoryMicroledgerStore();

    const first = await resolve(did, { store, fetchImpl });
    expect(first.didDocumentMetadata.versionId).toBe("0");
    expect(requestCount()).toBe(1);

    served.push(docs[1]!, docs[2]!, docs[3]!);
    const second = await resolve(did, { store, fetchImpl });
    expect(second.didResolutionMetadata.error).toBeUndefined();
    expect(second.didDocumentMetadata.versionId).toBe("3");
    expect(requestCount()).toBe(2); // one more GET, a range continuation
  });
});

describe("local-only-matrix", () => {
  it("errors LOCAL_RESOLUTION_NOT_POSSIBLE on an empty store with zero fetches", async () => {
    const { did, url, docs } = buildLedger();
    const { fetchImpl, requestCount } = fakeVdr(url, () => docs);
    const result = await resolve(did, {
      store: new InMemoryMicroledgerStore(),
      fetchImpl,
      localResolutionOnly: true,
    });
    expect(errorOf(result).type).toBe(
      "https://ledgerdomain.github.io/did-webplus-spec/#LOCAL_RESOLUTION_NOT_POSSIBLE",
    );
    expect(result.didResolutionMetadata.fetchedUpdatesFromVDR).toBe(false);
    expect(requestCount()).toBe(0);
  });

  it("succeeds with zero fetches once the store already has the queried version", async () => {
    const { did, url, docs } = buildLedger();
    const store = new InMemoryMicroledgerStore();
    const { fetchImpl: warm } = fakeVdr(url, () => docs);
    await resolve(did, { store, fetchImpl: warm });

    const { fetchImpl, requestCount } = fakeVdr(url, () => docs);
    const result = await resolve(`${did}?versionId=2`, { store, fetchImpl, localResolutionOnly: true });
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(requestCount()).toBe(0);
  });

  it("still errors for a plain DID when the local tip is not deactivated", async () => {
    const { did, url, docs } = buildLedger();
    const store = new InMemoryMicroledgerStore();
    const { fetchImpl: warm } = fakeVdr(url, () => docs);
    await resolve(did, { store, fetchImpl: warm });

    const { fetchImpl, requestCount } = fakeVdr(url, () => docs);
    const result = await resolve(did, { store, fetchImpl, localResolutionOnly: true });
    expect(errorOf(result).type).toBe(
      "https://ledgerdomain.github.io/did-webplus-spec/#LOCAL_RESOLUTION_NOT_POSSIBLE",
    );
    expect(requestCount()).toBe(0);
  });
});

describe("plain-did-always-fetches", () => {
  it("fetches even though the store already has the (non-deactivated) latest document", async () => {
    const { did, url, docs } = buildLedger();
    const store = new InMemoryMicroledgerStore();
    const { fetchImpl: warm } = fakeVdr(url, () => docs);
    await resolve(did, { store, fetchImpl: warm });

    const { fetchImpl, requestCount } = fakeVdr(url, () => docs);
    const result = await resolve(did, { store, fetchImpl });
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didResolutionMetadata.fetchedUpdatesFromVDR).toBe(true);
    expect(requestCount()).toBe(1);
  });
});

describe("request-creation-cold / request-creation-warm", () => {
  it("cold: requestCreate on a first resolve is not locally satisfiable", async () => {
    const { did, url, docs } = buildLedger();
    const { fetchImpl } = fakeVdr(url, () => docs);
    const result = await resolve(did, {
      store: new InMemoryMicroledgerStore(),
      fetchImpl,
      requestCreate: true,
    });
    expect(result.didDocumentMetadata.created).toBe("2026-08-01T00:00:00Z");
    expect(result.didResolutionMetadata.didDocumentMetadataResolvedLocally).toBe(false);
  });

  it("warm: requestCreate is locally satisfiable once version 0 is in the store", async () => {
    const { did, url, docs } = buildLedger();
    const store = new InMemoryMicroledgerStore();
    const { fetchImpl: warm } = fakeVdr(url, () => docs);
    await resolve(did, { store, fetchImpl: warm });

    const offlineFetch = (async () => {
      throw new Error("must not be called");
    }) as typeof fetch;
    const result = await resolve(`${did}?versionId=3`, { store, fetchImpl: offlineFetch, requestCreate: true });
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didResolutionMetadata.fetchedUpdatesFromVDR).toBe(false);
    expect(result.didDocumentMetadata.created).toBe("2026-08-01T00:00:00Z");
  });
});

describe("request-deactivated-forces-fetch / request-latest-forces-fetch", () => {
  it("requestDeactivated forces a fetch when the local tip isn't known to be deactivated", async () => {
    const { did, url, docs } = buildLedger();
    const store = new InMemoryMicroledgerStore();
    const { fetchImpl: warm } = fakeVdr(url, () => docs);
    await resolve(`${did}?versionId=0`, { store, fetchImpl: warm });

    const { fetchImpl, requestCount } = fakeVdr(url, () => docs);
    const result = await resolve(`${did}?versionId=0`, { store, fetchImpl, requestDeactivated: true });
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocumentMetadata.deactivated).toBe(false);
    expect(requestCount()).toBe(1);
  });

  it("requestLatest forces a fetch when the latest document isn't known locally", async () => {
    const { did, url, docs } = buildLedger();
    const store = new InMemoryMicroledgerStore();
    const { fetchImpl: warm } = fakeVdr(url, () => [docs[0]!]);
    await resolve(`${did}?versionId=0`, { store, fetchImpl: warm });

    const { fetchImpl, requestCount } = fakeVdr(url, () => docs);
    const result = await resolve(`${did}?versionId=0`, { store, fetchImpl, requestLatest: true });
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocumentMetadata.latestVersionId).toBe("3");
    expect(requestCount()).toBe(1);
  });
});

describe("request-next-at-latest / request-next-with-local-next", () => {
  it("omits the next group entirely when the resolved document is the latest", async () => {
    const { did, url, docs } = buildLedger();
    const { fetchImpl } = fakeVdr(url, () => docs);
    const result = await resolve(did, { store: new InMemoryMicroledgerStore(), fetchImpl, requestNext: true });
    expect(result.didDocumentMetadata).not.toHaveProperty("nextVersionId");
  });

  it("answers requestNext with zero fetches once the successor is already local", async () => {
    const { did, url, docs } = buildLedger();
    const store = new InMemoryMicroledgerStore();
    const { fetchImpl: warm } = fakeVdr(url, () => docs);
    await resolve(did, { store, fetchImpl: warm });

    const offlineFetch = (async () => {
      throw new Error("must not be called");
    }) as typeof fetch;
    const result = await resolve(`${did}?versionId=1`, { store, fetchImpl: offlineFetch, requestNext: true });
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didResolutionMetadata.fetchedUpdatesFromVDR).toBe(false);
    expect(result.didDocumentMetadata.nextVersionId).toBe("2");
  });
});

describe("version-beyond-served", () => {
  it("fetches once, then fails NOT_FOUND, never returning an earlier document", async () => {
    const { did, url, docs } = buildLedger();
    const { fetchImpl, requestCount } = fakeVdr(url, () => docs);
    const result = await resolve(`${did}?versionId=99`, { store: new InMemoryMicroledgerStore(), fetchImpl });
    expect(errorOf(result).type).toBe("https://www.w3.org/ns/did#NOT_FOUND");
    expect(result.didDocument).toBeNull();
    expect(requestCount()).toBe(1);
  });
});

describe("warm-self-hash / warm-version-id / warm-both-params", () => {
  it("answers a selfHash query already in the store with zero fetches", async () => {
    const { did, url, docs } = buildLedger();
    const store = new InMemoryMicroledgerStore();
    const { fetchImpl: warm } = fakeVdr(url, () => docs);
    await resolve(did, { store, fetchImpl: warm });

    const { fetchImpl, requestCount } = fakeVdr(url, () => docs);
    const result = await resolve(`${did}?selfHash=${docs[1]!.selfHash}`, { store, fetchImpl });
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(requestCount()).toBe(0);
  });

  it("answers a versionId query already in the store with zero fetches", async () => {
    const { did, url, docs } = buildLedger();
    const store = new InMemoryMicroledgerStore();
    const { fetchImpl: warm } = fakeVdr(url, () => docs);
    await resolve(did, { store, fetchImpl: warm });

    const { fetchImpl, requestCount } = fakeVdr(url, () => docs);
    const result = await resolve(`${did}?versionId=1`, { store, fetchImpl });
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(requestCount()).toBe(0);
  });

  it("answers matching selfHash+versionId already in the store with zero fetches", async () => {
    const { did, url, docs } = buildLedger();
    const store = new InMemoryMicroledgerStore();
    const { fetchImpl: warm } = fakeVdr(url, () => docs);
    await resolve(did, { store, fetchImpl: warm });

    const { fetchImpl, requestCount } = fakeVdr(url, () => docs);
    const result = await resolve(`${did}?selfHash=${docs[1]!.selfHash}&versionId=1`, { store, fetchImpl });
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(requestCount()).toBe(0);
  });
});

describe("deactivated-known-absence", () => {
  it("fails NOT_FOUND with zero fetches for a versionId beyond a deactivated tip", async () => {
    const { did, url, docs } = buildLedger();
    const seed = (n: number) => Uint8Array.from({ length: 32 }, (_, i) => (i * 23 + n + 7) & 0xff);
    const k3 = ed25519KeyPair(seed(3));
    const tombstone = deactivateDidDocument(docs[3]!, { signers: [k3], validFrom: "2026-08-01T00:00:04.000Z" });
    const allDocs = [...docs, tombstone];

    const store = new InMemoryMicroledgerStore();
    const { fetchImpl: warm } = fakeVdr(url, () => allDocs);
    await resolve(did, { store, fetchImpl: warm });

    const offlineFetch = (async () => {
      throw new Error("must not be called");
    }) as typeof fetch;
    const result = await resolve(`${did}?versionId=99`, { store, fetchImpl: offlineFetch });
    expect(errorOf(result).type).toBe("https://www.w3.org/ns/did#NOT_FOUND");
    expect(result.didResolutionMetadata.fetchedUpdatesFromVDR).toBe(false);
  });

  it("fails NOT_FOUND with zero fetches for an unknown selfHash beyond a deactivated tip", async () => {
    const { did, url, docs } = buildLedger();
    const seed = (n: number) => Uint8Array.from({ length: 32 }, (_, i) => (i * 23 + n + 7) & 0xff);
    const k3 = ed25519KeyPair(seed(3));
    const tombstone = deactivateDidDocument(docs[3]!, { signers: [k3], validFrom: "2026-08-01T00:00:04.000Z" });
    const allDocs = [...docs, tombstone];

    const store = new InMemoryMicroledgerStore();
    const { fetchImpl: warm } = fakeVdr(url, () => allDocs);
    await resolve(did, { store, fetchImpl: warm });

    const offlineFetch = (async () => {
      throw new Error("must not be called");
    }) as typeof fetch;
    const result = await resolve(`${did}?selfHash=uHiAunknownunknownunknownunknownunknownAAAA`, {
      store,
      fetchImpl: offlineFetch,
    });
    expect(errorOf(result).type).toBe("https://www.w3.org/ns/did#NOT_FOUND");
    expect(result.didResolutionMetadata.fetchedUpdatesFromVDR).toBe(false);
  });
});

describe("fetch-failed-with-local-document", () => {
  it("fails closed when a required fetch errors, even with the document already local", async () => {
    const { did, url, docs } = buildLedger();
    const store = new InMemoryMicroledgerStore();
    const { fetchImpl: warm } = fakeVdr(url, () => docs);
    await resolve(did, { store, fetchImpl: warm });

    // versionId=1 is local, but requestLatest needs fresh data and the VDR
    // errors: answering from the store would hide a newer key or a
    // deactivation from anyone who can block the VDR.
    const { fetchImpl } = fakeVdr(url, () => docs, 503);
    const result = await resolve(`${did}?versionId=1`, { store, fetchImpl, requestLatest: true });
    expect(errorOf(result).type).toBe("https://ledgerdomain.github.io/did-webplus-spec/#VDR_FETCH_FAILED");
    expect(result.didResolutionMetadata).toMatchObject({
      fetchedUpdatesFromVDR: true,
      didDocumentResolvedLocally: true,
      didDocumentMetadataResolvedLocally: false,
    });
  });

  it("fails closed for a plain DID when the VDR errors, rather than serving the local tip", async () => {
    const { did, url, docs } = buildLedger();
    const store = new InMemoryMicroledgerStore();
    const { fetchImpl: warm } = fakeVdr(url, () => docs);
    await resolve(did, { store, fetchImpl: warm });

    const { fetchImpl } = fakeVdr(url, () => docs, 503);
    const result = await resolve(did, { store, fetchImpl });
    expect(errorOf(result).type).toBe("https://ledgerdomain.github.io/did-webplus-spec/#VDR_FETCH_FAILED");
    expect(result.didDocument).toBeNull();
  });

  it("fails VDR_FETCH_FAILED when the VDR errors and nothing is known locally", async () => {
    const { did, url, docs } = buildLedger();
    const { fetchImpl } = fakeVdr(url, () => docs, 503);
    const result = await resolve(did, { store: new InMemoryMicroledgerStore(), fetchImpl });
    expect(errorOf(result).type).toBe("https://ledgerdomain.github.io/did-webplus-spec/#VDR_FETCH_FAILED");
  });
});
