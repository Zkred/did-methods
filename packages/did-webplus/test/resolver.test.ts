import { describe, expect, it } from "vitest";
import { canonicalize } from "@zkred/did-core";
import { resolve } from "../src/resolver.js";
import { DID, rootDoc, secondDoc } from "./fixtures/microledger.js";

const LEDGER_URL = `https://example.com/${rootDoc.selfHash}/did-documents.jsonl`;

function jsonlFetch(docs: unknown[]): typeof fetch {
  return (async (input: RequestInfo | URL) =>
    String(input) === LEDGER_URL
      ? new Response(docs.map((d) => canonicalize(d)).join("\n") + "\n", { status: 200 })
      : new Response("not found", { status: 404 })) as typeof fetch;
}

describe("resolve (unverified mode, development only)", () => {
  it("resolves the latest DID document without cryptographic checks", async () => {
    const result = await resolve(DID, { mode: "unverified", fetchImpl: jsonlFetch([rootDoc, secondDoc]) });
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocument?.id).toBe(DID);
    expect(result.didDocumentMetadata.versionId).toBe("1");
    expect(result.didDocumentMetadata.verified).toBe(false);
    expect(result.didDocumentMetadata.mode).toBe("unverified");
  });

  it("selects a specific version via the versionId query", async () => {
    const result = await resolve(`${DID}?versionId=0`, {
      mode: "unverified",
      fetchImpl: jsonlFetch([rootDoc, secondDoc]),
    });
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocumentMetadata.versionId).toBe("0");
  });
});

describe("resolve error mapping", () => {
  it("returns notFound for a missing microledger", async () => {
    const result = await resolve(DID, { store: null, fetchImpl: jsonlFetch([]) });
    expect(result.didResolutionMetadata.error).toBe("notFound");
    expect(result.didDocument).toBeNull();
  });

  it("returns invalidDid for a malformed DID", async () => {
    const result = await resolve("did:webplus:example.com:garbage", { store: null, fetchImpl: jsonlFetch([]) });
    expect(result.didResolutionMetadata.error).toBe("invalidDid");
  });
});
