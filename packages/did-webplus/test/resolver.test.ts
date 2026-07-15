import { describe, expect, it } from "vitest";
import { resolve } from "../src/resolver.js";
import { DID, rootDoc, secondDoc } from "./fixtures/microledger.js";

function fakeFetch(routes: Record<string, unknown>): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url in routes) {
      return new Response(JSON.stringify(routes[url]), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
}

const ROOT_SELF_HASH = rootDoc.selfHash;

describe("resolve", () => {
  it("resolves the latest DID document", async () => {
    const fetchImpl = fakeFetch({
      [`https://example.com/${ROOT_SELF_HASH}/did.json`]: secondDoc,
    });
    const result = await resolve(DID, { verify: false, fetchImpl });
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocument?.id).toBe(DID);
    expect(result.didDocumentMetadata.versionId).toBe("1");
    expect(result.didDocumentMetadata.verified).toBe(false);
  });

  it("resolves a specific version via the versionId query", async () => {
    const fetchImpl = fakeFetch({
      [`https://example.com/${ROOT_SELF_HASH}/did/versionId/0.json`]: rootDoc,
    });
    const result = await resolve(`${DID}?versionId=0`, { verify: false, fetchImpl });
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocumentMetadata.versionId).toBe("0");
  });

  it("returns notFound for a missing document", async () => {
    const result = await resolve(DID, { fetchImpl: fakeFetch({}) });
    expect(result.didResolutionMetadata.error).toBe("notFound");
    expect(result.didDocument).toBeNull();
  });

  it("returns invalidDid for a malformed DID", async () => {
    const result = await resolve("did:webplus:example.com:garbage", { fetchImpl: fakeFetch({}) });
    expect(result.didResolutionMetadata.error).toBe("invalidDid");
  });
});