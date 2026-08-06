import { describe, expect, it } from "vitest";
import { dereference, getResolver, isDidCid, resolve } from "../src/index.js";

const DID = "did:cid:bafkreiawdmk6fmqc5p237vffyctazpzdgvgqfdj2i3hx2idtodxkwhyj5m";
const GATEKEEPER = "https://gatekeeper.example.com";

const TRIPLE = {
  didResolutionMetadata: { contentType: "application/did+ld+json" },
  didDocument: { id: DID },
  didDocumentMetadata: { versionSequence: 3 },
};

function fakeGatekeeper(routes: Record<string, { status?: number; body?: unknown }>) {
  const requests: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL) => {
    const url = String(input);
    requests.push(url);
    const route = routes[url];
    if (!route) return new Response("not found", { status: 404 });
    return new Response(JSON.stringify(route.body ?? null), {
      status: route.status ?? 200,
      headers: { "content-type": "application/did+ld+json" },
    });
  }) as typeof fetch;
  return { fetchImpl, requests };
}

describe("isDidCid", () => {
  it("accepts CIDv1 base32 DIDs and rejects everything else", () => {
    expect(isDidCid(DID)).toBe(true);
    expect(isDidCid("did:cid:QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco")).toBe(false); // v0/base58
    expect(isDidCid("did:cid:BAFKREIUPPERCASE")).toBe(false);
    expect(isDidCid("did:web:example.com")).toBe(false);
  });
});

describe("resolve", () => {
  it("passes the gatekeeper's resolution triple through unchanged", async () => {
    const { fetchImpl, requests } = fakeGatekeeper({
      [`${GATEKEEPER}/1.0/identifiers/${encodeURIComponent(DID)}`]: { body: TRIPLE },
    });
    const result = await resolve(DID, { gatekeeperUrl: GATEKEEPER, fetchImpl });
    expect(result).toEqual(TRIPLE);
    expect(requests).toHaveLength(1);
  });

  it("passes versionTime and versionSequence through; strips fragments and foreign params", async () => {
    const expected = `${GATEKEEPER}/1.0/identifiers/${encodeURIComponent(DID)}?versionTime=2026-01-01T00%3A00%3A00Z&versionSequence=2`;
    const { fetchImpl, requests } = fakeGatekeeper({ [expected]: { body: TRIPLE } });
    const result = await resolve(
      `${DID}?versionTime=2026-01-01T00:00:00Z&versionSequence=2&unknown=x#key-1`,
      { gatekeeperUrl: GATEKEEPER, fetchImpl },
    );
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(requests).toEqual([expected]);
  });

  it("passes through the gatekeeper's own error triple", async () => {
    const errorTriple = {
      didResolutionMetadata: { error: "notFound" },
      didDocument: null,
      didDocumentMetadata: {},
    };
    const { fetchImpl } = fakeGatekeeper({
      [`${GATEKEEPER}/1.0/identifiers/${encodeURIComponent(DID)}`]: {
        status: 404,
        body: errorTriple,
      },
    });
    const result = await resolve(DID, { gatekeeperUrl: GATEKEEPER, fetchImpl });
    expect(result).toEqual(errorTriple);
  });

  it("returns invalidDid for a malformed DID without touching the network", async () => {
    const { fetchImpl, requests } = fakeGatekeeper({});
    const result = await resolve("did:cid:not!a!cid", { gatekeeperUrl: GATEKEEPER, fetchImpl });
    expect(result.didResolutionMetadata.error).toBe("invalidDid");
    expect(requests).toHaveLength(0);
  });

  it("requires a gatekeeperUrl", async () => {
    const result = await resolve(DID, { gatekeeperUrl: "" });
    expect(result.didResolutionMetadata.error).toBe("internalError");
    expect(result.didResolutionMetadata.message).toMatch(/gatekeeperUrl/);
  });

  it("registers under the cid method name", async () => {
    const { fetchImpl } = fakeGatekeeper({
      [`${GATEKEEPER}/1.0/identifiers/${encodeURIComponent(DID)}`]: { body: TRIPLE },
    });
    const registry = getResolver({ gatekeeperUrl: GATEKEEPER, fetchImpl });
    expect(Object.keys(registry)).toEqual(["cid"]);
    const result = await registry.cid(DID);
    expect(result.didDocument?.id).toBe(DID);
  });
});

describe("dereference", () => {
  it("dereferences /data through the gatekeeper", async () => {
    const { fetchImpl } = fakeGatekeeper({
      [`${GATEKEEPER}/1.0/identifiers/${encodeURIComponent(DID)}/data`]: {
        body: { hello: "world" },
      },
    });
    const data = await dereference(`${DID}/data`, { gatekeeperUrl: GATEKEEPER, fetchImpl });
    expect(data).toEqual({ hello: "world" });
  });

  it("rejects paths the method does not define", async () => {
    const { fetchImpl } = fakeGatekeeper({});
    await expect(
      dereference(`${DID}/nonsense`, { gatekeeperUrl: GATEKEEPER, fetchImpl }),
    ).rejects.toThrow(/\/data and \/registration/);
  });

  it("maps a missing resource to notFound", async () => {
    const { fetchImpl } = fakeGatekeeper({
      [`${GATEKEEPER}/1.0/identifiers/${encodeURIComponent(DID)}/registration`]: {
        status: 404,
        body: null,
      },
    });
    await expect(
      dereference(`${DID}/registration`, { gatekeeperUrl: GATEKEEPER, fetchImpl }),
    ).rejects.toThrow(/no \/registration resource/);
  });
});
