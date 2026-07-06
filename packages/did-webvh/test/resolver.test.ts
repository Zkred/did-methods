import { describe, expect, it, vi } from "vitest";

const resolveDIDMock = vi.hoisted(() => vi.fn());
vi.mock("didwebvh-ts", () => ({
  resolveDID: resolveDIDMock,
}));

import { getResolver, resolve } from "../src/index.js";

const DID = "did:webvh:QmScid123:example.com";

describe("resolve (did:webvh adapter)", () => {
  it("reshapes a successful didwebvh-ts result into a DidResolutionResult", async () => {
    resolveDIDMock.mockResolvedValueOnce({
      did: DID,
      controlled: false,
      doc: { id: DID },
      meta: {
        versionId: "3-QmHash",
        created: "2026-01-01T00:00:00Z",
        updated: "2026-02-01T00:00:00Z",
        deactivated: false,
        scid: "QmScid123",
        updateKeys: [],
        prerotation: false,
        portable: false,
        nextKeyHashes: [],
      },
    });

    const result = await resolve(DID);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocument?.id).toBe(DID);
    expect(result.didDocumentMetadata.versionId).toBe("3-QmHash");
    expect(result.didDocumentMetadata.deactivated).toBe(false);
  });

  it("passes DID URL query parameters through as resolution options", async () => {
    resolveDIDMock.mockResolvedValueOnce({
      did: DID,
      controlled: false,
      doc: { id: DID },
      meta: { versionId: "1-x", created: "", updated: "", deactivated: false, scid: "" },
    });

    await resolve(`${DID}?versionNumber=1`);
    expect(resolveDIDMock).toHaveBeenCalledWith(DID, expect.objectContaining({ versionNumber: 1 }));
  });

  it("maps resolution errors onto didResolutionMetadata.error", async () => {
    resolveDIDMock.mockResolvedValueOnce({
      did: DID,
      controlled: false,
      doc: null,
      meta: {
        error: "notFound",
        problemDetails: { type: "t", title: "Not Found", detail: "no log found" },
      },
    });

    const result = await resolve(DID);
    expect(result.didResolutionMetadata.error).toBe("notFound");
    expect(result.didResolutionMetadata.message).toBe("no log found");
    expect(result.didDocument).toBeNull();
  });

  it("registers under the webvh method name", () => {
    const registry = getResolver();
    expect(Object.keys(registry)).toEqual(["webvh"]);
  });
});