import { describe, expect, it } from "vitest";
import { canonicalize } from "@zkred/did-core";
import { resolve, vdgMicroledgerUrl, vdgResolutionUrl } from "../src/resolver.js";
import { DID, rootDoc, secondDoc } from "./fixtures/microledger.js";

describe("VDG URL construction", () => {
  it("percent-encodes the DID query into the resolve path", () => {
    expect(vdgResolutionUrl(`${DID}?versionId=1`, "vdg.example.com")).toBe(
      `https://vdg.example.com/webplus/v1/resolve/${encodeURIComponent(`${DID}?versionId=1`)}`,
    );
  });

  it("accepts a full base URL and builds the fetch endpoint", () => {
    expect(vdgMicroledgerUrl(DID, "http://localhost:8086")).toBe(
      `http://localhost:8086/webplus/v1/fetch/${encodeURIComponent(DID)}/did-documents.jsonl`,
    );
  });
});

describe("resolution through a VDG", () => {
  it("resolves a single document via /webplus/v1/resolve in thin mode", async () => {
    const expected = vdgResolutionUrl(DID, "vdg.example.com");
    const fetchImpl = (async (input: RequestInfo | URL) =>
      String(input) === expected
        ? new Response(JSON.stringify(secondDoc), { status: 200 })
        : new Response("nope", { status: 404 })) as typeof fetch;

    const result = await resolve(DID, { vdg: "vdg.example.com", mode: "thin", fetchImpl });
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocumentMetadata.versionId).toBe("1");
  });

  it("verifies the full microledger via /webplus/v1/fetch in full mode", async () => {
    const expected = vdgMicroledgerUrl(DID, "vdg.example.com");
    const fetchImpl = (async (input: RequestInfo | URL) =>
      String(input) === expected
        ? new Response([rootDoc, secondDoc].map((d) => canonicalize(d)).join("\n"), {
            status: 200,
          })
        : new Response("nope", { status: 404 })) as typeof fetch;

    const result = await resolve(DID, { vdg: "vdg.example.com", store: null, fetchImpl });
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocumentMetadata.verified).toBe(true);
    expect(result.didDocumentMetadata.versionId).toBe("1");
  });
});
