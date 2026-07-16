import { describe, expect, it } from "vitest";
import { formatDid, parseDid, parseQuery } from "../src/did.js";
import { microledgerUrl } from "../src/controller.js";
import { DID } from "./fixtures/microledger.js";

const ROOT_SELF_HASH = "uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ";

describe("parseDid", () => {
  it("parses a plain host DID", () => {
    const parsed = parseDid(DID);
    expect(parsed.host).toBe("example.com");
    expect(parsed.port).toBeUndefined();
    expect(parsed.path).toEqual([]);
    expect(parsed.rootSelfHash).toBe(ROOT_SELF_HASH);
  });

  it("parses a DID with percent-encoded port and path components", () => {
    const parsed = parseDid(`did:webplus:localhost%3A8085:dids:abc:${ROOT_SELF_HASH}`);
    expect(parsed.host).toBe("localhost");
    expect(parsed.port).toBe(8085);
    expect(parsed.path).toEqual(["dids", "abc"]);
    expect(parsed.rootSelfHash).toBe(ROOT_SELF_HASH);
  });

  it("round-trips through formatDid", () => {
    const original = `did:webplus:localhost%3A8085:dids:${ROOT_SELF_HASH}`;
    expect(formatDid(parseDid(original))).toBe(original);
    expect(formatDid(parseDid(DID))).toBe(DID);
  });

  it("rejects other methods, missing components, and malformed input", () => {
    expect(() => parseDid("did:web:example.com")).toThrow(/not a did:webplus/);
    expect(() => parseDid("did:webplus:example.com")).toThrow(/at least host/);
    expect(() => parseDid(`did:webplus:example.com:not-a-self-hash`)).toThrow(/self-hash/);
    expect(() => parseDid(`did:webplus:bad_host!:${ROOT_SELF_HASH}`)).toThrow(/invalid host/);
    expect(() => parseDid(`did:webplus:example.com%3A99999:${ROOT_SELF_HASH}`)).toThrow(/port/);
    expect(() => parseDid(`${DID}?versionId=1`)).toThrow(/query/);
  });
});

describe("parseQuery", () => {
  it("parses versionId, selfHash, and versionTime", () => {
    const query = parseQuery(`versionId=2&selfHash=${ROOT_SELF_HASH}&versionTime=2025-11-19T01:43:26.979Z`);
    expect(query.versionId).toBe(2);
    expect(query.selfHash).toBe(ROOT_SELF_HASH);
    expect(query.versionTime).toBe("2025-11-19T01:43:26.979Z");
  });

  it("rejects malformed values", () => {
    expect(() => parseQuery("versionId=-1")).toThrow(/versionId/);
    expect(() => parseQuery("selfHash=nope")).toThrow(/selfHash/);
    expect(() => parseQuery("versionTime=not-a-date")).toThrow(/versionTime/);
  });
});

describe("DID-to-URL mapping (spec: single resolution URL)", () => {
  it("maps a DID to its did-documents.jsonl URL", () => {
    expect(microledgerUrl(DID)).toBe(
      `https://example.com/${ROOT_SELF_HASH}/did-documents.jsonl`,
    );
  });

  it("percent-decodes ports and joins path components with slashes", () => {
    expect(microledgerUrl(`did:webplus:localhost%3A8085:dids:abc:${ROOT_SELF_HASH}`)).toBe(
      `http://localhost:8085/dids/abc/${ROOT_SELF_HASH}/did-documents.jsonl`,
    );
  });
});