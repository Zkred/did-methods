import { describe, expect, it } from "vitest";
import { canonicalize } from "@zkred/did-core";
import { resolve } from "../src/resolver.js";
import { isLocalhostHost, parseDid, resolutionUrl, schemeForHost } from "../src/did.js";
import { microledgerUrl } from "../src/controller.js";
import { vdgMicroledgerUrl, vdgResolutionUrl } from "../src/resolver.js";
import { DID, rootDoc, secondDoc } from "./fixtures/microledger.js";

const LEDGER_URL = `https://example.com/${rootDoc.selfHash}/did-documents.jsonl`;

describe("resolve() verifies by default", () => {
  it("fetches the full microledger and verifies it when no options are passed", async () => {
    const requested: string[] = [];
    const fetchImpl = (async (input: RequestInfo | URL) => {
      requested.push(String(input));
      if (String(input) === LEDGER_URL) {
        return new Response([rootDoc, secondDoc].map((d) => canonicalize(d)).join("\n"), {
          status: 200,
        });
      }
      return new Response("not found", { status: 404 });
    }) as typeof fetch;

    const result = await resolve(DID, { fetchImpl });
    expect(requested).toEqual([LEDGER_URL]);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocumentMetadata.verified).toBe(true);
  });

  it("rejects a tampered ledger by default (no verify option needed)", async () => {
    const tampered = structuredClone(secondDoc);
    tampered.updateRules = { key: "u7QG2O2Vm22e1g4v6VRxjY9Qgm9XqJAKf_b3cH6Oc4R0bhw" };
    const fetchImpl = (async (input: RequestInfo | URL) =>
      String(input) === LEDGER_URL
        ? new Response([rootDoc, tampered].map((d) => canonicalize(d)).join("\n"), { status: 200 })
        : new Response("not found", { status: 404 })) as typeof fetch;

    const result = await resolve(DID, { fetchImpl });
    expect(result.didResolutionMetadata.error).toBe("invalidDidDocument");
  });
});

describe("localhost hosts default to http", () => {
  const HASH = rootDoc.selfHash;

  it.each(["localhost", "vdr.localhost", "127.0.0.1", "::1"])("recognizes %s", (h) => {
    expect(isLocalhostHost(h)).toBe(true);
  });

  it("keeps real hosts on https", () => {
    expect(isLocalhostHost("example.com")).toBe(false);
    expect(schemeForHost("example.com")).toBe("https");
    expect(resolutionUrl(parseDid(DID))).toMatch(/^https:/);
  });

  it("uses http for localhost DIDs across all URL builders", () => {
    const localDid = `did:webplus:localhost%3A8085:${HASH}`;
    expect(resolutionUrl(parseDid(localDid))).toBe(`http://localhost:8085/${HASH}/did.json`);
    expect(microledgerUrl(localDid)).toBe(`http://localhost:8085/${HASH}/did-documents.jsonl`);
    expect(vdgResolutionUrl(DID, "localhost:8086")).toMatch(/^http:\/\/localhost:8086\//);
    expect(vdgMicroledgerUrl(DID, "vdg.example.com")).toMatch(/^https:\/\/vdg\.example\.com\//);
  });

  it("explicit scheme always wins", () => {
    const localDid = `did:webplus:localhost:${HASH}`;
    expect(resolutionUrl(parseDid(localDid), {}, { scheme: "https" })).toMatch(/^https:/);
    expect(resolutionUrl(parseDid(DID), {}, { scheme: "http" })).toMatch(/^http:/);
  });
});