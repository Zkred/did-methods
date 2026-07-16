import { describe, expect, it } from "vitest";
import { canonicalize } from "@zkred/did-core";
import { resolve, vdgMicroledgerUrl, vdgResolutionUrl } from "../src/resolver.js";
import { isLocalhostHost, parseDid, schemeForHost } from "../src/did.js";
import { microledgerUrl } from "../src/controller.js";
import { InMemoryMicroledgerStore } from "../src/store.js";
import { DID, rootDoc, secondDoc } from "./fixtures/microledger.js";

const LEDGER_URL = `https://example.com/${rootDoc.selfHash}/did-documents.jsonl`;

describe("resolve() verifies by default (Full DID Resolver)", () => {
  it("fetches the microledger via the spec resolution URL and verifies it", async () => {
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

    const result = await resolve(DID, { store: new InMemoryMicroledgerStore(), fetchImpl });
    expect(requested).toEqual([LEDGER_URL]);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocumentMetadata.verified).toBe(true);
    expect(result.didDocumentMetadata.mode).toBe("full");
  });

  it("rejects a tampered ledger by default (no options needed)", async () => {
    const tampered = structuredClone(secondDoc);
    tampered.updateRules = { key: "u7QG2O2Vm22e1g4v6VRxjY9Qgm9XqJAKf_b3cH6Oc4R0bhw" };
    const fetchImpl = (async (input: RequestInfo | URL) =>
      String(input) === LEDGER_URL
        ? new Response([rootDoc, tampered].map((d) => canonicalize(d)).join("\n"), { status: 200 })
        : new Response("not found", { status: 404 })) as typeof fetch;

    const result = await resolve(DID, { store: null, fetchImpl });
    expect(result.didResolutionMetadata.error).toBe("invalidDidDocument");
  });
});

describe("localhost http default (spec DID-to-URL mapping, step 5)", () => {
  const HASH = rootDoc.selfHash;

  it("recognizes exactly localhost", () => {
    expect(isLocalhostHost("localhost")).toBe(true);
    expect(isLocalhostHost("LOCALHOST")).toBe(true);
    // the spec names only "localhost"; everything else is https by default
    expect(isLocalhostHost("127.0.0.1")).toBe(false);
    expect(isLocalhostHost("vdr.localhost")).toBe(false);
    expect(isLocalhostHost("example.com")).toBe(false);
    expect(schemeForHost("example.com")).toBe("https");
  });

  it("uses http for localhost DIDs across URL builders", () => {
    const localDid = `did:webplus:localhost%3A8085:${HASH}`;
    expect(parseDid(localDid).host).toBe("localhost");
    expect(microledgerUrl(localDid)).toBe(`http://localhost:8085/${HASH}/did-documents.jsonl`);
    expect(vdgResolutionUrl(DID, "localhost:8086")).toMatch(/^http:\/\/localhost:8086\//);
    expect(vdgMicroledgerUrl(DID, "vdg.example.com")).toMatch(/^https:\/\/vdg\.example\.com\//);
  });

  it("explicit scheme always wins", () => {
    const localDid = `did:webplus:localhost:${HASH}`;
    expect(microledgerUrl(localDid, { scheme: "https" })).toMatch(/^https:/);
    expect(microledgerUrl(DID, { scheme: "http" })).toMatch(/^http:/);
  });
});
