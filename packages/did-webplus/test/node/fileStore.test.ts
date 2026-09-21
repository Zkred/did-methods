import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { canonicalize } from "@zkred/did-core";
import { FileMicroledgerStore } from "../../src/node/fileStore.js";
import { resolve } from "../../src/resolver.js";
import { WebplusCryptoVerifier } from "../../src/verifier.js";
import type { WebplusDidDocument } from "../../src/types.js";
import { DID, rootDoc, secondDoc } from "../fixtures/microledger.js";

const LEDGER_URL = `https://example.com/${rootDoc.selfHash}/did-documents.jsonl`;
const jsonl = (docs: WebplusDidDocument[]) => docs.map((d) => canonicalize(d)).join("\n") + "\n";

class CountingVerifier extends WebplusCryptoVerifier {
  selfHashCalls = 0;
  override async verifySelfHash(doc: WebplusDidDocument): Promise<boolean> {
    this.selfHashCalls += 1;
    return super.verifySelfHash(doc);
  }
}

describe("FileMicroledgerStore", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "did-webplus-store-"));
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("returns undefined for a DID that was never stored", async () => {
    const store = new FileMicroledgerStore(dir);
    expect(await store.get(DID)).toBeUndefined();
  });

  it("round-trips a stored microledger", async () => {
    const store = new FileMicroledgerStore(dir);
    const ledger = { raw: jsonl([rootDoc, secondDoc]).replace(/\n$/, ""), docs: [rootDoc, secondDoc] };
    await store.put(DID, ledger);
    expect(await store.get(DID)).toEqual(ledger);
  });

  it("persists across separate store instances pointed at the same directory", async () => {
    const ledger = { raw: jsonl([rootDoc]).replace(/\n$/, ""), docs: [rootDoc] };
    await new FileMicroledgerStore(dir).put(DID, ledger);
    // A fresh instance stands in for a new process reopening the same directory.
    const reopened = new FileMicroledgerStore(dir);
    expect(await reopened.get(DID)).toEqual(ledger);
  });

  it("does not collide on DIDs differing only in characters unsafe in filenames", async () => {
    const store = new FileMicroledgerStore(dir);
    const other = "did:webplus:example.com:uHiOTHERuHiOTHERuHiOTHERuHiOTHERuHiOTHERuHiA";
    await store.put(DID, { raw: "a", docs: [] });
    await store.put(other, { raw: "b", docs: [] });
    expect((await store.get(DID))?.raw).toBe("a");
    expect((await store.get(other))?.raw).toBe("b");
  });

  it("resolve() serves a historical query offline after reopening the store in a new instance", async () => {
    const fetchImpl = (async (input: RequestInfo | URL) =>
      String(input) === LEDGER_URL
        ? new Response(jsonl([rootDoc, secondDoc]), { status: 200 })
        : new Response("not found", { status: 404 })) as typeof fetch;

    await resolve(DID, { store: new FileMicroledgerStore(dir), fetchImpl });

    // Simulate a fresh process: new store instance, same directory, and a
    // fetchImpl that fails outright so nothing can be served except from disk.
    const verifier = new CountingVerifier();
    const offlineFetch = (async () => {
      throw new Error("network down");
    }) as typeof fetch;
    const result = await resolve(`${DID}?versionId=0`, {
      store: new FileMicroledgerStore(dir),
      verifier,
      fetchImpl: offlineFetch,
    });

    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocumentMetadata.versionId).toBe("0");
    expect(result.didDocumentMetadata.cached).toBe(true);
    expect(verifier.selfHashCalls).toBe(0);
  });
});
