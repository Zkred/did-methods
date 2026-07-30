import { readFileSync, existsSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { validateMicroledgerBytes } from "../src/microledger.js";

/**
 * Official did:webplus conformance test vectors, published at
 * https://ledgerdomain.github.io/did-webplus-spec/test-vector (source:
 * https://github.com/LedgerDomain/did-webplus-spec, test-vector/).
 *
 * Point SPEC_VECTOR_DIR at a checkout's test-vector directory to run
 * (CI clones the spec repo and sets it). Skipped when unset.
 */
const dir = process.env.SPEC_VECTOR_DIR;
const available = dir !== undefined && existsSync(`${dir}/index.json`);

describe.skipIf(!available)("official did:webplus conformance test vectors", () => {
  const index = JSON.parse(readFileSync(`${dir}/index.json`, "utf8")) as {
    vectors: Record<string, { did: string; path: string }>;
  };

  it.each(Object.entries(index.vectors))("%s", async (_name, entry) => {
    const tv = JSON.parse(readFileSync(`${dir}/${entry.path}/test-vector.json`, "utf8")) as {
      did: string;
      expected: { valid: boolean };
    };
    const raw = readFileSync(`${dir}/${entry.path}/did-documents.jsonl`, "utf8");
    const result = await validateMicroledgerBytes(raw, { expectedDid: tv.did });
    expect(result.valid).toBe(tv.expected.valid);
  });
});

if (!available) {
  describe("official did:webplus conformance test vectors", () => {
    it.skip("set SPEC_VECTOR_DIR to a did-webplus-spec test-vector checkout to run", () => {});
  });
}
