import { existsSync, readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { resolve, type WebplusResolverOptions } from "../src/resolver.js";
import { InMemoryMicroledgerStore } from "../src/store.js";

/**
 * Official did:webplus resolution-scenario conformance catalog (format
 * `did-webplus-resolution-scenario/1`), from the same test-vector directory
 * as spec-vectors.test.ts. Each scenario's steps run in order against one
 * store, mirroring the interop harness's one store directory per scenario.
 * Runs when SPEC_VECTOR_DIR is set (CI sets it).
 */

interface Step {
  servedDidDocumentCount: number;
  didQuery: string;
  resolutionOptions: WebplusResolverOptions;
  vdrFails?: boolean;
  expected: {
    success: boolean;
    didDocumentVersionId?: number;
    didDocumentSelfHash?: string;
    didDocumentMetadata?: Record<string, unknown>;
    didResolutionMetadata: Record<string, unknown>;
    vdrRequestCount: number;
  };
}

interface Scenario {
  name: string;
  did: string;
  steps: Step[];
}

const dir = process.env.SPEC_VECTOR_DIR;
const scenarios: Array<{ scenario: Scenario; jsonlLines: string[] }> =
  dir !== undefined && existsSync(dir)
    ? readdirSync(dir)
        .filter((entry) => existsSync(`${dir}/${entry}/resolution-scenario.json`))
        .map((entry) => ({
          scenario: JSON.parse(readFileSync(`${dir}/${entry}/resolution-scenario.json`, "utf8")) as Scenario,
          jsonlLines: readFileSync(`${dir}/${entry}/did-documents.jsonl`, "utf8")
            .split("\n")
            .filter((line) => line.length > 0),
        }))
    : [];

function fakeVdr(rootSelfHash: string, lines: string[]) {
  const state = { served: 0, fails: false, requests: 0 };
  const suffix = `/${rootSelfHash}/did-documents.jsonl`;
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    if (!String(input).endsWith(suffix)) return new Response("not found", { status: 404 });
    state.requests += 1;
    if (state.fails) return new Response("unavailable", { status: 503 });
    const body = new TextEncoder().encode(lines.slice(0, state.served).join("\n") + "\n");
    const range = (init?.headers as Record<string, string> | undefined)?.range;
    if (range) {
      const start = Number(range.replace("bytes=", "").replace("-", ""));
      if (start >= body.length) return new Response(null, { status: 416 });
      return new Response(body.slice(start), { status: 206 });
    }
    return new Response(body, { status: 200 });
  }) as typeof fetch;
  return { state, fetchImpl };
}

if (scenarios.length > 0) {
  describe("official did:webplus resolution-scenario catalog", () => {
    it.each(scenarios.map((s) => [s.scenario.name, s] as const))("%s", async (_name, { scenario, jsonlLines }) => {
      const store = new InMemoryMicroledgerStore();
      const vdr = fakeVdr(scenario.did.split(":").at(-1)!, jsonlLines);

      for (const [i, step] of scenario.steps.entries()) {
        const at = `step ${i} (${step.didQuery.split(":").at(-1)})`;
        vdr.state.served = step.servedDidDocumentCount;
        vdr.state.fails = step.vdrFails === true;
        vdr.state.requests = 0;

        const result = await resolve(step.didQuery, {
          store,
          fetchImpl: vdr.fetchImpl,
          ...step.resolutionOptions,
        });
        const meta = result.didResolutionMetadata as Record<string, unknown>;
        const { expected } = step;

        if (expected.success) {
          expect(meta.error, `${at}: unexpected error`).toBeUndefined();
          expect(result.didDocument?.versionId, `${at}: versionId`).toBe(expected.didDocumentVersionId);
          expect(result.didDocument?.selfHash, `${at}: selfHash`).toBe(expected.didDocumentSelfHash);
          expect(result.didDocumentMetadata, `${at}: didDocumentMetadata`).toEqual(expected.didDocumentMetadata);
          for (const [key, value] of Object.entries(expected.didResolutionMetadata)) {
            expect(meta[key], `${at}: didResolutionMetadata.${key}`).toEqual(value);
          }
        } else {
          const expectedError = expected.didResolutionMetadata.error as { type: string; title: string };
          const error = meta.error as { type: string; title: string } | undefined;
          expect(error?.type, `${at}: error.type`).toBe(expectedError.type);
          expect(error?.title, `${at}: error.title`).toBe(expectedError.title);
          for (const [key, value] of Object.entries(expected.didResolutionMetadata)) {
            if (key !== "error") expect(meta[key], `${at}: didResolutionMetadata.${key}`).toEqual(value);
          }
          expect(result.didDocument, `${at}: didDocument`).toBeNull();
        }
        expect(vdr.state.requests, `${at}: vdrRequestCount`).toBe(expected.vdrRequestCount);
      }
    });
  });
} else {
  describe("official did:webplus resolution-scenario catalog", () => {
    it.skip("set SPEC_VECTOR_DIR to a did-webplus-spec test-vector checkout to run", () => {});
  });
}
