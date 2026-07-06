import {
  DidError,
  ResolutionErrorCode,
  fetchJson,
  toErrorResult,
  type DidResolutionResult,
} from "@zkred/did-core";
import { parseDid, parseQuery, resolutionUrl, type ResolutionUrlOptions } from "./did.js";
import { microledgerUrl } from "./controller.js";
import { validateMicroledger, type CryptoVerifier } from "./microledger.js";
import type { WebplusDidDocument, WebplusDidQuery } from "./types.js";

export interface WebplusResolverOptions extends ResolutionUrlOptions {
  /** Request timeout in milliseconds. Default: 15000. */
  timeoutMs?: number;
  /** Custom fetch implementation (for testing or non-standard environments). */
  fetchImpl?: typeof fetch;
  /**
   * Fetch the DID's complete microledger and cryptographically verify it
   * (self-hashes, proofs, updateRules, chaining) before returning the
   * requested document. Default: false (single-document fetch).
   */
  verify?: boolean;
  /** Verifier used when `verify` is set; defaults to the built-in one. `null` = structural only. */
  verifier?: CryptoVerifier | null;
}

/**
 * Fetch a DID's complete microledger from its VDR: the `did-documents.jsonl`
 * endpoint, one DID document per line, ordered by versionId.
 */
export async function fetchMicroledger(
  did: string,
  options: WebplusResolverOptions = {},
): Promise<WebplusDidDocument[]> {
  const url = microledgerUrl(did, options);
  const fetchImpl = options.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 15_000);
  let response: Response;
  try {
    response = await fetchImpl(url, {
      headers: { accept: "application/jsonl" },
      signal: controller.signal,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new DidError(ResolutionErrorCode.InternalError, `request to ${url} failed: ${message}`);
  } finally {
    clearTimeout(timer);
  }
  if (response.status === 404) {
    throw new DidError(ResolutionErrorCode.NotFound, `microledger not found at ${url}`);
  }
  if (!response.ok) {
    throw new DidError(ResolutionErrorCode.InternalError, `unexpected HTTP ${response.status} from ${url}`);
  }
  const text = await response.text();
  const lines = text.split("\n").filter((line) => line.trim().length > 0);
  if (lines.length === 0) {
    throw new DidError(ResolutionErrorCode.NotFound, `microledger at ${url} is empty`);
  }
  try {
    return lines.map((line) => JSON.parse(line) as WebplusDidDocument);
  } catch {
    throw new DidError(
      ResolutionErrorCode.RepresentationNotSupported,
      `microledger at ${url} contains invalid JSON lines`,
    );
  }
}

/** Select the document a DID URL query refers to from a full microledger. */
export function selectFromMicroledger(
  docs: WebplusDidDocument[],
  query: WebplusDidQuery,
): WebplusDidDocument {
  if (query.selfHash !== undefined) {
    const doc = docs.find((d) => d.selfHash === query.selfHash);
    if (!doc) {
      throw new DidError(ResolutionErrorCode.NotFound, `no document with selfHash ${query.selfHash}`);
    }
    return doc;
  }
  if (query.versionId !== undefined) {
    const doc = docs.find((d) => d.versionId === query.versionId);
    if (!doc) {
      throw new DidError(ResolutionErrorCode.NotFound, `no document with versionId ${query.versionId}`);
    }
    return doc;
  }
  if (query.versionTime !== undefined) {
    const t = Date.parse(query.versionTime);
    const doc = [...docs].reverse().find((d) => Date.parse(d.validFrom) <= t);
    if (!doc) {
      throw new DidError(
        ResolutionErrorCode.NotFound,
        `no document was valid at versionTime ${query.versionTime}`,
      );
    }
    return doc;
  }
  return docs[docs.length - 1]!;
}

function successResult(
  doc: WebplusDidDocument,
  extraMetadata: Record<string, unknown> = {},
): DidResolutionResult {
  return {
    didResolutionMetadata: { contentType: "application/did+json" },
    didDocument: doc,
    didDocumentMetadata: {
      versionId: String(doc.versionId),
      updated: doc.validFrom,
      selfHash: doc.selfHash,
      ...extraMetadata,
    },
  };
}

async function resolveVerified(
  did: string,
  query: WebplusDidQuery,
  options: WebplusResolverOptions,
): Promise<DidResolutionResult> {
  const docs = await fetchMicroledger(did, options);
  const validation = await validateMicroledger(docs, {
    expectedDid: did,
    ...(options.verifier !== undefined ? { verifier: options.verifier } : {}),
  });
  if (!validation.valid) {
    const detail = validation.errors
      .map((e) => `versionId ${e.versionId}: ${e.message}`)
      .join("; ");
    return {
      didResolutionMetadata: {
        error: "invalidDidDocument",
        message: `microledger verification failed: ${detail}`,
      },
      didDocument: null,
      didDocumentMetadata: {},
    };
  }
  const doc = selectFromMicroledger(docs, query);
  const latest = docs[docs.length - 1]!;
  return successResult(doc, {
    created: docs[0]!.validFrom,
    latestVersionId: String(latest.versionId),
    verified: true,
  });
}

/**
 * Resolve a did:webplus DID URL (optionally carrying `versionId`, `selfHash`,
 * or `versionTime` query parameters) to its DID document.
 *
 * By default a single document is fetched from the VDR without cryptographic
 * verification. Pass `verify: true` to fetch the complete microledger and
 * verify it (self-hashes, Ed25519 proofs against updateRules, chaining)
 * before trusting any document. `versionTime` queries always fetch the full
 * microledger, since selecting by time requires the version history.
 */
export async function resolve(
  didUrl: string,
  options: WebplusResolverOptions = {},
): Promise<DidResolutionResult> {
  try {
    const [beforeFragment] = didUrl.split("#");
    const [didPart, queryPart] = beforeFragment!.split("?");
    const parsed = parseDid(didPart!);
    const query = parseQuery(queryPart);

    if (options.verify || query.versionTime !== undefined) {
      return await resolveVerified(parsed.did, query, options);
    }

    const url = resolutionUrl(parsed, query, options);
    const doc = await fetchJson<WebplusDidDocument>(url, {
      ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
      ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
    });
    return successResult(doc);
  } catch (err) {
    return toErrorResult(err);
  }
}

/**
 * Build a `did-resolver`-compatible registry entry:
 *
 * ```ts
 * import { Resolver } from "did-resolver";
 * import { getResolver } from "@zkred/did-webplus";
 *
 * const resolver = new Resolver(getResolver({ verify: true }));
 * const result = await resolver.resolve("did:webplus:example.com:uHiAg...");
 * ```
 */
export function getResolver(options: WebplusResolverOptions = {}) {
  return {
    webplus: (didUrl: string) => resolve(didUrl, options),
  };
}