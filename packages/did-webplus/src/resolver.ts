import {
  DidError,
  ResolutionErrorCode,
  canonicalize,
  fetchJson,
  toErrorResult,
  type DidResolutionResult,
} from "@zkred/did-core";
import { parseDid, parseQuery, schemeForHost, type ResolutionUrlOptions } from "./did.js";
import { microledgerUrl } from "./controller.js";
import {
  parseJcsCanonicalLines,
  validateMicroledger,
  validateMicroledgerExtension,
  type CryptoVerifier,
  type MicroledgerValidationResult,
} from "./microledger.js";
import { defaultMicroledgerStore, type MicroledgerStore, type StoredMicroledger } from "./store.js";
import type { WebplusDidDocument, WebplusDidQuery } from "./types.js";

/**
 * Resolver modes, in the spec's terminology:
 *
 * - `"full"` (default) — a Full DID Resolver: fetches the DID's microledger,
 *   cryptographically verifies it, and persists the verified portion so that
 *   repeated resolution is a range-based fetch verifying only new documents.
 *   Provides duplicity detection and offline historical resolution.
 * - `"thin"` — a Thin DID Resolver: delegates fetching/verification/archiving
 *   to a trusted VDG (required); a single request per resolution.
 * - `"unverified"` — development/testing only. Fetches the microledger and
 *   enforces the JCS wire-format rule but performs NO cryptographic
 *   verification and trusts the host. Non-conformant; never use in
 *   production.
 */
export type ResolverMode = "full" | "thin" | "unverified";

export interface WebplusResolverOptions extends ResolutionUrlOptions {
  /** Resolver mode. Default: `"full"`. */
  mode?: ResolverMode;
  /**
   * Microledger persistence for full mode. Defaults to a shared in-memory
   * store (`defaultMicroledgerStore`); supply your own `MicroledgerStore`
   * for durable storage, or `null` to disable persistence (every resolution
   * fetches and verifies the complete microledger).
   */
  store?: MicroledgerStore | null;
  /** Request timeout in milliseconds. Default: 15000. */
  timeoutMs?: number;
  /** Custom fetch implementation (for testing or non-standard environments). */
  fetchImpl?: typeof fetch;
  /** Verifier used in full mode; defaults to the built-in one. `null` = structural only. */
  verifier?: CryptoVerifier | null;
  /**
   * Verifiable Data Gateway (hostname or base URL). Required for thin mode;
   * optional for full/unverified modes, where the VDG's fetch endpoint is
   * used instead of the DID's VDR.
   */
  vdg?: string;
}

/** Normalize a VDG hostname or base URL into a base URL without a trailing slash. */
function vdgBaseUrl(vdg: string, options: ResolutionUrlOptions = {}): string {
  if (vdg.includes("://")) {
    return vdg.replace(/\/+$/, "");
  }
  const host = vdg.split("/")[0]!.split(":")[0]!;
  return `${schemeForHost(host, options)}://${vdg}`.replace(/\/+$/, "");
}

/** The URL the VDG serves a DID query's document at (Thin DID Resolver). */
export function vdgResolutionUrl(
  didQuery: string,
  vdg: string,
  options: ResolutionUrlOptions = {},
): string {
  return `${vdgBaseUrl(vdg, options)}/webplus/v1/resolve/${encodeURIComponent(didQuery)}`;
}

/** The URL the VDG serves a DID's complete microledger at. */
export function vdgMicroledgerUrl(
  did: string,
  vdg: string,
  options: ResolutionUrlOptions = {},
): string {
  return `${vdgBaseUrl(vdg, options)}/webplus/v1/fetch/${encodeURIComponent(did)}/did-documents.jsonl`;
}

function ledgerUrlFor(did: string, options: WebplusResolverOptions): string {
  return options.vdg ? vdgMicroledgerUrl(did, options.vdg, options) : microledgerUrl(did, options);
}

async function fetchText(
  url: string,
  options: WebplusResolverOptions,
  rangeStart?: number,
): Promise<{ status: number; text: string }> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 15_000);
  try {
    const response = await fetchImpl(url, {
      headers: {
        accept: "application/jsonl",
        ...(rangeStart !== undefined ? { range: `bytes=${rangeStart}-` } : {}),
      },
      signal: controller.signal,
    });
    return { status: response.status, text: await response.text() };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new DidError(ResolutionErrorCode.InternalError, `request to ${url} failed: ${message}`);
  } finally {
    clearTimeout(timer);
  }
}

function throwOnValidationErrors(result: MicroledgerValidationResult, url: string): void {
  if (result.errors.length === 0) return;
  const detail = result.errors.map((e) => `versionId ${e.versionId}: ${e.message}`).join("; ");
  throw new DidError(
    ResolutionErrorCode.InvalidDidDocument,
    `microledger verification failed for ${url}: ${detail}`,
  );
}

function parseCanonicalOrThrow(text: string, url: string): WebplusDidDocument[] {
  const { docs, errors } = parseJcsCanonicalLines(text);
  const invalidJson = errors.find((e) => e.message.includes("not valid JSON"));
  if (invalidJson) {
    throw new DidError(
      ResolutionErrorCode.RepresentationNotSupported,
      `microledger at ${url}: ${invalidJson.message}`,
    );
  }
  if (errors.length > 0) {
    throw new DidError(
      ResolutionErrorCode.InvalidDidDocument,
      `microledger at ${url}: ${errors.map((e) => e.message).join("; ")}`,
    );
  }
  return docs;
}

const rawOf = (docs: WebplusDidDocument[]): string =>
  docs.map((d) => canonicalize(d)).join("\n") + "\n";

const utf8Length = (s: string): number => new TextEncoder().encode(s).length;

/**
 * Fetch a DID's complete microledger from its VDR (or a VDG), enforcing the
 * JCS wire-format rule. Performs a full (non-range) fetch and no
 * cryptographic verification; `resolve` in full mode builds on top of this.
 */
export async function fetchMicroledger(
  did: string,
  options: WebplusResolverOptions = {},
): Promise<WebplusDidDocument[]> {
  const url = ledgerUrlFor(did, options);
  const { status, text } = await fetchText(url, options);
  if (status === 404) {
    throw new DidError(ResolutionErrorCode.NotFound, `microledger not found at ${url}`);
  }
  if (status < 200 || status >= 300) {
    throw new DidError(ResolutionErrorCode.InternalError, `unexpected HTTP ${status} from ${url}`);
  }
  const docs = parseCanonicalOrThrow(text, url);
  if (docs.length === 0) {
    throw new DidError(ResolutionErrorCode.NotFound, `microledger at ${url} is empty`);
  }
  return docs;
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
  docs: WebplusDidDocument[] | null,
  extraMetadata: Record<string, unknown>,
): DidResolutionResult {
  return {
    didResolutionMetadata: { contentType: "application/did+json" },
    didDocument: doc,
    didDocumentMetadata: {
      versionId: String(doc.versionId),
      updated: doc.validFrom,
      selfHash: doc.selfHash,
      ...(docs
        ? { created: docs[0]!.validFrom, latestVersionId: String(docs[docs.length - 1]!.versionId) }
        : {}),
      ...extraMetadata,
    },
  };
}

/** True when a historical query is answerable from the verified store alone. */
function servableOffline(stored: StoredMicroledger, query: WebplusDidQuery): boolean {
  if (query.selfHash !== undefined) {
    return stored.docs.some((d) => d.selfHash === query.selfHash);
  }
  if (query.versionId !== undefined) {
    return query.versionId < stored.docs.length;
  }
  if (query.versionTime !== undefined) {
    // Final only if a stored document strictly supersedes the queried time.
    const t = Date.parse(query.versionTime);
    return stored.docs.some((d) => Date.parse(d.validFrom) > t);
  }
  return false; // "latest" always requires checking for updates
}

async function resolveFull(
  did: string,
  query: WebplusDidQuery,
  options: WebplusResolverOptions,
): Promise<DidResolutionResult> {
  const store = options.store === null ? undefined : (options.store ?? defaultMicroledgerStore);
  const stored = await store?.get(did);
  const url = ledgerUrlFor(did, options);
  const verifierOpt = options.verifier !== undefined ? { verifier: options.verifier } : {};

  if (stored && servableOffline(stored, query)) {
    return successResult(selectFromMicroledger(stored.docs, query), stored.docs, {
      verified: true,
      mode: "full",
      cached: true,
    });
  }

  let docs: WebplusDidDocument[];
  let raw: string;

  if (stored) {
    const offset = utf8Length(stored.raw);
    const { status, text } = await fetchText(url, options, offset);
    if (status === 416) {
      // nothing new since our verified copy
      docs = stored.docs;
      raw = stored.raw;
    } else if (status === 206) {
      const newDocs = parseCanonicalOrThrow(text, url);
      const result = await validateMicroledgerExtension(stored.docs, newDocs, {
        expectedDid: did,
        ...verifierOpt,
      });
      throwOnDuplicityOrErrors(result, url, stored, newDocs);
      docs = [...stored.docs, ...newDocs];
      raw = stored.raw + rawOf(newDocs).slice(0, -1) + "\n";
    } else if (status >= 200 && status < 300) {
      // server ignored the Range header; got the full ledger
      const fetched = parseCanonicalOrThrow(text, url);
      assertNoDuplicity(stored, fetched, url);
      const newDocs = fetched.slice(stored.docs.length);
      const result = await validateMicroledgerExtension(stored.docs, newDocs, {
        expectedDid: did,
        ...verifierOpt,
      });
      throwOnValidationErrors(result, url);
      docs = [...stored.docs, ...newDocs];
      raw = rawOf(docs);
    } else if (status === 404) {
      throw new DidError(ResolutionErrorCode.NotFound, `microledger not found at ${url}`);
    } else {
      throw new DidError(ResolutionErrorCode.InternalError, `unexpected HTTP ${status} from ${url}`);
    }
  } else {
    const { status, text } = await fetchText(url, options);
    if (status === 404) {
      throw new DidError(ResolutionErrorCode.NotFound, `microledger not found at ${url}`);
    }
    if (status < 200 || status >= 300) {
      throw new DidError(ResolutionErrorCode.InternalError, `unexpected HTTP ${status} from ${url}`);
    }
    docs = parseCanonicalOrThrow(text, url);
    if (docs.length === 0) {
      throw new DidError(ResolutionErrorCode.NotFound, `microledger at ${url} is empty`);
    }
    const result = await validateMicroledger(docs, { expectedDid: did, ...verifierOpt });
    throwOnValidationErrors(result, url);
    raw = rawOf(docs);
  }

  await store?.put(did, { raw, docs });
  return successResult(selectFromMicroledger(docs, query), docs, {
    verified: true,
    mode: "full",
  });
}

function assertNoDuplicity(
  stored: StoredMicroledger,
  fetched: WebplusDidDocument[],
  url: string,
): void {
  if (fetched.length < stored.docs.length) {
    throw new DidError(
      ResolutionErrorCode.InvalidDidDocument,
      `duplicity detected at ${url}: served microledger (${fetched.length} documents) is shorter than the verified history (${stored.docs.length} documents)`,
    );
  }
  for (let i = 0; i < stored.docs.length; i++) {
    if (fetched[i]!.selfHash !== stored.docs[i]!.selfHash) {
      throw new DidError(
        ResolutionErrorCode.InvalidDidDocument,
        `duplicity detected at ${url}: versionId ${i} selfHash ${fetched[i]!.selfHash} contradicts previously verified ${stored.docs[i]!.selfHash}`,
      );
    }
  }
}

function throwOnDuplicityOrErrors(
  result: MicroledgerValidationResult,
  url: string,
  stored: StoredMicroledger,
  newDocs: WebplusDidDocument[],
): void {
  const first = newDocs[0];
  const last = stored.docs[stored.docs.length - 1]!;
  if (first && first.prevDIDDocumentSelfHash !== last.selfHash) {
    throw new DidError(
      ResolutionErrorCode.InvalidDidDocument,
      `duplicity detected at ${url}: update for versionId ${first.versionId} chains from ${first.prevDIDDocumentSelfHash}, contradicting previously verified ${last.selfHash}`,
    );
  }
  throwOnValidationErrors(result, url);
}

async function resolveThin(
  didUrlNoFragment: string,
  options: WebplusResolverOptions,
): Promise<DidResolutionResult> {
  if (!options.vdg) {
    throw new DidError(
      ResolutionErrorCode.InternalError,
      'thin mode requires a trusted VDG (spec: "Thin DID Resolver"); pass the vdg option, or use full mode',
    );
  }
  const url = vdgResolutionUrl(didUrlNoFragment, options.vdg, options);
  const doc = await fetchJson<WebplusDidDocument>(url, {
    ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
    ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
  });
  return successResult(doc, null, { verified: false, mode: "thin" });
}

async function resolveUnverified(
  did: string,
  query: WebplusDidQuery,
  options: WebplusResolverOptions,
): Promise<DidResolutionResult> {
  const docs = await fetchMicroledger(did, options);
  return successResult(selectFromMicroledger(docs, query), docs, {
    verified: false,
    mode: "unverified",
  });
}

/**
 * Resolve a did:webplus DID URL (optionally carrying `versionId`, `selfHash`,
 * or `versionTime` query parameters) to its DID document.
 *
 * The default is a **Full DID Resolver**: the DID's microledger is fetched
 * from its VDR (or a VDG) via the spec's single resolution URL
 * (`…/did-documents.jsonl`), cryptographically verified, and persisted, so
 * repeated resolution issues a range-based fetch and verifies only new
 * documents, detects duplicity (forks/rollbacks), and answers historical
 * queries offline. `mode: "thin"` delegates to a trusted VDG.
 * `mode: "unverified"` is for development/testing only.
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
    const mode = options.mode ?? "full";

    switch (mode) {
      case "thin":
        return await resolveThin(beforeFragment!, options);
      case "unverified":
        return await resolveUnverified(parsed.did, query, options);
      case "full":
        return await resolveFull(parsed.did, query, options);
    }
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
 * const resolver = new Resolver(getResolver());
 * const result = await resolver.resolve("did:webplus:example.com:uHiAg...");
 * ```
 */
export function getResolver(options: WebplusResolverOptions = {}) {
  return {
    webplus: (didUrl: string) => resolve(didUrl, options),
  };
}