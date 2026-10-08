import { DidError, ResolutionErrorCode, canonicalize, fetchJson, toErrorResult, type DidResolutionResult } from "@zkred/did-core";
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
import {
  WEBPLUS_ERROR_TYPE,
  WebplusResolutionError,
  webplusErrorResult,
  type ResolutionLocalityBooleans,
} from "./problemDetails.js";
import {
  buildDidDocumentMetadata,
  computeDocLocality,
  computeMetadataLocality,
  type WebplusResolutionOptions,
} from "./resolutionMetadata.js";
import type { WebplusDidDocument, WebplusDidQuery } from "./types.js";

/**
 * Resolver modes, in the spec's terminology:
 *
 * - `"full"` (default) — a Full DID Resolver: fetches the DID's microledger,
 *   cryptographically verifies it, and persists the verified portion so that
 *   repeated resolution is a range-based fetch verifying only new documents.
 *   Provides duplicity detection and offline historical resolution. The only
 *   mode that implements the DID Resolution Options / locality rules below.
 * - `"thin"` — a Thin DID Resolver: delegates fetching/verification/archiving
 *   to a trusted VDG (required); a single request per resolution. Fetches
 *   only the resolved document, so `requestCreate`/`requestNext`/
 *   `requestLatest`/`localResolutionOnly` are not honored.
 * - `"unverified"` — development/testing only. Fetches the microledger and
 *   enforces the JCS wire-format rule but performs NO cryptographic
 *   verification and trusts the host. Non-conformant; never use in
 *   production.
 */
export type ResolverMode = "full" | "thin" | "unverified";

export interface WebplusResolverOptions extends ResolutionUrlOptions, WebplusResolutionOptions {
  /** Resolver mode. Default: `"full"`. */
  mode?: ResolverMode;
  /**
   * Microledger persistence for full mode. Defaults to a shared in-memory
   * store (`defaultMicroledgerStore`); supply your own `MicroledgerStore`
   * for durable storage (see `FileMicroledgerStore` at the `./node`
   * subpath), or `null` to disable persistence (every resolution fetches and
   * verifies the complete microledger).
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
    throw new Error(`request to ${url} failed: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    clearTimeout(timer);
  }
}

/** Raised by the low-level fetch helpers for anything that means "couldn't get a usable response from the VDR"; reported as `VDR_FETCH_FAILED`. */
class FetchFailure extends Error {}

function invalidDidDocument(message: string, booleans: ResolutionLocalityBooleans): never {
  throw new WebplusResolutionError(WEBPLUS_ERROR_TYPE.InvalidDidDocument, message, booleans);
}

function parseCanonicalOrThrow(
  text: string,
  url: string,
  booleans: ResolutionLocalityBooleans,
): WebplusDidDocument[] {
  const { docs, errors } = parseJcsCanonicalLines(text);
  if (errors.length > 0) {
    invalidDidDocument(`microledger at ${url}: ${errors.map((e) => e.message).join("; ")}`, booleans);
  }
  return docs;
}

function throwOnValidationErrors(
  result: MicroledgerValidationResult,
  url: string,
  booleans: ResolutionLocalityBooleans,
): void {
  if (result.errors.length === 0) return;
  const detail = result.errors.map((e) => `versionId ${e.versionId}: ${e.message}`).join("; ");
  invalidDidDocument(`microledger verification failed for ${url}: ${detail}`, booleans);
}

/**
 * Canonical archived form of a verified ledger: JCS lines joined by `\n`,
 * with NO trailing newline. Its UTF-8 byte length is therefore the position
 * immediately after the final `}`, which is exactly where the spec requires
 * range-based GETs to start (so servers that omit a trailing newline in
 * did-documents.jsonl are still handled).
 */
const rawOf = (docs: WebplusDidDocument[]): string => docs.map((d) => canonicalize(d)).join("\n");

/** Normalize stored raw (possibly persisted by <=0.8.0 with a trailing newline). */
const stripTrailingNewline = (raw: string): string =>
  raw.endsWith("\n") ? raw.replace(/\r?\n$/, "") : raw;

const utf8Length = (s: string): number => new TextEncoder().encode(s).length;

/**
 * Fetch a DID's complete microledger from its VDR (or a VDG), enforcing the
 * JCS wire-format rule. Performs a full (non-range) fetch and no
 * cryptographic verification; used by `mode: "unverified"`.
 */
export async function fetchMicroledger(
  did: string,
  options: WebplusResolverOptions = {},
): Promise<WebplusDidDocument[]> {
  const url = ledgerUrlFor(did, options);
  const booleans: ResolutionLocalityBooleans = {
    didDocumentResolvedLocally: false,
    didDocumentMetadataResolvedLocally: true,
    fetchedUpdatesFromVDR: true,
  };
  let status: number, text: string;
  try {
    ({ status, text } = await fetchText(url, options));
  } catch (err) {
    throw new WebplusResolutionError(
      WEBPLUS_ERROR_TYPE.VdrFetchFailed,
      err instanceof Error ? err.message : String(err),
      booleans,
    );
  }
  if (status === 404) {
    throw new WebplusResolutionError(WEBPLUS_ERROR_TYPE.NotFound, `microledger not found at ${url}`, booleans);
  }
  if (status < 200 || status >= 300) {
    throw new WebplusResolutionError(
      WEBPLUS_ERROR_TYPE.VdrFetchFailed,
      `unexpected HTTP ${status} from ${url}`,
      booleans,
    );
  }
  const docs = parseCanonicalOrThrow(text, url, booleans);
  if (docs.length === 0) {
    throw new WebplusResolutionError(WEBPLUS_ERROR_TYPE.NotFound, `microledger at ${url} is empty`, booleans);
  }
  return docs;
}

/**
 * Select the document a DID URL query refers to from a full microledger.
 * Throws `invalidDidUrl` if `selfHash` and `versionId` are both given and
 * name different documents, `notFound` if the query matches nothing.
 */
export function selectFromMicroledger(
  docs: WebplusDidDocument[],
  query: WebplusDidQuery,
  booleans: ResolutionLocalityBooleans = {
    didDocumentResolvedLocally: false,
    didDocumentMetadataResolvedLocally: true,
    fetchedUpdatesFromVDR: true,
  },
): WebplusDidDocument {
  if (query.selfHash !== undefined && query.versionId !== undefined) {
    const known =
      docs.find((d) => d.selfHash === query.selfHash) ?? docs.find((d) => d.versionId === query.versionId);
    if (known && (known.selfHash !== query.selfHash || known.versionId !== query.versionId)) {
      throw new WebplusResolutionError(
        WEBPLUS_ERROR_TYPE.InvalidDidUrl,
        `selfHash ${query.selfHash} and versionId ${query.versionId} name different documents`,
        booleans,
      );
    }
  }
  if (query.selfHash !== undefined) {
    const doc = docs.find((d) => d.selfHash === query.selfHash);
    if (!doc) {
      throw new WebplusResolutionError(
        WEBPLUS_ERROR_TYPE.NotFound,
        `no document with selfHash ${query.selfHash}`,
        booleans,
      );
    }
    return doc;
  }
  if (query.versionId !== undefined) {
    const doc = docs.find((d) => d.versionId === query.versionId);
    if (!doc) {
      throw new WebplusResolutionError(
        WEBPLUS_ERROR_TYPE.NotFound,
        `no document with versionId ${query.versionId}`,
        booleans,
      );
    }
    return doc;
  }
  if (query.versionTime !== undefined) {
    const t = Date.parse(query.versionTime);
    const doc = [...docs].reverse().find((d) => Date.parse(d.validFrom) <= t);
    if (!doc) {
      throw new WebplusResolutionError(
        WEBPLUS_ERROR_TYPE.NotFound,
        `no document was valid at versionTime ${query.versionTime}`,
        booleans,
      );
    }
    return doc;
  }
  return docs[docs.length - 1]!;
}

function successResult(
  doc: WebplusDidDocument,
  allDocs: WebplusDidDocument[],
  options: WebplusResolutionOptions,
  booleans: ResolutionLocalityBooleans,
): DidResolutionResult {
  return {
    didResolutionMetadata: { contentType: "application/did+json", ...booleans },
    didDocument: doc,
    didDocumentMetadata: buildDidDocumentMetadata(doc, allDocs, options),
  };
}

function assertNoDuplicity(
  stored: StoredMicroledger,
  fetched: WebplusDidDocument[],
  url: string,
  booleans: ResolutionLocalityBooleans,
): void {
  if (fetched.length < stored.docs.length) {
    invalidDidDocument(
      `duplicity detected at ${url}: served microledger (${fetched.length} documents) is shorter than the verified history (${stored.docs.length} documents)`,
      booleans,
    );
  }
  for (let i = 0; i < stored.docs.length; i++) {
    if (fetched[i]!.selfHash !== stored.docs[i]!.selfHash) {
      invalidDidDocument(
        `duplicity detected at ${url}: versionId ${i} selfHash ${fetched[i]!.selfHash} contradicts previously verified ${stored.docs[i]!.selfHash}`,
        booleans,
      );
    }
  }
}

function throwOnDuplicityOrErrors(
  result: MicroledgerValidationResult,
  url: string,
  stored: StoredMicroledger,
  newDocs: WebplusDidDocument[],
  booleans: ResolutionLocalityBooleans,
): void {
  const first = newDocs[0];
  const last = stored.docs[stored.docs.length - 1]!;
  if (first && first.prevDIDDocumentSelfHash !== last.selfHash) {
    invalidDidDocument(
      `duplicity detected at ${url}: update for versionId ${first.versionId} chains from ${first.prevDIDDocumentSelfHash}, contradicting previously verified ${last.selfHash}`,
      booleans,
    );
  }
  throwOnValidationErrors(result, url, booleans);
}

/**
 * Fetch whatever is new since `stored` (or the whole microledger when
 * `stored` is undefined), verify it, and return the merged document list.
 * Throws `FetchFailure` for anything that means the VDR couldn't be reached
 * or read usefully (network error, an unexpected status, a 404 continuing a
 * known history), which `resolveFull` reports as `VDR_FETCH_FAILED`.
 * Verification/duplicity failures throw `WebplusResolutionError` directly.
 */
async function fetchAndMergeMicroledger(
  did: string,
  url: string,
  stored: StoredMicroledger | undefined,
  options: WebplusResolverOptions,
  verifierOpt: { verifier?: CryptoVerifier | null },
  booleans: ResolutionLocalityBooleans,
): Promise<WebplusDidDocument[]> {
  if (stored) {
    const storedRaw = stripTrailingNewline(stored.raw);
    // Spec: the range MUST start immediately after the final `}` of the last
    // archived document (byte 0 when nothing is archived).
    const offset = utf8Length(storedRaw);
    let status: number, text: string;
    try {
      ({ status, text } = await fetchText(url, options, offset));
    } catch (err) {
      throw new FetchFailure(err instanceof Error ? err.message : String(err));
    }
    if (status === 416) {
      return stored.docs; // nothing new since our verified copy
    }
    if (status === 206) {
      // The chunk begins with the newline separating the last archived
      // document from any new ones (strip that separator byte before strict
      // JSONL parsing); a bare newline (or empty chunk) means the server has
      // nothing new but does store a trailing newline.
      const chunk = text.startsWith("\n") ? text.slice(1) : text;
      const newDocs = parseCanonicalOrThrow(chunk, url, booleans);
      if (newDocs.length === 0) return stored.docs;
      const result = await validateMicroledgerExtension(stored.docs, newDocs, {
        expectedDid: did,
        ...verifierOpt,
      });
      throwOnDuplicityOrErrors(result, url, stored, newDocs, booleans);
      return [...stored.docs, ...newDocs];
    }
    if (status >= 200 && status < 300) {
      // server ignored the Range header; got the full ledger
      const fetched = parseCanonicalOrThrow(text, url, booleans);
      assertNoDuplicity(stored, fetched, url, booleans);
      const newDocs = fetched.slice(stored.docs.length);
      const result = await validateMicroledgerExtension(stored.docs, newDocs, {
        expectedDid: did,
        ...verifierOpt,
      });
      throwOnValidationErrors(result, url, booleans);
      return [...stored.docs, ...newDocs];
    }
    // Any other status (including 404) while continuing a known history: the
    // VDR may be transiently broken, which is a fetch failure rather than a
    // definitive notFound.
    throw new FetchFailure(`unexpected HTTP ${status} from ${url}`);
  }

  let status: number, text: string;
  try {
    ({ status, text } = await fetchText(url, options));
  } catch (err) {
    throw new FetchFailure(err instanceof Error ? err.message : String(err));
  }
  if (status === 404) {
    // No prior local data, and the VDR affirmatively has nothing: a
    // definitive answer, not a transient fetch failure.
    throw new WebplusResolutionError(WEBPLUS_ERROR_TYPE.NotFound, `microledger not found at ${url}`, booleans);
  }
  if (status < 200 || status >= 300) {
    throw new FetchFailure(`unexpected HTTP ${status} from ${url}`);
  }
  const docs = parseCanonicalOrThrow(text, url, booleans);
  if (docs.length === 0) {
    throw new WebplusResolutionError(WEBPLUS_ERROR_TYPE.NotFound, `microledger at ${url} is empty`, booleans);
  }
  const result = await validateMicroledger(docs, { expectedDid: did, ...verifierOpt });
  throwOnValidationErrors(result, url, booleans);
  return docs;
}

async function resolveFull(
  did: string,
  query: WebplusDidQuery,
  options: WebplusResolverOptions,
): Promise<DidResolutionResult> {
  const store = options.store === null ? undefined : (options.store ?? defaultMicroledgerStore);
  const stored = await store?.get(did);
  const localDocs = stored?.docs ?? [];
  const url = ledgerUrlFor(did, options);
  const verifierOpt = options.verifier !== undefined ? { verifier: options.verifier } : {};

  const locality = computeDocLocality(localDocs, query);

  if (locality.status === "conflict") {
    throw new WebplusResolutionError(
      WEBPLUS_ERROR_TYPE.InvalidDidUrl,
      "selfHash and versionId in the same query name different local documents",
      { didDocumentResolvedLocally: false, didDocumentMetadataResolvedLocally: true, fetchedUpdatesFromVDR: false },
    );
  }
  if (locality.status === "known-absent") {
    throw new WebplusResolutionError(
      WEBPLUS_ERROR_TYPE.NotFound,
      "a local deactivation proves the requested document does not exist",
      { didDocumentResolvedLocally: false, didDocumentMetadataResolvedLocally: true, fetchedUpdatesFromVDR: false },
    );
  }

  const resolvedLocally = locality.status === "found" ? locality.doc : undefined;
  const metadataLocal = computeMetadataLocality(localDocs, resolvedLocally, options);
  const needsFetch = resolvedLocally === undefined || !metadataLocal;
  const preFetchBooleans: ResolutionLocalityBooleans = {
    didDocumentResolvedLocally: resolvedLocally !== undefined,
    didDocumentMetadataResolvedLocally: metadataLocal,
    fetchedUpdatesFromVDR: false,
  };

  if (!needsFetch) {
    return successResult(resolvedLocally!, localDocs, options, preFetchBooleans);
  }

  if (options.localResolutionOnly) {
    throw new WebplusResolutionError(
      WEBPLUS_ERROR_TYPE.LocalResolutionNotPossible,
      "localResolutionOnly is set and the requested document or metadata is not locally satisfiable",
      preFetchBooleans,
    );
  }

  const fetchedBooleans: ResolutionLocalityBooleans = { ...preFetchBooleans, fetchedUpdatesFromVDR: true };

  let allDocs: WebplusDidDocument[];
  try {
    allDocs = await fetchAndMergeMicroledger(did, url, stored, options, verifierOpt, fetchedBooleans);
  } catch (err) {
    if (err instanceof FetchFailure) {
      // Fail closed. A fetch is only attempted when the local prefix can't
      // answer on its own (a plain DID, or metadata such as latest/next/
      // deactivated that needs fresh data), so answering from local data here
      // would let anyone who can block the VDR serve a rotated-out key or
      // hide a deactivation behind a "successful" resolution.
      throw new WebplusResolutionError(WEBPLUS_ERROR_TYPE.VdrFetchFailed, err.message, fetchedBooleans);
    }
    throw err;
  }

  await store?.put(did, { raw: rawOf(allDocs), docs: allDocs });
  const finalDoc = selectFromMicroledger(allDocs, query, fetchedBooleans);
  return successResult(finalDoc, allDocs, options, fetchedBooleans);
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
  // Thin mode fetches only the resolved document, not the full microledger,
  // so create/next/latest metadata (which need the rest of the history)
  // can't be honored here regardless of what was requested.
  return successResult(doc, [doc], {}, {
    didDocumentResolvedLocally: false,
    didDocumentMetadataResolvedLocally: true,
    fetchedUpdatesFromVDR: true,
  });
}

async function resolveUnverified(
  did: string,
  query: WebplusDidQuery,
  options: WebplusResolverOptions,
): Promise<DidResolutionResult> {
  const docs = await fetchMicroledger(did, options);
  const booleans: ResolutionLocalityBooleans = {
    didDocumentResolvedLocally: false,
    didDocumentMetadataResolvedLocally: true,
    fetchedUpdatesFromVDR: true,
  };
  return successResult(selectFromMicroledger(docs, query, booleans), docs, options, booleans);
}

/**
 * Resolve a did:webplus DID URL (optionally carrying `versionId`, `selfHash`,
 * or `versionTime` query parameters) to its DID document.
 *
 * The default is a **Full DID Resolver**: the DID's microledger is fetched
 * from its VDR (or a VDG) via the spec's single resolution URL
 * (`…/did-documents.jsonl`), cryptographically verified, and persisted, so
 * repeated resolution issues a range-based fetch and verifies only new
 * documents, detects duplicity (forks/rollbacks), and answers queries
 * already satisfiable from local data with zero network requests. The five
 * DID Resolution Options (`requestCreate`, `requestNext`, `requestLatest`,
 * `requestDeactivated`, `localResolutionOnly`) are honored in this mode.
 * `mode: "thin"` delegates to a trusted VDG. `mode: "unverified"` is for
 * development/testing only.
 *
 * Resolution-process failures (not found, conflicting query parameters,
 * local resolution not possible, VDR unreachable, failed verification) carry
 * an RFC 9457 Problem Details object as `didResolutionMetadata.error`,
 * matching the spec's reference implementations. A malformed DID string
 * (a syntax error, before resolution begins) still carries the standard
 * `@zkred/did-core` short error code.
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
    if (err instanceof WebplusResolutionError) {
      return webplusErrorResult(err);
    }
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
