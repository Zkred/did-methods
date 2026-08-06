import {
  DidError,
  ResolutionErrorCode,
  type DidResolutionResult,
} from "@zkred/did-core";

/**
 * did:cid resolution as a `did-resolver` plugin.
 *
 * did:cid (https://github.com/archetech/archon, DIF Recommended) is
 * content-addressed: the method-specific identifier is a CIDv1 in base32.
 * Resolution and update-tracking are performed by an Archon **gatekeeper**
 * node, which exposes a standards-conformant resolution endpoint at
 * `GET /1.0/identifiers/{did}` returning the W3C resolution result triple.
 *
 * This package is deliberately a thin client: you point it at a gatekeeper
 * you trust (your own node, typically), and it maps DID URLs onto that
 * endpoint. Verification of the content-addressed history is the
 * gatekeeper's job, analogous to a did:webplus Thin DID Resolver trusting
 * its VDG.
 */

/** `did:cid:` followed by a CIDv1 in standard base32 (multibase prefix `b`). */
const DID_CID_PATTERN = /^did:cid:b[a-z2-7]{20,}$/;

export function isDidCid(did: string): boolean {
  return DID_CID_PATTERN.test(did);
}

export interface DidCidResolverOptions {
  /**
   * Base URL of the Archon gatekeeper to resolve through, e.g.
   * `https://gatekeeper.example.com`. Required: choosing which gatekeeper to
   * trust is the method's central trust decision, so there is no default.
   */
  gatekeeperUrl: string;
  /** Request timeout in milliseconds. Default: 15000. */
  timeoutMs?: number;
  /** Custom fetch implementation (for testing or non-standard environments). */
  fetchImpl?: typeof fetch;
}

interface ParsedDidCidUrl {
  did: string;
  /** Method-defined dereferenceable resource path, e.g. "/data". */
  path: string;
  /** Query string without the leading "?", passed through to the gatekeeper. */
  query: string;
}

function parseDidCidUrl(didUrl: string): ParsedDidCidUrl {
  const [beforeFragment] = didUrl.split("#");
  const [beforeQuery, ...queryParts] = beforeFragment!.split("?");
  const query = queryParts.join("?");
  const pathStart = beforeQuery!.indexOf("/");
  const did = pathStart === -1 ? beforeQuery! : beforeQuery!.slice(0, pathStart);
  const path = pathStart === -1 ? "" : beforeQuery!.slice(pathStart);
  if (!isDidCid(did)) {
    throw new DidError(
      ResolutionErrorCode.InvalidDid,
      `not a did:cid DID (expected did:cid:<CIDv1 base32>): ${did}`,
    );
  }
  return { did, path, query };
}

/** Allowed resolution query parameters, passed through to the gatekeeper. */
const PASSTHROUGH_PARAMS = ["versionTime", "versionSequence", "service", "relativeRef"];

function passthroughQuery(query: string): string {
  if (!query) return "";
  const source = new URLSearchParams(query);
  const out = new URLSearchParams();
  for (const name of PASSTHROUGH_PARAMS) {
    const value = source.get(name);
    if (value !== null) out.set(name, value);
  }
  const s = out.toString();
  return s ? `?${s}` : "";
}

function endpointUrl(options: DidCidResolverOptions, did: string, path: string, query: string): string {
  const base = options.gatekeeperUrl.replace(/\/+$/, "");
  return `${base}/1.0/identifiers/${encodeURIComponent(did)}${path}${passthroughQuery(query)}`;
}

async function fetchFromGatekeeper(
  url: string,
  options: DidCidResolverOptions,
): Promise<{ status: number; body: unknown }> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 15_000);
  try {
    const response = await fetchImpl(url, {
      headers: { accept: "application/did+ld+json, application/did+json, application/json" },
      signal: controller.signal,
    });
    let body: unknown = null;
    try {
      body = await response.json();
    } catch {
      body = null;
    }
    return { status: response.status, body };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new DidError(ResolutionErrorCode.InternalError, `request to ${url} failed: ${message}`);
  } finally {
    clearTimeout(timer);
  }
}

function isResolutionTriple(body: unknown): body is DidResolutionResult {
  return (
    typeof body === "object" &&
    body !== null &&
    "didResolutionMetadata" in body &&
    "didDocument" in body
  );
}

function errorResult(error: string, message: string): DidResolutionResult {
  return {
    didResolutionMetadata: { error, message },
    didDocument: null,
    didDocumentMetadata: {},
  };
}

/**
 * Resolve a did:cid DID URL through the configured gatekeeper. The
 * gatekeeper's standards-conformant resolution result (including its error
 * triples for 400/404) is passed through unchanged.
 */
export async function resolve(
  didUrl: string,
  options: DidCidResolverOptions,
): Promise<DidResolutionResult> {
  if (!options?.gatekeeperUrl) {
    return errorResult(
      "internalError",
      "did:cid resolution requires a gatekeeperUrl (the Archon gatekeeper node you trust)",
    );
  }
  try {
    const { did, query } = parseDidCidUrl(didUrl);
    const { body } = await fetchFromGatekeeper(endpointUrl(options, did, "", query), options);
    if (isResolutionTriple(body)) {
      return body;
    }
    return errorResult("notFound", `gatekeeper returned no resolution result for ${did}`);
  } catch (err) {
    if (err instanceof DidError) {
      return errorResult(err.code, err.message);
    }
    return errorResult("internalError", err instanceof Error ? err.message : String(err));
  }
}

/**
 * Dereference a did:cid method-defined resource (`/data` or `/registration`)
 * through the gatekeeper, returning the resource JSON. Throws `DidError` on
 * failure.
 */
export async function dereference(
  didUrl: string,
  options: DidCidResolverOptions,
): Promise<unknown> {
  const { did, path, query } = parseDidCidUrl(didUrl);
  if (path !== "/data" && path !== "/registration") {
    throw new DidError(
      ResolutionErrorCode.InvalidDid,
      `did:cid defines the dereferenceable resources /data and /registration; got: ${path || "(none)"}`,
    );
  }
  const { status, body } = await fetchFromGatekeeper(
    endpointUrl(options, did, path, query),
    options,
  );
  if (status === 404) {
    throw new DidError(ResolutionErrorCode.NotFound, `no ${path} resource for ${did}`);
  }
  if (status < 200 || status >= 300) {
    throw new DidError(ResolutionErrorCode.InternalError, `gatekeeper returned HTTP ${status} for ${didUrl}`);
  }
  return body;
}

/**
 * Build a `did-resolver`-compatible registry entry:
 *
 * ```ts
 * import { Resolver } from "did-resolver";
 * import { getResolver } from "@zkred/did-cid";
 *
 * const resolver = new Resolver(getResolver({ gatekeeperUrl: "https://my-gatekeeper.example" }));
 * const result = await resolver.resolve("did:cid:bafkreiawdmk6fmqc5p237vffyctazpzdgvgqfdj2i3hx2idtodxkwhyj5m");
 * ```
 */
export function getResolver(options: DidCidResolverOptions) {
  return {
    cid: (didUrl: string) => resolve(didUrl, options),
  };
}
