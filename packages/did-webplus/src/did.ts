import { DidError, ResolutionErrorCode } from "@zkred/did-core";
import type { ParsedWebplusDid, WebplusDidQuery } from "./types.js";

const METHOD_PREFIX = "did:webplus:";

/**
 * Self-hashes are multibase base64url (prefix `u`) values produced by the
 * `selfhash` self-addressing scheme, e.g. `uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ`.
 */
const SELF_HASH_PATTERN = /^u[A-Za-z0-9_-]{20,}$/;

const HOST_PATTERN = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i;

export function isSelfHash(value: string): boolean {
  return SELF_HASH_PATTERN.test(value);
}

/**
 * Parse a did:webplus DID of the form:
 *
 *   did:webplus:<host>[%3A<port>][:<path>...]:<root-self-hash>
 *
 * The final component is always the self-hash of the root DID document.
 * Query and fragment parts must be stripped before calling (see `parseQuery`).
 */
export function parseDid(did: string): ParsedWebplusDid {
  if (!did.startsWith(METHOD_PREFIX)) {
    throw new DidError(ResolutionErrorCode.InvalidDid, `not a did:webplus DID: ${did}`);
  }
  const methodSpecificId = did.slice(METHOD_PREFIX.length);
  if (methodSpecificId.includes("?") || methodSpecificId.includes("#") || methodSpecificId.includes("/")) {
    throw new DidError(
      ResolutionErrorCode.InvalidDid,
      `DID must not contain query, fragment, or path separators: ${did}`,
    );
  }

  const components = methodSpecificId.split(":");
  if (components.length < 2) {
    throw new DidError(
      ResolutionErrorCode.InvalidDid,
      `expected at least host and root self-hash components: ${did}`,
    );
  }

  const hostComponent = decodeURIComponent(components[0]!);
  const rootSelfHash = components[components.length - 1]!;
  const path = components.slice(1, -1);

  let host = hostComponent;
  let port: number | undefined;
  const colonIndex = hostComponent.indexOf(":");
  if (colonIndex !== -1) {
    host = hostComponent.slice(0, colonIndex);
    port = Number(hostComponent.slice(colonIndex + 1));
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new DidError(ResolutionErrorCode.InvalidDid, `invalid port in DID host: ${did}`);
    }
  }
  if (!HOST_PATTERN.test(host)) {
    throw new DidError(ResolutionErrorCode.InvalidDid, `invalid host in DID: ${did}`);
  }
  if (!isSelfHash(rootSelfHash)) {
    throw new DidError(
      ResolutionErrorCode.InvalidDid,
      `last DID component is not a valid self-hash: ${did}`,
    );
  }
  for (const segment of path) {
    if (segment.length === 0) {
      throw new DidError(ResolutionErrorCode.InvalidDid, `empty path component in DID: ${did}`);
    }
  }

  return { did, host, ...(port !== undefined ? { port } : {}), path, rootSelfHash };
}

/** Format DID components back into a did:webplus DID string. */
export function formatDid(input: Omit<ParsedWebplusDid, "did">): string {
  const hostComponent = input.port !== undefined ? `${input.host}%3A${input.port}` : input.host;
  return [METHOD_PREFIX.slice(0, -1), hostComponent, ...input.path, input.rootSelfHash].join(":");
}

/** Parse the query portion of a did:webplus DID URL (e.g. `versionId=2&selfHash=uHiA...`). */
export function parseQuery(query: string | undefined): WebplusDidQuery {
  if (!query) return {};
  const params = new URLSearchParams(query);
  const result: WebplusDidQuery = {};

  const versionId = params.get("versionId");
  if (versionId !== null) {
    const n = Number(versionId);
    if (!Number.isInteger(n) || n < 0) {
      throw new DidError(ResolutionErrorCode.InvalidDid, `invalid versionId query: ${versionId}`);
    }
    result.versionId = n;
  }
  const selfHash = params.get("selfHash");
  if (selfHash !== null) {
    if (!isSelfHash(selfHash)) {
      throw new DidError(ResolutionErrorCode.InvalidDid, `invalid selfHash query: ${selfHash}`);
    }
    result.selfHash = selfHash;
  }
  const versionTime = params.get("versionTime");
  if (versionTime !== null) {
    if (Number.isNaN(Date.parse(versionTime))) {
      throw new DidError(ResolutionErrorCode.InvalidDid, `invalid versionTime query: ${versionTime}`);
    }
    result.versionTime = versionTime;
  }
  return result;
}

export interface ResolutionUrlOptions {
  /**
   * URL scheme. Defaults to `https`; `http` is intended only for local
   * development against a VDR on localhost.
   */
  scheme?: "https" | "http";
}

/**
 * Map a parsed DID (plus optional query) to the URL of the DID document
 * hosted by the VDR:
 *
 *   latest:      https://<host>/<path...>/<rootSelfHash>/did.json
 *   by version:  https://<host>/<path...>/<rootSelfHash>/did/versionId/<n>.json
 *   by selfHash: https://<host>/<path...>/<rootSelfHash>/did/selfHash/<hash>.json
 */
export function resolutionUrl(
  parsed: ParsedWebplusDid,
  query: WebplusDidQuery = {},
  options: ResolutionUrlOptions = {},
): string {
  const scheme = options.scheme ?? "https";
  const authority = parsed.port !== undefined ? `${parsed.host}:${parsed.port}` : parsed.host;
  const base = [`${scheme}:/`, authority, ...parsed.path, parsed.rootSelfHash].join("/");

  if (query.selfHash !== undefined) {
    return `${base}/did/selfHash/${query.selfHash}.json`;
  }
  if (query.versionId !== undefined) {
    return `${base}/did/versionId/${query.versionId}.json`;
  }
  return `${base}/did.json`;
}