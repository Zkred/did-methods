import { fetchJson, toErrorResult, type DidResolutionResult } from "@zkred/did-core";
import { parseDid, parseQuery, resolutionUrl, type ResolutionUrlOptions } from "./did.js";
import type { WebplusDidDocument } from "./types.js";

export interface WebplusResolverOptions extends ResolutionUrlOptions {
  /** Request timeout in milliseconds. Default: 15000. */
  timeoutMs?: number;
  /** Custom fetch implementation (for testing or non-standard environments). */
  fetchImpl?: typeof fetch;
}

/**
 * Resolve a did:webplus DID URL (optionally carrying `versionId`, `selfHash`,
 * or `versionTime` query parameters) to its DID document.
 *
 * Note: this fetches and structurally checks the requested DID document.
 * Fetching the full microledger and cryptographically verifying it
 * (self-hashes and update proofs) is exposed separately via
 * `validateMicroledger` and will be integrated here as verification support
 * lands.
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

    const url = resolutionUrl(parsed, query, options);
    const doc = await fetchJson<WebplusDidDocument>(url, {
      ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
      ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
    });

    return {
      didResolutionMetadata: { contentType: "application/did+json" },
      didDocument: doc,
      didDocumentMetadata: {
        versionId: String(doc.versionId),
        updated: doc.validFrom,
        selfHash: doc.selfHash,
      },
    };
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