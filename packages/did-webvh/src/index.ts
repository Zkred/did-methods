import type { DidDocument, DidResolutionResult } from "@zkred/did-core";
import { resolveDID } from "didwebvh-ts";

export {
  createDID,
  updateDID,
  deactivateDID,
  resolveDID,
  resolveDIDFromLog,
} from "didwebvh-ts";

type WebvhResolveOptions = NonNullable<Parameters<typeof resolveDID>[1]>;

/** Map a DID URL's query parameters onto didwebvh-ts resolution options. */
function queryToOptions(didUrl: string): WebvhResolveOptions {
  const queryStart = didUrl.indexOf("?");
  if (queryStart === -1) return {};
  const params = new URLSearchParams(didUrl.slice(queryStart + 1));
  const options: WebvhResolveOptions = {};

  const versionId = params.get("versionId");
  if (versionId !== null) options.versionId = versionId;
  const versionNumber = params.get("versionNumber");
  if (versionNumber !== null) options.versionNumber = Number(versionNumber);
  const versionTime = params.get("versionTime");
  if (versionTime !== null) options.versionTime = new Date(versionTime);
  return options;
}

/**
 * Resolve a did:webvh DID URL to a spec-shaped DID resolution result.
 *
 * This is a thin adapter over `didwebvh-ts` (the DIF-maintained
 * implementation), reshaping its output into the W3C
 * `DidResolutionResult` structure used by the `did-resolver` ecosystem.
 */
export async function resolve(
  didUrl: string,
  options: WebvhResolveOptions = {},
): Promise<DidResolutionResult> {
  const [did] = didUrl.split("#");
  const { doc, meta } = await resolveDID(did!.split("?")[0]!, {
    ...queryToOptions(didUrl),
    ...options,
  });

  if (meta.error) {
    return {
      didResolutionMetadata: {
        error: meta.error,
        ...(meta.problemDetails ? { message: meta.problemDetails.detail } : {}),
      },
      didDocument: null,
      didDocumentMetadata: {},
    };
  }

  return {
    didResolutionMetadata: { contentType: "application/did+json" },
    didDocument: doc as DidDocument,
    didDocumentMetadata: {
      versionId: meta.versionId,
      created: meta.created,
      updated: meta.updated,
      deactivated: meta.deactivated,
      scid: meta.scid,
    },
  };
}

/**
 * Build a `did-resolver`-compatible registry entry:
 *
 * ```ts
 * import { Resolver } from "did-resolver";
 * import { getResolver } from "@zkred/did-webvh";
 *
 * const resolver = new Resolver(getResolver());
 * const result = await resolver.resolve("did:webvh:Qma6mc1...:example.com");
 * ```
 */
export function getResolver(options: WebvhResolveOptions = {}) {
  return {
    webvh: (didUrl: string) => resolve(didUrl, options),
  };
}