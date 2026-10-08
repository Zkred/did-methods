import type { DidResolutionResult } from "@zkred/did-core";

/**
 * did:webplus resolution-process error types (RFC 9457 Problem Details).
 * Unlike the generic did-resolver convention of a short ASCII error code,
 * the did:webplus reference implementations (Rust and Python) emit a full
 * Problem Details object for `didResolutionMetadata.error`; this package
 * matches that for interop. DID-syntax errors (a malformed DID string,
 * before resolution begins) are unaffected and keep the standard
 * `@zkred/did-core` string codes.
 */
export const WEBPLUS_ERROR_TYPE = {
  NotFound: "https://www.w3.org/ns/did#NOT_FOUND",
  InvalidDidUrl: "https://www.w3.org/ns/did#INVALID_DID_URL",
  LocalResolutionNotPossible:
    "https://ledgerdomain.github.io/did-webplus-spec#LOCAL_RESOLUTION_NOT_POSSIBLE",
  VdrFetchFailed: "https://ledgerdomain.github.io/did-webplus-spec#VDR_FETCH_FAILED",
  InvalidDidDocument: "https://www.w3.org/ns/did#INVALID_DID_DOCUMENT",
} as const;

export type WebplusErrorType = (typeof WEBPLUS_ERROR_TYPE)[keyof typeof WEBPLUS_ERROR_TYPE];

const TITLE_BY_TYPE: Record<WebplusErrorType, string> = {
  [WEBPLUS_ERROR_TYPE.NotFound]: "Not Found",
  [WEBPLUS_ERROR_TYPE.InvalidDidUrl]: "Invalid DID URL",
  [WEBPLUS_ERROR_TYPE.LocalResolutionNotPossible]: "Local Resolution Not Possible",
  [WEBPLUS_ERROR_TYPE.VdrFetchFailed]: "VDR Fetch Failed",
  [WEBPLUS_ERROR_TYPE.InvalidDidDocument]: "Invalid DID Document",
};

export interface WebplusProblemDetails {
  type: WebplusErrorType;
  title: string;
  detail: string;
}

/** The three did:webplus-specific `didResolutionMetadata` booleans, fixed at the pre-fetch determination. */
export interface ResolutionLocalityBooleans {
  didDocumentResolvedLocally: boolean;
  didDocumentMetadataResolvedLocally: boolean;
  fetchedUpdatesFromVDR: boolean;
}

/**
 * A did:webplus resolution-process failure. Carries the resolution-locality
 * booleans determined at the throw site, since they depend on what was known
 * locally *before* the operation that failed (a later top-level catch cannot
 * reconstruct that context).
 */
export class WebplusResolutionError extends Error {
  readonly type: WebplusErrorType;
  readonly booleans: ResolutionLocalityBooleans;

  constructor(type: WebplusErrorType, detail: string, booleans: ResolutionLocalityBooleans) {
    super(detail);
    this.name = "WebplusResolutionError";
    this.type = type;
    this.booleans = booleans;
  }

  toProblemDetails(): WebplusProblemDetails {
    return { type: this.type, title: TITLE_BY_TYPE[this.type], detail: this.message };
  }
}

export function webplusErrorResult(err: WebplusResolutionError): DidResolutionResult {
  return {
    didResolutionMetadata: { error: err.toProblemDetails(), ...err.booleans },
    didDocument: null,
    didDocumentMetadata: {},
  };
}
