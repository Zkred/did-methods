import type { DidResolutionResult } from "./types.js";

/** Standard DID resolution error codes (W3C DID Core + DID Resolution spec). */
export const ResolutionErrorCode = {
  InvalidDid: "invalidDid",
  InvalidDidDocument: "invalidDidDocument",
  NotFound: "notFound",
  RepresentationNotSupported: "representationNotSupported",
  MethodNotSupported: "methodNotSupported",
  InternalError: "internalError",
} as const;

export type ResolutionErrorCode = (typeof ResolutionErrorCode)[keyof typeof ResolutionErrorCode];

export class DidError extends Error {
  readonly code: ResolutionErrorCode;

  constructor(code: ResolutionErrorCode, message: string) {
    super(message);
    this.name = "DidError";
    this.code = code;
  }
}

/** Build a spec-shaped resolution result carrying an error. */
export function errorResult(code: ResolutionErrorCode, message?: string): DidResolutionResult {
  return {
    didResolutionMetadata: message ? { error: code, message } : { error: code },
    didDocument: null,
    didDocumentMetadata: {},
  };
}

/** Convert any thrown value into a resolution error result. */
export function toErrorResult(err: unknown): DidResolutionResult {
  if (err instanceof DidError) {
    return errorResult(err.code, err.message);
  }
  const message = err instanceof Error ? err.message : String(err);
  return errorResult(ResolutionErrorCode.InternalError, message);
}