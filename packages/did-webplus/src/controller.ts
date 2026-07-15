import { DidError, ResolutionErrorCode, canonicalize, utf8Encode } from "@zkred/did-core";
import { formatDid, parseDid, schemeForHost, type ResolutionUrlOptions } from "./did.js";
import {
  formatMbPubKey,
  hashWithFunction,
  placeholderForFunction,
  placeholderMbHash,
  type CurveName,
  type HashFunctionName,
} from "./multiformat.js";
import { selfHashDocument } from "./selfhash.js";
import { publicKeyJwkParams, signProof, type SigningKeyPair } from "./sign.js";
import type { UpdateRules, WebplusDidDocument } from "./types.js";
import type { VerificationMethod } from "@zkred/did-core";

export type KeyPurpose =
  | "authentication"
  | "assertionMethod"
  | "keyAgreement"
  | "capabilityInvocation"
  | "capabilityDelegation";

const ALL_PURPOSES: KeyPurpose[] = [
  "authentication",
  "assertionMethod",
  "keyAgreement",
  "capabilityInvocation",
  "capabilityDelegation",
];

/** A verification method to include in a DID document. */
export interface VerificationKey {
  /** Raw public key bytes: 32 for Ed25519, 33 (compressed point) for EC curves. */
  publicKey: Uint8Array;
  /** Signature curve. Defaults to Ed25519. */
  curve?: CurveName;
  /** Key purposes this key serves. Defaults to all five. */
  purposes?: KeyPurpose[];
}

/** Build a `{ key }` update rule authorizing this public key directly. */
export function keyRule(publicKey: Uint8Array, curve: CurveName = "ed25519"): UpdateRules {
  return { key: formatMbPubKey(publicKey, curve) };
}

/**
 * Build a `{ hashedKey }` update rule: the key is committed to by hash and
 * only revealed when used (pre-rotation). The hash is computed over the
 * multibase string bytes of the public key, per the reference implementation.
 */
export function hashedKeyRule(
  publicKey: Uint8Array,
  hashFunction: HashFunctionName = "blake3",
  curve: CurveName = "ed25519",
): UpdateRules {
  return {
    hashedKey: hashWithFunction(hashFunction, utf8Encode(formatMbPubKey(publicKey, curve))),
  };
}

export interface CreateDidDocumentOptions {
  /** VDR hostname, e.g. `example.com`. */
  host: string;
  /** VDR port when non-standard (percent-encoded into the DID). */
  port?: number;
  /** Optional path components between host and root self-hash. */
  path?: string[];
  /** Verification methods to include. */
  keys: VerificationKey[];
  /** Rules that authorize the *next* update. Use `keyRule`/`hashedKeyRule` helpers. */
  updateRules: UpdateRules;
  /** RFC 3339 timestamp; defaults to now. */
  validFrom?: string;
  /** Hash function for the self-hash. Defaults to BLAKE3, matching the reference implementation. */
  hashFunction?: HashFunctionName;
  /** Optional signers producing root-level proofs (not required by the spec). */
  signers?: SigningKeyPair[];
}

function buildVerificationMethods(
  did: string,
  selfHash: string,
  versionId: number,
  keys: VerificationKey[],
): { verificationMethod: VerificationMethod[]; purposes: Record<KeyPurpose, string[]> } {
  const verificationMethod: VerificationMethod[] = [];
  const purposes: Record<KeyPurpose, string[]> = {
    authentication: [],
    assertionMethod: [],
    keyAgreement: [],
    capabilityInvocation: [],
    capabilityDelegation: [],
  };
  keys.forEach((key, i) => {
    const id = `${did}?selfHash=${selfHash}&versionId=${versionId}#${i}`;
    verificationMethod.push({
      id,
      type: "JsonWebKey2020",
      controller: did,
      publicKeyJwk: {
        kid: id,
        ...publicKeyJwkParams(key.publicKey, key.curve ?? "ed25519"),
      },
    });
    for (const purpose of key.purposes ?? ALL_PURPOSES) {
      purposes[purpose].push(`#${i}`);
    }
  });
  return { verificationMethod, purposes };
}

/**
 * Create a self-hashed root DID document (versionId 0). Follows the
 * reference implementation's order of operations: build with placeholder
 * self-hashes, attach proofs (if any), then self-hash.
 */
export function createDidDocument(options: CreateDidDocumentOptions): WebplusDidDocument {
  if (options.keys.length === 0) {
    throw new DidError(ResolutionErrorCode.InternalError, "at least one key is required");
  }
  const placeholder = placeholderForFunction(options.hashFunction ?? "blake3");
  const did = formatDid({
    host: options.host,
    ...(options.port !== undefined ? { port: options.port } : {}),
    path: options.path ?? [],
    rootSelfHash: placeholder,
  });
  const { verificationMethod, purposes } = buildVerificationMethods(
    did,
    placeholder,
    0,
    options.keys,
  );
  const doc: WebplusDidDocument = {
    id: did,
    selfHash: placeholder,
    updateRules: options.updateRules,
    validFrom: options.validFrom ?? new Date().toISOString(),
    versionId: 0,
    verificationMethod,
    ...purposes,
  };
  for (const signer of options.signers ?? []) {
    doc.proofs = [...(doc.proofs ?? []), signProof(doc, signer)];
  }
  return selfHashDocument(doc);
}

export interface UpdateDidDocumentOptions {
  /** Verification methods for the new document version. */
  keys: VerificationKey[];
  /** Rules that authorize the update *after* this one. */
  updateRules: UpdateRules;
  /** Signers whose proofs must satisfy the previous document's updateRules. */
  signers: SigningKeyPair[];
  /** RFC 3339 timestamp; defaults to now. Must be later than the previous document's. */
  validFrom?: string;
  /** Hash function for the self-hash. Defaults to the previous document's. */
  hashFunction?: HashFunctionName;
}

/**
 * Create the next self-hashed DID document in the microledger, with proofs
 * from `signers` authorizing the update against `prev.updateRules`.
 */
export function updateDidDocument(
  prev: WebplusDidDocument,
  options: UpdateDidDocumentOptions,
): WebplusDidDocument {
  if (options.signers.length === 0) {
    throw new DidError(ResolutionErrorCode.InternalError, "at least one signer is required");
  }
  const placeholder = options.hashFunction
    ? placeholderForFunction(options.hashFunction)
    : placeholderMbHash(prev.selfHash);
  const versionId = prev.versionId + 1;
  const { verificationMethod, purposes } = buildVerificationMethods(
    prev.id,
    placeholder,
    versionId,
    options.keys,
  );
  const doc: WebplusDidDocument = {
    id: prev.id,
    selfHash: placeholder,
    prevDIDDocumentSelfHash: prev.selfHash,
    updateRules: options.updateRules,
    validFrom: options.validFrom ?? new Date().toISOString(),
    versionId,
    verificationMethod,
    ...purposes,
  };
  doc.proofs = options.signers.map((signer) => signProof(doc, signer));
  return selfHashDocument(doc);
}

export interface DeactivateDidDocumentOptions {
  /** Signers whose proofs must satisfy the previous document's updateRules. */
  signers: SigningKeyPair[];
  /** RFC 3339 timestamp; defaults to now. Must be later than the previous document's. */
  validFrom?: string;
  /** Hash function for the self-hash. Defaults to the previous document's. */
  hashFunction?: HashFunctionName;
}

/**
 * Create the final ("tombstone") DID document that deactivates the DID:
 * `updateRules` is `{}` so no further update can ever be authorized, and no
 * verification methods remain (per the spec's recommendation, so no keys are
 * left that can't be rotated). Submit it with `submitDidUpdate`.
 */
export function deactivateDidDocument(
  prev: WebplusDidDocument,
  options: DeactivateDidDocumentOptions,
): WebplusDidDocument {
  return updateDidDocument(prev, {
    keys: [],
    updateRules: {},
    signers: options.signers,
    ...(options.validFrom !== undefined ? { validFrom: options.validFrom } : {}),
    ...(options.hashFunction !== undefined ? { hashFunction: options.hashFunction } : {}),
  });
}

export interface VdrClientOptions extends ResolutionUrlOptions {
  fetchImpl?: typeof fetch;
  /** Extra request headers (e.g. VDR authorization). */
  headers?: Record<string, string>;
}

/** The `did-documents.jsonl` URL a DID's microledger lives at on its VDR. */
export function microledgerUrl(did: string, options: ResolutionUrlOptions = {}): string {
  const parsed = parseDid(did);
  const scheme = schemeForHost(parsed.host, options);
  const authority = parsed.port !== undefined ? `${parsed.host}:${parsed.port}` : parsed.host;
  return [`${scheme}:/`, authority, ...parsed.path, parsed.rootSelfHash, "did-documents.jsonl"].join(
    "/",
  );
}

async function submitToVdr(
  method: "POST" | "PUT",
  doc: WebplusDidDocument,
  options: VdrClientOptions,
): Promise<void> {
  const url = microledgerUrl(doc.id, options);
  const fetchImpl = options.fetchImpl ?? fetch;
  const response = await fetchImpl(url, {
    method,
    headers: { "content-type": "application/json", ...(options.headers ?? {}) },
    // The spec requires DID documents to be in JCS (RFC 8785) form on the
    // wire; VDRs reject non-canonical serializations.
    body: canonicalize(doc),
  });
  if (!response.ok) {
    throw new DidError(
      ResolutionErrorCode.InternalError,
      `VDR ${method} ${url} failed with HTTP ${response.status}: ${await response.text()}`,
    );
  }
}

/** Register a freshly created root DID document with its VDR (HTTP POST). */
export async function registerDid(
  doc: WebplusDidDocument,
  options: VdrClientOptions = {},
): Promise<void> {
  return submitToVdr("POST", doc, options);
}

/** Submit a DID document update to the VDR (HTTP PUT). */
export async function submitDidUpdate(
  doc: WebplusDidDocument,
  options: VdrClientOptions = {},
): Promise<void> {
  return submitToVdr("PUT", doc, options);
}