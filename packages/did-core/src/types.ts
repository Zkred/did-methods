/**
 * Minimal DID data model types shared by @zkred method implementations.
 *
 * Shapes follow the W3C DID Core data model and are structurally compatible
 * with the `did-resolver` package's types, without requiring a dependency on
 * it from this package.
 */

export interface JsonWebKey {
  kty: string;
  kid?: string;
  crv?: string;
  x?: string;
  y?: string;
  e?: string;
  n?: string;
  alg?: string;
  use?: string;
  [key: string]: unknown;
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk?: JsonWebKey;
  publicKeyMultibase?: string;
  [key: string]: unknown;
}

export interface ServiceEndpoint {
  id: string;
  type: string;
  serviceEndpoint: string | Record<string, unknown> | Array<string | Record<string, unknown>>;
  [key: string]: unknown;
}

/** A verification relationship entry: either a fragment/DID URL reference or an embedded method. */
export type VerificationRelationship = string | VerificationMethod;

export interface DidDocument {
  "@context"?: string | string[];
  id: string;
  alsoKnownAs?: string[];
  controller?: string | string[];
  verificationMethod?: VerificationMethod[];
  authentication?: VerificationRelationship[];
  assertionMethod?: VerificationRelationship[];
  keyAgreement?: VerificationRelationship[];
  capabilityInvocation?: VerificationRelationship[];
  capabilityDelegation?: VerificationRelationship[];
  service?: ServiceEndpoint[];
  [key: string]: unknown;
}

export interface DidResolutionMetadata {
  contentType?: string;
  error?: string;
  message?: string;
  [key: string]: unknown;
}

export interface DidDocumentMetadata {
  created?: string;
  updated?: string;
  deactivated?: boolean;
  versionId?: string;
  nextUpdate?: string;
  nextVersionId?: string;
  [key: string]: unknown;
}

export interface DidResolutionResult {
  didResolutionMetadata: DidResolutionMetadata;
  didDocument: DidDocument | null;
  didDocumentMetadata: DidDocumentMetadata;
}