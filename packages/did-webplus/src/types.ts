import type { DidDocument } from "@zkred/did-core";

/**
 * Update rules govern which proofs are required for the next DID document in
 * the microledger. An empty object means updates are disallowed. See the
 * did:webplus spec: https://ledgerdomain.github.io/did-webplus-spec
 */
export type UpdateRules =
  | { key: string }
  | { hashedKey: string }
  | { any: UpdateRules[] }
  | { all: UpdateRules[] }
  | { atLeast: number; of: WeightedUpdateRules[] }
  | Record<string, never>;

/** An updateRules entry inside `of`, optionally carrying a weight (default 1). */
export type WeightedUpdateRules = UpdateRules & { weight?: number };

/**
 * A did:webplus DID document — one entry in the DID's microledger.
 *
 * Every document is self-addressed via `selfHash`, and every non-root
 * document points at its predecessor via `prevDIDDocumentSelfHash`, forming
 * an immutable, un-forkable chain.
 */
export interface WebplusDidDocument extends DidDocument {
  /** Self-hash of this document (self-addressing identifier component). */
  selfHash: string;
  /** Self-hash of the previous document. Absent on the root document. */
  prevDIDDocumentSelfHash?: string;
  /** Rules that the *next* update's proofs must satisfy. */
  updateRules?: UpdateRules;
  /**
   * Detached-payload JWS proofs (RFC 7797, `b64: false`) satisfying the
   * previous document's `updateRules`. Absent/optional on the root document.
   */
  proofs?: string[];
  /** RFC 3339 timestamp from which this document version is valid. */
  validFrom: string;
  /** 0-based version number within the microledger. */
  versionId: number;
}

/** Components of a parsed did:webplus DID. */
export interface ParsedWebplusDid {
  /** The full DID string, e.g. `did:webplus:example.com:uHiAg...`. */
  did: string;
  /** Hostname of the VDR, e.g. `example.com`. */
  host: string;
  /** Port, when the DID encodes one via `%3A`, e.g. `example.com%3A8085`. */
  port?: number;
  /** Optional path components between host and root self-hash. */
  path: string[];
  /** Self-hash of the root DID document (last DID component). */
  rootSelfHash: string;
}

/** Query parameters recognized by did:webplus DID URLs. */
export interface WebplusDidQuery {
  versionId?: number;
  selfHash?: string;
  versionTime?: string;
}