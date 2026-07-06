import type { WebplusDidDocument } from "./types.js";

export interface MicroledgerValidationError {
  versionId: number;
  message: string;
}

export interface MicroledgerValidationResult {
  valid: boolean;
  errors: MicroledgerValidationError[];
}

/**
 * Pluggable cryptographic verifier for microledger entries.
 *
 * Structural validation (chaining, version ordering, timestamps) is
 * implemented natively by `validateMicroledger`. Verifying self-hashes and
 * update proofs requires the `selfhash` self-addressing computation and JWS
 * verification against `updateRules`; supply an implementation of this
 * interface to enforce them. Full built-in cryptographic verification,
 * validated against the Rust reference implementation's test vectors, is on
 * the roadmap.
 */
export interface CryptoVerifier {
  /** Return true if `doc.selfHash` is the correct self-hash of `doc`. */
  verifySelfHash(doc: WebplusDidDocument): Promise<boolean>;
  /** Return true if `doc.proofs` satisfy `prev.updateRules`. */
  verifyProofs(doc: WebplusDidDocument, prev: WebplusDidDocument): Promise<boolean>;
}

/**
 * Validate the structure of a did:webplus microledger: a list of DID
 * documents ordered by `versionId`, chained by `prevDIDDocumentSelfHash`.
 *
 * Checks performed:
 * - documents are contiguous from versionId 0
 * - all documents share the same `id`, matching `expectedDid` when given
 * - the root document's `selfHash` equals the DID's final component
 * - the root document has no `prevDIDDocumentSelfHash`
 * - each non-root document links to its predecessor's `selfHash` and carries proofs
 * - `validFrom` timestamps are strictly increasing
 * - optionally, self-hashes and proofs verify via the supplied `CryptoVerifier`
 */
export async function validateMicroledger(
  docs: WebplusDidDocument[],
  options: { expectedDid?: string; verifier?: CryptoVerifier } = {},
): Promise<MicroledgerValidationResult> {
  const errors: MicroledgerValidationError[] = [];
  const report = (versionId: number, message: string) => errors.push({ versionId, message });

  if (docs.length === 0) {
    return { valid: false, errors: [{ versionId: 0, message: "microledger is empty" }] };
  }

  const root = docs[0]!;
  const did = options.expectedDid ?? root.id;
  const expectedRootSelfHash = did.split(":").at(-1);

  if (root.versionId !== 0) {
    report(root.versionId, `first document has versionId ${root.versionId}, expected 0`);
  }
  if (root.prevDIDDocumentSelfHash !== undefined) {
    report(0, "root document must not have prevDIDDocumentSelfHash");
  }
  if (root.selfHash !== expectedRootSelfHash) {
    report(0, `root selfHash ${root.selfHash} does not match DID component ${expectedRootSelfHash}`);
  }

  let prev = root;
  for (let i = 0; i < docs.length; i++) {
    const doc = docs[i]!;
    if (doc.id !== did) {
      report(doc.versionId, `document id ${doc.id} does not match DID ${did}`);
    }
    if (doc.versionId !== i) {
      report(doc.versionId, `expected versionId ${i} at position ${i}, got ${doc.versionId}`);
    }
    if (typeof doc.selfHash !== "string" || doc.selfHash.length === 0) {
      report(doc.versionId, "document is missing selfHash");
    }
    if (Number.isNaN(Date.parse(doc.validFrom))) {
      report(doc.versionId, `invalid validFrom timestamp: ${doc.validFrom}`);
    }

    if (i > 0) {
      if (doc.prevDIDDocumentSelfHash !== prev.selfHash) {
        report(
          doc.versionId,
          `prevDIDDocumentSelfHash ${doc.prevDIDDocumentSelfHash} does not match previous selfHash ${prev.selfHash}`,
        );
      }
      if (!Array.isArray(doc.proofs) || doc.proofs.length === 0) {
        report(doc.versionId, "non-root document must carry at least one proof");
      }
      if (Date.parse(doc.validFrom) <= Date.parse(prev.validFrom)) {
        report(doc.versionId, `validFrom ${doc.validFrom} is not later than previous ${prev.validFrom}`);
      }
    }

    if (options.verifier) {
      if (!(await options.verifier.verifySelfHash(doc))) {
        report(doc.versionId, "selfHash verification failed");
      }
      if (i > 0 && !(await options.verifier.verifyProofs(doc, prev))) {
        report(doc.versionId, "proofs do not satisfy previous document's updateRules");
      }
    }

    prev = doc;
  }

  return { valid: errors.length === 0, errors };
}