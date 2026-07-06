import type { WebplusDidDocument } from "./types.js";

export interface MicroledgerValidationError {
  versionId: number;
  message: string;
}

export interface MicroledgerValidationResult {
  valid: boolean;
  errors: MicroledgerValidationError[];
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Pluggable cryptographic verifier for microledger entries.
 *
 * `validateMicroledger` uses the built-in `WebplusCryptoVerifier` by default
 * (self-hash verification via JCS + multihash, Ed25519 JWS proofs checked
 * against `updateRules`). Supply your own implementation to customize, or
 * pass `verifier: null` to run structural validation only.
 *
 * Implementations may either return `false` or throw an `Error` to fail a
 * check; a thrown error's message is surfaced in the validation result.
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
 * - self-hashes and proofs verify cryptographically (built-in by default;
 *   pass `verifier: null` for structural checks only)
 */
export async function validateMicroledger(
  docs: WebplusDidDocument[],
  options: { expectedDid?: string; verifier?: CryptoVerifier | null } = {},
): Promise<MicroledgerValidationResult> {
  const { WebplusCryptoVerifier } = await import("./verifier.js");
  const verifier =
    options.verifier === null ? undefined : (options.verifier ?? new WebplusCryptoVerifier());
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

    if (verifier) {
      try {
        if (!(await verifier.verifySelfHash(doc))) {
          report(doc.versionId, "selfHash verification failed");
        }
      } catch (err) {
        report(doc.versionId, `selfHash verification failed: ${errorMessage(err)}`);
      }
      if (i > 0) {
        try {
          if (!(await verifier.verifyProofs(doc, prev))) {
            report(doc.versionId, "proofs do not satisfy previous document's updateRules");
          }
        } catch (err) {
          report(
            doc.versionId,
            `proofs do not satisfy previous document's updateRules: ${errorMessage(err)}`,
          );
        }
      }
    }

    prev = doc;
  }

  return { valid: errors.length === 0, errors };
}