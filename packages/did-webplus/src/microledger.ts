import { canonicalize } from "@zkred/did-core";
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

const VALID_FROM_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/;

/**
 * Strict spec validation of a `validFrom` timestamp: RFC 3339 with uppercase
 * `T`/`Z`, `Z` offset only, at most millisecond precision, a real calendar
 * date, and not before the Unix epoch. Returns an error message or null.
 */
export function validFromError(value: unknown): string | null {
  if (typeof value !== "string") {
    return "valid-from-invalid-format: validFrom must be a string";
  }
  const m = VALID_FROM_PATTERN.exec(value);
  if (!m) {
    return `valid-from-invalid-format: ${value} is not RFC 3339 with uppercase T/Z and at most millisecond precision`;
  }
  const [, y, mo, d, h, mi, s] = m.map(Number) as unknown as number[];
  const t = Date.UTC(y!, mo! - 1, d!, h!, mi!, s!);
  const roundTrip = new Date(t);
  if (
    roundTrip.getUTCFullYear() !== y ||
    roundTrip.getUTCMonth() !== mo! - 1 ||
    roundTrip.getUTCDate() !== d ||
    roundTrip.getUTCHours() !== h ||
    roundTrip.getUTCMinutes() !== mi ||
    roundTrip.getUTCSeconds() !== s
  ) {
    return `valid-from-invalid-format: ${value} is not a real calendar date/time`;
  }
  if (t < 0) {
    return `valid-from-pre-epoch: ${value} is before the Unix epoch`;
  }
  return null;
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
  /**
   * Optional: verify proofs present on a root document (which needs none,
   * but any present must be cryptographically valid).
   */
  verifyRootProofs?(doc: WebplusDidDocument): Promise<boolean>;
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
/**
 * Split a `did-documents.jsonl` payload into lines and enforce the spec's
 * wire-format rule: each serialized DID document MUST be byte-for-byte equal
 * to its own JCS (RFC 8785) serialization. Returns parsed documents plus any
 * `not-jcs-canonical` violations. A single trailing `\r` per line (CRLF
 * transport) is tolerated; anything else, including insignificant whitespace
 * or reordered keys, is a violation.
 */
export function parseJcsCanonicalLines(jsonl: string): {
  docs: WebplusDidDocument[];
  errors: MicroledgerValidationError[];
} {
  const docs: WebplusDidDocument[] = [];
  const errors: MicroledgerValidationError[] = [];
  // Strict JSONL: lines are separated by exactly "\n" (a single trailing
  // newline after the last document is permitted); CRLF endings and blank
  // lines are malformed. An empty file is zero documents, not an error.
  const body = jsonl.endsWith("\n") ? jsonl.slice(0, -1) : jsonl;
  const lines = body.length === 0 ? [] : body.split("\n");

  lines.forEach((line, i) => {
    if (line.trim().length === 0) {
      errors.push({
        versionId: -1,
        message: `malformed-jsonl-line: line ${i + 1} is blank`,
      });
      return;
    }
    let doc: WebplusDidDocument;
    try {
      doc = JSON.parse(line) as WebplusDidDocument;
    } catch {
      errors.push({ versionId: -1, message: `line ${i + 1} is not valid JSON` });
      return;
    }
    if (canonicalize(doc) !== line) {
      errors.push({
        versionId: typeof doc.versionId === "number" ? doc.versionId : -1,
        message: `not-jcs-canonical: line ${i + 1} is not byte-equal to its JCS (RFC 8785) serialization`,
      });
    }
    docs.push(doc);
  });

  return { docs, errors };
}

/**
 * Validate a microledger from its raw `did-documents.jsonl` bytes: enforces
 * the JCS wire-format rule on every line (which the parsed-object
 * `validateMicroledger` cannot check, since raw bytes are gone after
 * parsing), then runs the full structural and cryptographic validation.
 */
export async function validateMicroledgerBytes(
  jsonl: string,
  options: { expectedDid?: string; verifier?: CryptoVerifier | null } = {},
): Promise<MicroledgerValidationResult> {
  const { docs, errors } = parseJcsCanonicalLines(jsonl);
  if (docs.length === 0) {
    // An empty did-documents.jsonl is well-formed: zero valid documents.
    return { valid: errors.length === 0, errors };
  }
  const structural = await validateMicroledger(docs, options);
  return { valid: errors.length === 0 && structural.valid, errors: [...errors, ...structural.errors] };
}

export async function validateMicroledger(
  docs: WebplusDidDocument[],
  options: { expectedDid?: string; verifier?: CryptoVerifier | null } = {},
): Promise<MicroledgerValidationResult> {
  return validateMicroledgerExtension([], docs, options);
}

/**
 * Validate `newDocs` as a continuation of the already-verified `baseDocs`
 * prefix (the incremental path of a Full DID Resolver: after a range-based
 * fetch, only the new documents need verification). With an empty base this
 * is exactly `validateMicroledger`.
 */
export async function validateMicroledgerExtension(
  baseDocs: WebplusDidDocument[],
  newDocs: WebplusDidDocument[],
  options: { expectedDid?: string; verifier?: CryptoVerifier | null } = {},
): Promise<MicroledgerValidationResult> {
  const { WebplusCryptoVerifier } = await import("./verifier.js");
  const verifier =
    options.verifier === null ? undefined : (options.verifier ?? new WebplusCryptoVerifier());
  const errors: MicroledgerValidationError[] = [];
  const report = (versionId: number, message: string) => errors.push({ versionId, message });

  if (baseDocs.length === 0 && newDocs.length === 0) {
    return { valid: false, errors: [{ versionId: 0, message: "microledger is empty" }] };
  }

  const first = baseDocs[0] ?? newDocs[0]!;
  const did = options.expectedDid ?? first.id;
  const expectedRootSelfHash = did.split(":").at(-1);

  if (baseDocs.length === 0) {
    const root = newDocs[0]!;
    if (root.versionId !== 0) {
      report(root.versionId, `first document has versionId ${root.versionId}, expected 0`);
    }
    if (root.prevDIDDocumentSelfHash !== undefined) {
      report(0, "root document must not have prevDIDDocumentSelfHash");
    }
    if (root.selfHash !== expectedRootSelfHash) {
      report(0, `root selfHash ${root.selfHash} does not match DID component ${expectedRootSelfHash}`);
    }
  }

  const offset = baseDocs.length;
  const docs = newDocs;
  let prev = offset > 0 ? baseDocs[offset - 1]! : docs[0]!;
  for (let j = 0; j < docs.length; j++) {
    const i = offset + j;
    const doc = docs[j]!;
    if (doc.id !== did) {
      report(doc.versionId, `document id ${doc.id} does not match DID ${did}`);
    }
    if (doc.versionId !== i) {
      report(doc.versionId, `expected versionId ${i} at position ${i}, got ${doc.versionId}`);
    }
    if (typeof doc.selfHash !== "string" || doc.selfHash.length === 0) {
      report(doc.versionId, "missing-required-field: document is missing selfHash");
    }
    if (doc.updateRules === undefined || doc.updateRules === null) {
      report(doc.versionId, "missing-required-field: document is missing updateRules");
    }
    if (typeof doc.id !== "string" || doc.id.length === 0) {
      report(doc.versionId, "missing-required-field: document is missing id");
    }
    if (typeof doc.versionId !== "number") {
      report(i, "missing-required-field: versionId must be a number");
    }
    const validFromProblem = validFromError(doc.validFrom);
    if (validFromProblem) {
      report(doc.versionId, validFromProblem);
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
      if (i === 0 && (doc.proofs?.length ?? 0) > 0 && verifier.verifyRootProofs) {
        try {
          await verifier.verifyRootProofs(doc);
        } catch (err) {
          report(doc.versionId, errorMessage(err));
        }
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