import type { WebplusDidDocument, WebplusDidQuery } from "./types.js";

/** The five did:webplus-specific DID Resolution Options, all defaulting to `false`. */
export interface WebplusResolutionOptions {
  /** Include creation metadata (`created`, `createdMilliseconds`). */
  requestCreate?: boolean;
  /** Include next-update metadata when a successor document exists. */
  requestNext?: boolean;
  /** Include latest-update metadata. Forces a fetch when the latest document isn't known locally. */
  requestLatest?: boolean;
  /** Include `deactivated`. Forces a fetch when the local tip isn't known to be deactivated. */
  requestDeactivated?: boolean;
  /** Make zero network requests; fail if the document/requested metadata isn't locally satisfiable. */
  localResolutionOnly?: boolean;
}

/**
 * A document with `updateRules: {}` (the tombstone set by `deactivateDidDocument`)
 * permits no further updates. In a validated microledger, only the final
 * document can have this shape — a later document would need proofs that
 * satisfy `{}`, which `evaluateUpdateRules` always refuses.
 */
export function isDeactivated(doc: WebplusDidDocument): boolean {
  return doc.updateRules !== undefined && Object.keys(doc.updateRules).length === 0;
}

/** `validFrom` floored to whole seconds: `YYYY-MM-DDTHH:MM:SSZ`. */
export function secondsForm(validFrom: string): string {
  return validFrom.replace(/\.\d{1,3}Z$/, "Z");
}

/**
 * `validFrom` normalized to millisecond precision with trailing fractional
 * zeros stripped. Equal-value fractional forms (`.5`, `.50`, `.500`) collapse
 * to one canonical form (`.5`); a fractional part of all zeros collapses to
 * no fractional part at all, so a document with no genuine sub-second
 * precision reports the same value as `secondsForm`.
 */
export function millisForm(validFrom: string): string {
  const m = /^(.*)\.(\d{1,3})Z$/.exec(validFrom);
  if (!m) return validFrom;
  const [, base, frac] = m as unknown as [string, string, string];
  const stripped = frac.padEnd(3, "0").replace(/0+$/, "");
  return stripped ? `${base}.${stripped}Z` : `${base}Z`;
}

/** Outcome of checking whether a DID URL query is answerable from a locally-known document prefix. */
export type DocLocality =
  | { status: "found"; doc: WebplusDidDocument }
  /** A local deactivation proves the query can never be satisfied (version beyond the tip, unknown selfHash, etc.). */
  | { status: "known-absent" }
  /** `selfHash` and `versionId` are both given, both found locally, and they name different documents. */
  | { status: "conflict" }
  | { status: "needs-fetch" };

/**
 * Whether `localDocs` (a verified, contiguous-from-0 prefix of the
 * microledger) already answers `query`, per the spec's "Local Satisfiability
 * of the Requested Document" rules. A plain DID (no query params) is never
 * locally satisfiable unless the local tip is deactivated, in which case
 * `localDocs` is provably the DID's entire history.
 */
export function computeDocLocality(
  localDocs: WebplusDidDocument[],
  query: WebplusDidQuery,
): DocLocality {
  const tip = localDocs[localDocs.length - 1];
  const complete = tip !== undefined && isDeactivated(tip);
  const isPlain =
    query.selfHash === undefined && query.versionId === undefined && query.versionTime === undefined;

  if (isPlain) {
    return complete ? { status: "found", doc: tip! } : { status: "needs-fetch" };
  }

  if (query.selfHash !== undefined && query.versionId !== undefined) {
    const byHash = localDocs.find((d) => d.selfHash === query.selfHash);
    const byVersion =
      query.versionId >= 0 && query.versionId < localDocs.length ? localDocs[query.versionId] : undefined;
    // Either match pins down the other value: a local document with that
    // selfHash has a definite versionId (and vice versa), so a disagreement is
    // provable without fetching.
    const known = byHash ?? byVersion;
    if (known) {
      return known.selfHash === query.selfHash && known.versionId === query.versionId
        ? { status: "found", doc: known }
        : { status: "conflict" };
    }
    return complete ? { status: "known-absent" } : { status: "needs-fetch" };
  }

  if (query.selfHash !== undefined) {
    const doc = localDocs.find((d) => d.selfHash === query.selfHash);
    if (doc) return { status: "found", doc };
    return complete ? { status: "known-absent" } : { status: "needs-fetch" };
  }

  if (query.versionId !== undefined) {
    if (query.versionId >= 0 && query.versionId < localDocs.length) {
      return { status: "found", doc: localDocs[query.versionId]! };
    }
    return complete ? { status: "known-absent" } : { status: "needs-fetch" };
  }

  // versionTime: the latest local document valid at or before the queried time.
  const t = Date.parse(query.versionTime!);
  let candidateIndex = -1;
  for (let i = localDocs.length - 1; i >= 0; i--) {
    if (Date.parse(localDocs[i]!.validFrom) <= t) {
      candidateIndex = i;
      break;
    }
  }
  if (candidateIndex === -1) {
    return complete ? { status: "known-absent" } : { status: "needs-fetch" };
  }
  // Final (not possibly superseded by an unknown later document) once a later
  // local document is known to exist — monotonic validFrom guarantees it has
  // validFrom > t — or once the local prefix is provably complete.
  const provenFinal = complete || candidateIndex < localDocs.length - 1;
  return provenFinal
    ? { status: "found", doc: localDocs[candidateIndex]! }
    : { status: "needs-fetch" };
}

/**
 * Whether every *requested* metadata group (creation / next / latest /
 * deactivated) is answerable from `localDocs` alone, per "Local
 * Satisfiability of Metadata Groups". Vacuously true when no group is
 * requested. `resolvedDoc` is the document `computeDocLocality` found
 * locally, if any — metadata groups that depend on knowing which document
 * was resolved are never locally satisfiable without it.
 */
export function computeMetadataLocality(
  localDocs: WebplusDidDocument[],
  resolvedDoc: WebplusDidDocument | undefined,
  options: WebplusResolutionOptions,
): boolean {
  const tip = localDocs[localDocs.length - 1];
  const tipDeactivated = tip !== undefined && isDeactivated(tip);

  if (options.requestCreate && localDocs.length === 0) {
    return false;
  }

  if (options.requestNext) {
    if (resolvedDoc === undefined) return false;
    const hasNextLocally = localDocs[resolvedDoc.versionId + 1] !== undefined;
    const knownNoNext = isDeactivated(resolvedDoc);
    if (!hasNextLocally && !knownNoNext) return false;
  }

  if ((options.requestLatest || options.requestDeactivated) && !tipDeactivated) {
    return false;
  }

  return true;
}

/**
 * Build `didDocumentMetadata` per the spec's exact field set: only
 * `versionId` is unconditional, every other field appears only when its
 * triggering option was requested (or, for `deactivated: true`, whenever the
 * resolved document is a deactivation regardless of the option).
 */
export function buildDidDocumentMetadata(
  resolvedDoc: WebplusDidDocument,
  allDocs: WebplusDidDocument[],
  options: WebplusResolutionOptions,
): Record<string, unknown> {
  const metadata: Record<string, unknown> = { versionId: String(resolvedDoc.versionId) };

  if (resolvedDoc.versionId !== 0) {
    metadata.updated = secondsForm(resolvedDoc.validFrom);
    metadata.updatedMilliseconds = millisForm(resolvedDoc.validFrom);
  }

  if (options.requestCreate) {
    const root = allDocs[0]!;
    metadata.created = secondsForm(root.validFrom);
    metadata.createdMilliseconds = millisForm(root.validFrom);
  }

  if (options.requestNext) {
    const next = allDocs[resolvedDoc.versionId + 1];
    if (next) {
      metadata.nextUpdate = secondsForm(next.validFrom);
      metadata.nextUpdateMilliseconds = millisForm(next.validFrom);
      metadata.nextVersionId = String(next.versionId);
    }
  }

  if (options.requestLatest) {
    const latest = allDocs[allDocs.length - 1]!;
    metadata.latestUpdate = secondsForm(latest.validFrom);
    metadata.latestUpdateMilliseconds = millisForm(latest.validFrom);
    metadata.latestVersionId = String(latest.versionId);
  }

  if (isDeactivated(resolvedDoc)) {
    metadata.deactivated = true;
  } else if (options.requestDeactivated) {
    metadata.deactivated = false;
  }

  return metadata;
}
