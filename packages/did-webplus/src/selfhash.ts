import { canonicalize, utf8Encode } from "@zkred/did-core";
import { hashAsMbHash, placeholderMbHash } from "./multiformat.js";
import type { WebplusDidDocument } from "./types.js";

/**
 * Self-hashing of did:webplus DID documents, mirroring the reference
 * implementation (LedgerDomain's `selfhash` scheme over JCS serialization).
 *
 * A DID document has "self-hash slots" — places where its own hash appears.
 * To hash or verify, every slot is set to the hash function's placeholder
 * (multihash header + all-zeros digest), the document is JCS-serialized, and
 * the digest is computed over those bytes.
 *
 * Slots for a ROOT document (versionId 0):
 * - the last `:`-separated component of the DID in `id`
 * - the `selfHash` field
 * - per verification method: the DID component and `selfHash` query parameter
 *   of `id` and `publicKeyJwk.kid`, and the DID component of `controller`
 *
 * Slots for a NON-ROOT document:
 * - the `selfHash` field
 * - per verification method: the `selfHash` query parameter of `id` and
 *   `publicKeyJwk.kid` (the DID component keeps the ROOT self-hash)
 */

export function isRootDocument(doc: WebplusDidDocument): boolean {
  return doc.prevDIDDocumentSelfHash === undefined;
}

function lastDidComponent(did: string): string {
  return did.slice(did.lastIndexOf(":") + 1);
}

function replaceLastDidComponent(did: string, value: string): string {
  return did.slice(0, did.lastIndexOf(":") + 1) + value;
}

/** Split a DID URL into the base DID, query string, and fragment suffix. */
function splitDidUrl(didUrl: string): { base: string; query: string; suffix: string } {
  const queryStart = didUrl.indexOf("?");
  if (queryStart === -1) {
    throw new TypeError(`verification method id has no query: ${didUrl}`);
  }
  const fragmentStart = didUrl.indexOf("#", queryStart);
  const suffix = fragmentStart === -1 ? "" : didUrl.slice(fragmentStart);
  const query = didUrl.slice(queryStart + 1, fragmentStart === -1 ? undefined : fragmentStart);
  return { base: didUrl.slice(0, queryStart), query, suffix };
}

function selfHashQueryValue(didUrl: string): string {
  const { query } = splitDidUrl(didUrl);
  const value = new URLSearchParams(query).get("selfHash");
  if (value === null) {
    throw new TypeError(`verification method id has no selfHash query parameter: ${didUrl}`);
  }
  return value;
}

/** Replace the selfHash query parameter value in-place, preserving parameter order. */
function replaceSelfHashQueryValue(didUrl: string, value: string): string {
  const { base, query, suffix } = splitDidUrl(didUrl);
  const replaced = query
    .split("&")
    .map((pair) => (pair.startsWith("selfHash=") ? `selfHash=${value}` : pair))
    .join("&");
  return `${base}?${replaced}${suffix}`;
}

/**
 * Collect the values of all self-hash slots. Mirrors the reference
 * implementation's slot enumeration: for non-root documents, only the
 * `selfHash` field participates in the equality check.
 */
export function collectSelfHashSlots(doc: WebplusDidDocument): string[] {
  if (!isRootDocument(doc)) {
    return [doc.selfHash];
  }
  const slots: string[] = [lastDidComponent(doc.id), doc.selfHash];
  for (const vm of doc.verificationMethod ?? []) {
    const { base } = splitDidUrl(vm.id);
    slots.push(lastDidComponent(base), selfHashQueryValue(vm.id));
    if (vm.controller === doc.id) {
      slots.push(lastDidComponent(vm.controller));
    }
    const kid = vm.publicKeyJwk?.kid;
    if (typeof kid === "string") {
      const { base: kidBase } = splitDidUrl(kid);
      slots.push(lastDidComponent(kidBase), selfHashQueryValue(kid));
    }
  }
  return slots;
}

/** Return a deep copy of `doc` with every self-hash slot set to `value`. */
export function withSelfHashSlotsSetTo(
  doc: WebplusDidDocument,
  value: string,
): WebplusDidDocument {
  const clone = structuredClone(doc);
  const root = isRootDocument(clone);
  clone.selfHash = value;
  if (root) {
    clone.id = replaceLastDidComponent(clone.id, value);
  }
  for (const vm of clone.verificationMethod ?? []) {
    if (root) {
      const { base, query, suffix } = splitDidUrl(vm.id);
      vm.id = `${replaceLastDidComponent(base, value)}?${query}${suffix}`;
      if (typeof vm.controller === "string") {
        vm.controller = replaceLastDidComponent(vm.controller, value);
      }
    }
    vm.id = replaceSelfHashQueryValue(vm.id, value);
    const kid = vm.publicKeyJwk?.kid;
    if (typeof kid === "string") {
      let newKid = kid;
      if (root) {
        const { base, query, suffix } = splitDidUrl(kid);
        newKid = `${replaceLastDidComponent(base, value)}?${query}${suffix}`;
      }
      vm.publicKeyJwk!.kid = replaceSelfHashQueryValue(newKid, value);
    }
  }
  return clone;
}

export interface SelfHashVerificationResult {
  valid: boolean;
  error?: string;
}

/**
 * Verify that `doc.selfHash` is the correct self-hash of the document:
 * all slots must agree, and hashing the JCS serialization of the document
 * (with slots set to the placeholder) must reproduce the claimed hash.
 */
export function verifyDocumentSelfHash(doc: WebplusDidDocument): SelfHashVerificationResult {
  try {
    const slots = collectSelfHashSlots(doc);
    const claimed = doc.selfHash;
    for (const slot of slots) {
      if (slot !== claimed) {
        return {
          valid: false,
          error: `self-hash slot value ${slot} does not match selfHash ${claimed}`,
        };
      }
    }
    const placeholder = placeholderMbHash(claimed);
    const prepared = withSelfHashSlotsSetTo(doc, placeholder);
    const computed = hashAsMbHash(claimed, utf8Encode(canonicalize(prepared)));
    if (computed !== claimed) {
      return {
        valid: false,
        error: `computed self-hash ${computed} does not match claimed selfHash ${claimed}`,
      };
    }
    return { valid: true };
  } catch (err) {
    return { valid: false, error: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * The bytes a proof (JWS) signs: the JCS serialization of the DID document
 * with the `proofs` field removed and all self-hash slots set to the
 * placeholder value.
 */
export function proofSigningInput(doc: WebplusDidDocument): Uint8Array {
  const placeholder = placeholderMbHash(doc.selfHash);
  const prepared = withSelfHashSlotsSetTo(doc, placeholder);
  delete prepared.proofs;
  return utf8Encode(canonicalize(prepared));
}