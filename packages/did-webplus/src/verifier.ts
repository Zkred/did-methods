import { verifyDetachedJws } from "./jws.js";
import type { CryptoVerifier } from "./microledger.js";
import { proofSigningInput, verifyDocumentSelfHash } from "./selfhash.js";
import { evaluateUpdateRules } from "./updateRules.js";
import type { WebplusDidDocument } from "./types.js";

/**
 * Verify every proof on `doc` and return the signers' public keys (JWS `kid`
 * values). Per the conformance test vectors, ANY malformed or
 * cryptographically invalid proof rejects the document, even when other
 * proofs would satisfy the update rules and even on root documents.
 * (Valid proofs from keys the update rules do not name are fine.)
 */
export function validProofKeys(doc: WebplusDidDocument): string[] {
  const payload = proofSigningInput(doc);
  const keys: string[] = [];
  (doc.proofs ?? []).forEach((proof, i) => {
    try {
      keys.push(verifyDetachedJws(proof, payload));
    } catch (err) {
      throw new Error(
        `invalid-proof-signature: proof ${i} is malformed or its signature does not verify (${err instanceof Error ? err.message : String(err)})`,
      );
    }
  });
  return keys;
}

/**
 * Built-in cryptographic verifier for did:webplus microledgers: verifies
 * document self-hashes (JCS + multihash, BLAKE3/SHA-2) and Ed25519 JWS
 * proofs against the predecessor document's updateRules.
 */
export class WebplusCryptoVerifier implements CryptoVerifier {
  async verifySelfHash(doc: WebplusDidDocument): Promise<boolean> {
    const result = verifyDocumentSelfHash(doc);
    if (!result.valid) {
      throw new Error(result.error ?? "self-hash verification failed");
    }
    return true;
  }

  async verifyProofs(doc: WebplusDidDocument, prev: WebplusDidDocument): Promise<boolean> {
    if (prev.updateRules === undefined) {
      throw new Error(
        `previous document (versionId ${prev.versionId}) has no updateRules; updates cannot be authorized`,
      );
    }
    const keys = validProofKeys(doc); // throws on any invalid proof
    if (!evaluateUpdateRules(prev.updateRules, keys)) {
      throw new Error(
        keys.length === 0
          ? "document carries no proofs"
          : `valid proof keys [${keys.join(", ")}] do not satisfy the previous document's updateRules`,
      );
    }
    return true;
  }

  /**
   * Root documents require no proofs, but any proofs present must still be
   * cryptographically valid (conformance vector: root-with-invalid-proof).
   */
  async verifyRootProofs(doc: WebplusDidDocument): Promise<boolean> {
    validProofKeys(doc); // throws on any invalid proof
    return true;
  }
}