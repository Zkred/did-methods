import { verifyDetachedJws } from "./jws.js";
import type { CryptoVerifier } from "./microledger.js";
import { proofSigningInput, verifyDocumentSelfHash } from "./selfhash.js";
import { evaluateUpdateRules } from "./updateRules.js";
import type { WebplusDidDocument } from "./types.js";

/**
 * Collect the public keys (JWS `kid` values) of all valid proofs on `doc`.
 * Invalid or malformed proofs are skipped, matching the reference
 * implementation, which only requires that the *valid* proofs satisfy the
 * update rules.
 */
export function validProofKeys(doc: WebplusDidDocument): string[] {
  const payload = proofSigningInput(doc);
  const keys: string[] = [];
  for (const proof of doc.proofs ?? []) {
    try {
      keys.push(verifyDetachedJws(proof, payload));
    } catch {
      // invalid proof: contributes nothing toward the update rules
    }
  }
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
    const keys = validProofKeys(doc);
    if (!evaluateUpdateRules(prev.updateRules, keys)) {
      throw new Error(
        keys.length === 0
          ? "document carries no cryptographically valid proofs"
          : `valid proof keys [${keys.join(", ")}] do not satisfy the previous document's updateRules`,
      );
    }
    return true;
  }
}