import { base64urlEncode, concatBytes, utf8Encode } from "@zkred/did-core";
import { ed25519 } from "@noble/curves/ed25519";
import { formatMbPubKey } from "./multiformat.js";
import { proofSigningInput } from "./selfhash.js";
import type { WebplusDidDocument } from "./types.js";

/** An Ed25519 key pair used for signing DID update proofs. */
export interface Ed25519KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  /** Multibase multicodec form of the public key (`u7Q...`), used in JWS `kid` and updateRules. */
  mbPubKey: string;
}

/** Generate a new Ed25519 key pair, or derive one from a 32-byte private key. */
export function ed25519KeyPair(privateKey?: Uint8Array): Ed25519KeyPair {
  const priv = privateKey ?? ed25519.utils.randomPrivateKey();
  if (priv.length !== 32) {
    throw new TypeError(`ed25519 private key must be 32 bytes, got ${priv.length}`);
  }
  const publicKey = ed25519.getPublicKey(priv);
  return { privateKey: priv, publicKey, mbPubKey: formatMbPubKey(publicKey) };
}

/** The base64url `x` coordinate for a `publicKeyJwk` entry. */
export function ed25519PublicKeyJwkX(publicKey: Uint8Array): string {
  return base64urlEncode(publicKey);
}

/**
 * Sign a proof over an arbitrary payload as a detached, unencoded-payload
 * Ed25519 JWS (RFC 7797, `b64: false`), with the signer's multibase public
 * key as `kid` — the shape did:webplus proofs use.
 */
export function signDetachedJws(payload: Uint8Array, keyPair: Ed25519KeyPair): string {
  // Header field order matches the reference implementation's output.
  const header = { alg: "Ed25519", kid: keyPair.mbPubKey, crit: ["b64"], b64: false };
  const protectedB64 = base64urlEncode(utf8Encode(JSON.stringify(header)));
  const signingInput = concatBytes(utf8Encode(`${protectedB64}.`), payload);
  const signature = ed25519.sign(signingInput, keyPair.privateKey);
  return `${protectedB64}..${base64urlEncode(signature)}`;
}

/**
 * Produce a did:webplus update proof for `doc`: a detached JWS over the
 * document's proof signing input (JCS, no `proofs`, placeholder self-hashes).
 * Attach the result to `doc.proofs` *before* self-hashing the document.
 */
export function signProof(doc: WebplusDidDocument, keyPair: Ed25519KeyPair): string {
  return signDetachedJws(proofSigningInput(doc), keyPair);
}