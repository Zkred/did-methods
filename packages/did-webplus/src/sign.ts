import { base64urlEncode, concatBytes, utf8Encode } from "@zkred/did-core";
import { ed25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha2";
import { formatMbPubKey, type CurveName } from "./multiformat.js";
import { JOSE_ALG_BY_CURVE } from "./jws.js";
import { proofSigningInput } from "./selfhash.js";
import type { WebplusDidDocument } from "./types.js";

/** A key pair used for signing DID update proofs. */
export interface SigningKeyPair {
  curve: CurveName;
  privateKey: Uint8Array;
  /** Public key bytes: 32 for Ed25519, 33 (compressed point) for EC curves. */
  publicKey: Uint8Array;
  /** Multibase multicodec form of the public key, used in JWS `kid` and updateRules. */
  mbPubKey: string;
}

/** @deprecated Use {@link SigningKeyPair}; kept as an alias for 0.2.x compatibility. */
export type Ed25519KeyPair = SigningKeyPair;

/** Generate a new Ed25519 key pair, or derive one from a 32-byte private key. */
export function ed25519KeyPair(privateKey?: Uint8Array): SigningKeyPair {
  const priv = privateKey ?? ed25519.utils.randomPrivateKey();
  if (priv.length !== 32) {
    throw new TypeError(`ed25519 private key must be 32 bytes, got ${priv.length}`);
  }
  const publicKey = ed25519.getPublicKey(priv);
  return { curve: "ed25519", privateKey: priv, publicKey, mbPubKey: formatMbPubKey(publicKey) };
}

/** Generate a new secp256k1 key pair, or derive one from a 32-byte private key. */
export function secp256k1KeyPair(privateKey?: Uint8Array): SigningKeyPair {
  const priv = privateKey ?? secp256k1.utils.randomPrivateKey();
  const publicKey = secp256k1.getPublicKey(priv, true);
  return {
    curve: "secp256k1",
    privateKey: priv,
    publicKey,
    mbPubKey: formatMbPubKey(publicKey, "secp256k1"),
  };
}

/** Generate a new P-256 key pair, or derive one from a 32-byte private key. */
export function p256KeyPair(privateKey?: Uint8Array): SigningKeyPair {
  const priv = privateKey ?? p256.utils.randomPrivateKey();
  const publicKey = p256.getPublicKey(priv, true);
  return { curve: "p256", privateKey: priv, publicKey, mbPubKey: formatMbPubKey(publicKey, "p256") };
}

/** The `publicKeyJwk` fields for a public key: OKP/x for Ed25519, EC/x/y for EC curves. */
export function publicKeyJwkParams(
  publicKey: Uint8Array,
  curve: CurveName = "ed25519",
): { kty: string; crv: string; x: string; y?: string } {
  switch (curve) {
    case "ed25519":
      return { kty: "OKP", crv: "Ed25519", x: base64urlEncode(publicKey) };
    case "secp256k1":
    case "p256": {
      const point =
        curve === "secp256k1"
          ? secp256k1.ProjectivePoint.fromHex(publicKey)
          : p256.ProjectivePoint.fromHex(publicKey);
      const affine = point.toAffine();
      const coord = (n: bigint) => {
        const hex = n.toString(16).padStart(64, "0");
        return base64urlEncode(Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16))));
      };
      return {
        kty: "EC",
        crv: curve === "secp256k1" ? "secp256k1" : "P-256",
        x: coord(affine.x),
        y: coord(affine.y),
      };
    }
  }
}

function signWithCurve(
  curve: CurveName,
  signingInput: Uint8Array,
  privateKey: Uint8Array,
): Uint8Array {
  switch (curve) {
    case "ed25519":
      return ed25519.sign(signingInput, privateKey);
    case "secp256k1":
      return secp256k1.sign(sha256(signingInput), privateKey).toCompactRawBytes();
    case "p256":
      return p256.sign(sha256(signingInput), privateKey).toCompactRawBytes();
  }
}

/**
 * Sign a proof over an arbitrary payload as a detached, unencoded-payload
 * JWS (RFC 7797, `b64: false`), with the signer's multibase public key as
 * `kid` — the shape did:webplus proofs use.
 */
export function signDetachedJws(payload: Uint8Array, keyPair: SigningKeyPair): string {
  // Header field order matches the reference implementation's output.
  const header = {
    alg: JOSE_ALG_BY_CURVE[keyPair.curve],
    kid: keyPair.mbPubKey,
    crit: ["b64"],
    b64: false,
  };
  const protectedB64 = base64urlEncode(utf8Encode(JSON.stringify(header)));
  const signingInput = concatBytes(utf8Encode(`${protectedB64}.`), payload);
  const signature = signWithCurve(keyPair.curve, signingInput, keyPair.privateKey);
  return `${protectedB64}..${base64urlEncode(signature)}`;
}

/**
 * Produce a did:webplus update proof for `doc`: a detached JWS over the
 * document's proof signing input (JCS, no `proofs`, placeholder self-hashes).
 * Attach the result to `doc.proofs` *before* self-hashing the document.
 */
export function signProof(doc: WebplusDidDocument, keyPair: SigningKeyPair): string {
  return signDetachedJws(proofSigningInput(doc), keyPair);
}