import { base64urlDecode, base64urlEncode, concatBytes, utf8Encode } from "@zkred/did-core";
import { ed25519 } from "@noble/curves/ed25519";
import { ed448 } from "@noble/curves/ed448";
import { secp256k1 } from "@noble/curves/secp256k1";
import { p256 } from "@noble/curves/p256";
import { p384 } from "@noble/curves/p384";
import { p521 } from "@noble/curves/p521";
import { sha256, sha384, sha512 } from "@noble/hashes/sha2";
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

/** Generate a new Ed448 key pair, or derive one from a 57-byte private key. */
export function ed448KeyPair(privateKey?: Uint8Array): SigningKeyPair {
  const priv = privateKey ?? ed448.utils.randomPrivateKey();
  const publicKey = ed448.getPublicKey(priv);
  return { curve: "ed448", privateKey: priv, publicKey, mbPubKey: formatMbPubKey(publicKey, "ed448") };
}

/** Generate a new P-384 key pair, or derive one from a private key. */
export function p384KeyPair(privateKey?: Uint8Array): SigningKeyPair {
  const priv = privateKey ?? p384.utils.randomPrivateKey();
  const publicKey = p384.getPublicKey(priv, true);
  return { curve: "p384", privateKey: priv, publicKey, mbPubKey: formatMbPubKey(publicKey, "p384") };
}

/** Generate a new P-521 key pair, or derive one from a private key. */
export function p521KeyPair(privateKey?: Uint8Array): SigningKeyPair {
  const priv = privateKey ?? p521.utils.randomPrivateKey();
  const publicKey = p521.getPublicKey(priv, true);
  return { curve: "p521", privateKey: priv, publicKey, mbPubKey: formatMbPubKey(publicKey, "p521") };
}

/** The `publicKeyJwk` fields for a public key: OKP/x for Ed25519, EC/x/y for EC curves. */
export function publicKeyJwkParams(
  publicKey: Uint8Array,
  curve: CurveName = "ed25519",
): { kty: string; crv: string; x: string; y?: string } {
  switch (curve) {
    case "ed25519":
      return { kty: "OKP", crv: "Ed25519", x: base64urlEncode(publicKey) };
    case "ed448":
      return { kty: "OKP", crv: "Ed448", x: base64urlEncode(publicKey) };
    case "secp256k1":
    case "p256":
    case "p384":
    case "p521": {
      const ec = { secp256k1, p256, p384, p521 }[curve];
      const coordBytes = { secp256k1: 32, p256: 32, p384: 48, p521: 66 }[curve];
      const crv = { secp256k1: "secp256k1", p256: "P-256", p384: "P-384", p521: "P-521" }[curve];
      const affine = ec.ProjectivePoint.fromHex(publicKey).toAffine();
      const coord = (n: bigint) => {
        const hex = n.toString(16).padStart(coordBytes * 2, "0");
        return base64urlEncode(Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16))));
      };
      return { kty: "EC", crv, x: coord(affine.x), y: coord(affine.y) };
    }
  }
}

/**
 * Recover raw public key bytes (and curve) from `publicKeyJwk` fields:
 * the 32-byte key for Ed25519 (OKP), or the 33-byte compressed point
 * rebuilt from x/y coordinates for EC curves.
 */
export function publicKeyBytesFromJwk(jwk: {
  crv?: string;
  x?: string;
  y?: string;
}): { curve: CurveName; publicKey: Uint8Array } {
  if (typeof jwk.x !== "string") {
    throw new TypeError("publicKeyJwk is missing x");
  }
  switch (jwk.crv) {
    case "Ed25519":
      return { curve: "ed25519", publicKey: base64urlDecode(jwk.x) };
    case "Ed448":
      return { curve: "ed448", publicKey: base64urlDecode(jwk.x) };
    case "secp256k1":
    case "P-256":
    case "P-384":
    case "P-521": {
      if (typeof jwk.y !== "string") {
        throw new TypeError(`EC publicKeyJwk with crv ${jwk.crv} is missing y`);
      }
      const curve: CurveName = (
        { secp256k1: "secp256k1", "P-256": "p256", "P-384": "p384", "P-521": "p521" } as const
      )[jwk.crv];
      const ec = { secp256k1, p256, p384, p521 }[curve];
      const uncompressed = concatBytes(
        Uint8Array.of(0x04),
        base64urlDecode(jwk.x),
        base64urlDecode(jwk.y),
      );
      return { curve, publicKey: ec.ProjectivePoint.fromHex(uncompressed).toRawBytes(true) };
    }
    default:
      throw new TypeError(`unsupported publicKeyJwk crv: ${jwk.crv}`);
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
    case "ed448":
      return ed448.sign(signingInput, privateKey);
    case "secp256k1":
      return secp256k1.sign(sha256(signingInput), privateKey).toCompactRawBytes();
    case "p256":
      return p256.sign(sha256(signingInput), privateKey).toCompactRawBytes();
    case "p384":
      return p384.sign(sha384(signingInput), privateKey).toCompactRawBytes();
    case "p521":
      return p521.sign(sha512(signingInput), privateKey).toCompactRawBytes();
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