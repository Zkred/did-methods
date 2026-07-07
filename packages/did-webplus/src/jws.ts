import { base64urlDecode, concatBytes, utf8Encode } from "@zkred/did-core";
import { ed25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha2";
import { parseMbPubKey, type CurveName } from "./multiformat.js";

/**
 * did:webplus proofs are compact JWS with a detached, unencoded payload
 * (RFC 7797, `"b64": false`). The `kid` header carries the multibase
 * multicodec public key itself, so verification needs no key lookup.
 *
 * Supported algorithms (matching the reference implementation's JOSE names):
 * `Ed25519` (and standard `EdDSA`), `ES256K` (secp256k1), `ES256` (P-256).
 */

/** The JOSE `alg` value used for each curve. */
export const JOSE_ALG_BY_CURVE: Record<CurveName, string> = {
  ed25519: "Ed25519",
  secp256k1: "ES256K",
  p256: "ES256",
};

const CURVE_BY_JOSE_ALG: Record<string, CurveName> = {
  Ed25519: "ed25519",
  EdDSA: "ed25519",
  ES256K: "secp256k1",
  ES256: "p256",
};

export interface JwsHeader {
  alg: string;
  kid: string;
  crit?: string[];
  b64?: boolean;
  [key: string]: unknown;
}

export interface ParsedJws {
  protectedB64: string;
  header: JwsHeader;
  signature: Uint8Array;
}

export function parseDetachedJws(jws: string): ParsedJws {
  const parts = jws.split(".");
  if (parts.length !== 3) {
    throw new TypeError("JWS must have three dot-separated parts");
  }
  const [protectedB64, payloadB64, signatureB64] = parts as [string, string, string];
  if (payloadB64 !== "") {
    throw new TypeError("expected a detached-payload JWS (empty payload part)");
  }
  let header: JwsHeader;
  try {
    header = JSON.parse(new TextDecoder().decode(base64urlDecode(protectedB64))) as JwsHeader;
  } catch {
    throw new TypeError("JWS protected header is not valid base64url JSON");
  }
  if (!(header.alg in CURVE_BY_JOSE_ALG)) {
    throw new TypeError(`unsupported JWS alg: ${header.alg}`);
  }
  if (header.b64 !== false || !header.crit?.includes("b64")) {
    throw new TypeError('expected an unencoded-payload JWS ("b64": false with "b64" in "crit")');
  }
  if (typeof header.kid !== "string") {
    throw new TypeError("JWS header is missing kid");
  }
  return { protectedB64, header, signature: base64urlDecode(signatureB64) };
}

function verifySignature(
  curve: CurveName,
  signature: Uint8Array,
  signingInput: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  switch (curve) {
    case "ed25519":
      return ed25519.verify(signature, signingInput, publicKey);
    case "secp256k1":
      return secp256k1.verify(signature, sha256(signingInput), publicKey);
    case "p256":
      return p256.verify(signature, sha256(signingInput), publicKey);
  }
}

/**
 * Verify a detached unencoded-payload JWS over `payload`.
 * Returns the verified signer's public key (the `kid`, a multibase multicodec
 * key string), or throws if the JWS is malformed or the signature is invalid.
 */
export function verifyDetachedJws(jws: string, payload: Uint8Array): string {
  const { protectedB64, header, signature } = parseDetachedJws(jws);
  const { curve, keyBytes } = parseMbPubKey(header.kid);
  if (CURVE_BY_JOSE_ALG[header.alg] !== curve) {
    throw new TypeError(`JWS alg ${header.alg} does not match kid key type ${curve}`);
  }
  // RFC 7797 with b64=false: signing input is ASCII(protected || '.') || payload.
  const signingInput = concatBytes(utf8Encode(`${protectedB64}.`), payload);
  if (!verifySignature(curve, signature, signingInput, keyBytes)) {
    throw new TypeError("JWS signature verification failed");
  }
  return header.kid;
}