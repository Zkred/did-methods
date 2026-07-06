import { base64urlDecode, concatBytes, utf8Encode } from "@zkred/did-core";
import { ed25519 } from "@noble/curves/ed25519";
import { parseMbPubKey } from "./multiformat.js";

/**
 * did:webplus proofs are compact JWS with a detached, unencoded payload
 * (RFC 7797, `"b64": false`), signed with Ed25519. The `kid` header carries
 * the multibase multicodec public key itself, so verification needs no key
 * lookup.
 */

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
  if (header.alg !== "Ed25519" && header.alg !== "EdDSA") {
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

/**
 * Verify a detached unencoded-payload JWS over `payload`.
 * Returns the verified signer's public key (the `kid`, a multibase multicodec
 * key string), or throws if the JWS is malformed or the signature is invalid.
 */
export function verifyDetachedJws(jws: string, payload: Uint8Array): string {
  const { protectedB64, header, signature } = parseDetachedJws(jws);
  const { keyBytes } = parseMbPubKey(header.kid);
  // RFC 7797 with b64=false: signing input is ASCII(protected || '.') || payload.
  const signingInput = concatBytes(utf8Encode(`${protectedB64}.`), payload);
  if (!ed25519.verify(signature, signingInput, keyBytes)) {
    throw new TypeError("JWS signature verification failed");
  }
  return header.kid;
}