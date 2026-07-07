import {
  base64urlDecode,
  base64urlEncode,
  concatBytes,
  varintDecode,
  varintEncode,
} from "@zkred/did-core";
import { blake3 } from "@noble/hashes/blake3";
import { sha224, sha256, sha384, sha512 } from "@noble/hashes/sha2";

/**
 * Multibase-encoded multihash values ("MBHash") and multicodec public keys
 * ("MBPubKey") as used by did:webplus. Only the base64url multibase prefix
 * (`u`) is currently emitted by the reference implementation.
 */

type HashFn = (data: Uint8Array) => Uint8Array;

/** Multicodec hash-function codes supported by the reference implementation. */
const HASH_FUNCTIONS: Record<number, { name: string; fn: HashFn }> = {
  0x12: { name: "sha2-256", fn: sha256 },
  0x13: { name: "sha2-512", fn: sha512 },
  0x1e: { name: "blake3", fn: blake3 },
  0x20: { name: "sha2-384", fn: sha384 },
  0x1013: { name: "sha2-224", fn: sha224 },
};

/** Supported signature curves and their multicodec public-key codes. */
export type CurveName = "ed25519" | "secp256k1" | "p256";

const PUB_KEY_CODE_BY_CURVE: Record<CurveName, number> = {
  ed25519: 0xed,
  secp256k1: 0xe7,
  p256: 0x1200,
};

/** Raw key byte length per curve: 32 for Ed25519, 33 (compressed point) for the EC curves. */
const PUB_KEY_LENGTH_BY_CURVE: Record<CurveName, number> = {
  ed25519: 32,
  secp256k1: 33,
  p256: 33,
};

const CURVE_BY_PUB_KEY_CODE = new Map<number, CurveName>(
  (Object.entries(PUB_KEY_CODE_BY_CURVE) as Array<[CurveName, number]>).map(([name, code]) => [
    code,
    name,
  ]),
);

/** Hash function names accepted where a hash function must be chosen (e.g. DID creation). */
export type HashFunctionName = "blake3" | "sha2-256" | "sha2-512" | "sha2-384" | "sha2-224";

const HASH_CODE_BY_NAME: Record<HashFunctionName, number> = {
  "sha2-256": 0x12,
  "sha2-512": 0x13,
  blake3: 0x1e,
  "sha2-384": 0x20,
  "sha2-224": 0x1013,
};

export interface ParsedMbHash {
  /** Multicodec hash function code (e.g. 0x1e for BLAKE3). */
  code: number;
  /** Digest length in bytes. */
  length: number;
  digest: Uint8Array;
}

function decodeMultibase(value: string, what: string): Uint8Array {
  if (!value.startsWith("u")) {
    throw new TypeError(`${what} must be multibase base64url (prefix "u"): ${value}`);
  }
  return base64urlDecode(value.slice(1));
}

/** Parse a multibase multihash string like `uHiAgZ9Z9FJ38...`. */
export function parseMbHash(mbHash: string): ParsedMbHash {
  const bytes = decodeMultibase(mbHash, "MBHash");
  const code = varintDecode(bytes, 0);
  const length = varintDecode(bytes, code.length);
  const digest = bytes.subarray(code.length + length.length);
  if (digest.length !== length.value) {
    throw new TypeError(
      `MBHash digest length ${digest.length} does not match declared length ${length.value}`,
    );
  }
  return { code: code.value, length: length.value, digest };
}

function encodeMbHash(code: number, digest: Uint8Array): string {
  return `u${base64urlEncode(concatBytes(varintEncode(code), varintEncode(digest.length), digest))}`;
}

/**
 * The placeholder value for a hash function: the multihash header followed by
 * an all-zeros digest. Self-hash slots are set to this before hashing.
 */
export function placeholderMbHash(templateMbHash: string): string {
  const { code, length } = parseMbHash(templateMbHash);
  requireHashFunction(code);
  return encodeMbHash(code, new Uint8Array(length));
}

function requireHashFunction(code: number): { name: string; fn: HashFn } {
  const entry = HASH_FUNCTIONS[code];
  if (!entry) {
    throw new TypeError(`unsupported multihash function code 0x${code.toString(16)}`);
  }
  return entry;
}

/** Hash `data` with the same hash function as `templateMbHash`, producing an MBHash string. */
export function hashAsMbHash(templateMbHash: string, data: Uint8Array): string {
  const { code } = parseMbHash(templateMbHash);
  const digest = requireHashFunction(code).fn(data);
  return encodeMbHash(code, digest);
}

/** Hash `data` with a hash function chosen by name, producing an MBHash string. */
export function hashWithFunction(name: HashFunctionName, data: Uint8Array): string {
  const code = HASH_CODE_BY_NAME[name];
  if (code === undefined) {
    throw new TypeError(`unsupported hash function name: ${name}`);
  }
  const digest = requireHashFunction(code).fn(data);
  return encodeMbHash(code, digest);
}

/** The all-zeros placeholder MBHash for a hash function chosen by name. */
export function placeholderForFunction(name: HashFunctionName): string {
  return placeholderMbHash(hashWithFunction(name, new Uint8Array(0)));
}

/**
 * Encode raw public key bytes as a multibase multicodec key string
 * (e.g. `u7Q...` for Ed25519). EC curves expect the 33-byte compressed point,
 * matching the reference implementation's `mbx` crate.
 */
export function formatMbPubKey(keyBytes: Uint8Array, curve: CurveName = "ed25519"): string {
  const expected = PUB_KEY_LENGTH_BY_CURVE[curve];
  if (keyBytes.length !== expected) {
    throw new TypeError(`${curve} public key must be ${expected} bytes, got ${keyBytes.length}`);
  }
  return `u${base64urlEncode(concatBytes(varintEncode(PUB_KEY_CODE_BY_CURVE[curve]), keyBytes))}`;
}

/** Decode a multibase multicodec public key like `u7QG2O2Vm...` into its curve and raw key bytes. */
export function parseMbPubKey(mbPubKey: string): { curve: CurveName; keyBytes: Uint8Array } {
  const bytes = decodeMultibase(mbPubKey, "MBPubKey");
  const code = varintDecode(bytes, 0);
  const curve = CURVE_BY_PUB_KEY_CODE.get(code.value);
  if (!curve) {
    throw new TypeError(`unsupported public key multicodec 0x${code.value.toString(16)}`);
  }
  const keyBytes = bytes.subarray(code.length);
  const expected = PUB_KEY_LENGTH_BY_CURVE[curve];
  if (keyBytes.length !== expected) {
    throw new TypeError(`${curve} public key must be ${expected} bytes, got ${keyBytes.length}`);
  }
  return { curve, keyBytes };
}