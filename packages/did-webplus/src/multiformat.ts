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

const ED25519_PUB_CODE = 0xed;

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

/** Encode raw Ed25519 public key bytes as a multibase multicodec key string (`u7Q...`). */
export function formatMbPubKey(keyBytes: Uint8Array): string {
  if (keyBytes.length !== 32) {
    throw new TypeError(`ed25519 public key must be 32 bytes, got ${keyBytes.length}`);
  }
  return `u${base64urlEncode(concatBytes(varintEncode(ED25519_PUB_CODE), keyBytes))}`;
}

/** Decode a multibase multicodec public key like `u7QG2O2Vm...` into raw Ed25519 key bytes. */
export function parseMbPubKey(mbPubKey: string): { codecName: string; keyBytes: Uint8Array } {
  const bytes = decodeMultibase(mbPubKey, "MBPubKey");
  const code = varintDecode(bytes, 0);
  if (code.value !== ED25519_PUB_CODE) {
    throw new TypeError(
      `unsupported public key multicodec 0x${code.value.toString(16)} (only ed25519-pub is supported)`,
    );
  }
  const keyBytes = bytes.subarray(code.length);
  if (keyBytes.length !== 32) {
    throw new TypeError(`ed25519 public key must be 32 bytes, got ${keyBytes.length}`);
  }
  return { codecName: "ed25519-pub", keyBytes };
}