import {
  base64urlDecode,
  base64urlEncode,
  concatBytes,
  varintDecode,
  varintEncode,
} from "@zkred/did-core";
import { blake3 } from "@noble/hashes/blake3";
import { sha224, sha256, sha384, sha512 } from "@noble/hashes/sha2";
import { sha3_224, sha3_256, sha3_384, sha3_512 } from "@noble/hashes/sha3";

/**
 * Multibase-encoded multihash values ("MBHash") and multicodec public keys
 * ("MBPubKey") as used by did:webplus. Supported multibase prefixes:
 * `u` (base64url, the reference implementation's default), `z` (base58btc),
 * and `b` (base32 lower, RFC 4648, no padding). Derived values (placeholders,
 * computed hashes) preserve the base of the value they derive from.
 */

export type MultibasePrefix = "u" | "z" | "b";

// --- base58btc ---------------------------------------------------------

const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B58_MAP = new Map([...B58_ALPHABET].map((c, i) => [c, BigInt(i)]));

function base58btcEncode(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = "";
  while (n > 0n) {
    out = B58_ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = "1" + out;
  }
  return out;
}

function base58btcDecode(value: string): Uint8Array {
  let n = 0n;
  for (const c of value) {
    const v = B58_MAP.get(c);
    if (v === undefined) throw new TypeError(`invalid base58btc character: ${c}`);
    n = n * 58n + v;
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n % 256n));
    n /= 256n;
  }
  for (const c of value) {
    if (c !== "1") break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}

// --- base32 lower (RFC 4648, no padding) --------------------------------

const B32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
const B32_MAP = new Map([...B32_ALPHABET].map((c, i) => [c, i]));

function base32lowerEncode(bytes: Uint8Array): string {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const b of bytes) {
    buffer = (buffer << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += B32_ALPHABET[(buffer << (5 - bits)) & 31];
  }
  return out;
}

function base32lowerDecode(value: string): Uint8Array {
  let buffer = 0;
  let bits = 0;
  const out: number[] = [];
  for (const c of value) {
    const v = B32_MAP.get(c);
    if (v === undefined) throw new TypeError(`invalid base32lower character: ${c}`);
    buffer = (buffer << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

// --- multibase ----------------------------------------------------------

export function decodeMultibase(value: string, what: string): {
  base: MultibasePrefix;
  bytes: Uint8Array;
} {
  const prefix = value[0];
  const rest = value.slice(1);
  switch (prefix) {
    case "u":
      return { base: "u", bytes: base64urlDecode(rest) };
    case "z":
      return { base: "z", bytes: base58btcDecode(rest) };
    case "b":
      return { base: "b", bytes: base32lowerDecode(rest) };
    default:
      throw new TypeError(
        `${what} must be multibase base64url ("u"), base58btc ("z"), or base32lower ("b"): ${value}`,
      );
  }
}

export function encodeMultibase(base: MultibasePrefix, bytes: Uint8Array): string {
  switch (base) {
    case "u":
      return `u${base64urlEncode(bytes)}`;
    case "z":
      return `z${base58btcEncode(bytes)}`;
    case "b":
      return `b${base32lowerEncode(bytes)}`;
  }
}

// --- hash functions -----------------------------------------------------

type HashFn = (data: Uint8Array) => Uint8Array;

/** Multicodec hash-function codes supported by the reference implementation. */
const HASH_FUNCTIONS: Record<number, { name: string; fn: HashFn }> = {
  0x12: { name: "sha2-256", fn: sha256 },
  0x13: { name: "sha2-512", fn: sha512 },
  0x14: { name: "sha3-512", fn: sha3_512 },
  0x15: { name: "sha3-384", fn: sha3_384 },
  0x16: { name: "sha3-256", fn: sha3_256 },
  0x17: { name: "sha3-224", fn: sha3_224 },
  0x1e: { name: "blake3", fn: blake3 },
  0x20: { name: "sha2-384", fn: sha384 },
  0x1013: { name: "sha2-224", fn: sha224 },
};

/** Supported signature curves and their multicodec public-key codes. */
export type CurveName = "ed25519" | "ed448" | "secp256k1" | "p256" | "p384" | "p521";

const PUB_KEY_CODE_BY_CURVE: Record<CurveName, number> = {
  ed25519: 0xed,
  secp256k1: 0xe7,
  p256: 0x1200,
  p384: 0x1201,
  p521: 0x1202,
  ed448: 0x1203,
};

/**
 * Raw key byte length per curve: the raw key for Edwards curves (32 for
 * Ed25519, 57 for Ed448) and the compressed point for the EC curves
 * (33 / 49 / 67 bytes), matching the reference implementation's `mbx` crate.
 */
const PUB_KEY_LENGTH_BY_CURVE: Record<CurveName, number> = {
  ed25519: 32,
  ed448: 57,
  secp256k1: 33,
  p256: 33,
  p384: 49,
  p521: 67,
};

const CURVE_BY_PUB_KEY_CODE = new Map<number, CurveName>(
  (Object.entries(PUB_KEY_CODE_BY_CURVE) as Array<[CurveName, number]>).map(([name, code]) => [
    code,
    name,
  ]),
);

/** Hash function names accepted where a hash function must be chosen (e.g. DID creation). */
export type HashFunctionName =
  | "blake3"
  | "sha2-256"
  | "sha2-512"
  | "sha2-384"
  | "sha2-224"
  | "sha3-256"
  | "sha3-512"
  | "sha3-384"
  | "sha3-224";

const HASH_CODE_BY_NAME: Record<HashFunctionName, number> = {
  "sha2-256": 0x12,
  "sha2-512": 0x13,
  "sha3-512": 0x14,
  "sha3-384": 0x15,
  "sha3-256": 0x16,
  "sha3-224": 0x17,
  blake3: 0x1e,
  "sha2-384": 0x20,
  "sha2-224": 0x1013,
};

export interface ParsedMbHash {
  /** Multibase prefix the value was encoded with. */
  base: MultibasePrefix;
  /** Multicodec hash function code (e.g. 0x1e for BLAKE3). */
  code: number;
  /** Digest length in bytes. */
  length: number;
  digest: Uint8Array;
}

/** Parse a multibase multihash string like `uHiAgZ9Z9FJ38...`. */
export function parseMbHash(mbHash: string): ParsedMbHash {
  const { base, bytes } = decodeMultibase(mbHash, "MBHash");
  const code = varintDecode(bytes, 0);
  const length = varintDecode(bytes, code.length);
  const digest = bytes.subarray(code.length + length.length);
  if (digest.length !== length.value) {
    throw new TypeError(
      `MBHash digest length ${digest.length} does not match declared length ${length.value}`,
    );
  }
  return { base, code: code.value, length: length.value, digest };
}

function encodeMbHash(code: number, digest: Uint8Array, base: MultibasePrefix): string {
  return encodeMultibase(
    base,
    concatBytes(varintEncode(code), varintEncode(digest.length), digest),
  );
}

/**
 * The placeholder value for a hash function: the multihash header followed by
 * an all-zeros digest, in the same multibase as the template. Self-hash slots
 * are set to this before hashing.
 */
export function placeholderMbHash(templateMbHash: string): string {
  const { base, code, length } = parseMbHash(templateMbHash);
  requireHashFunction(code);
  return encodeMbHash(code, new Uint8Array(length), base);
}

function requireHashFunction(code: number): { name: string; fn: HashFn } {
  const entry = HASH_FUNCTIONS[code];
  if (!entry) {
    throw new TypeError(`unsupported multihash function code 0x${code.toString(16)}`);
  }
  return entry;
}

/**
 * Hash `data` with the same hash function and multibase as `templateMbHash`,
 * producing an MBHash string byte-comparable with values from that source.
 */
export function hashAsMbHash(templateMbHash: string, data: Uint8Array): string {
  const { base, code } = parseMbHash(templateMbHash);
  const digest = requireHashFunction(code).fn(data);
  return encodeMbHash(code, digest, base);
}

/** Hash `data` with a hash function chosen by name, producing an MBHash string. */
export function hashWithFunction(
  name: HashFunctionName,
  data: Uint8Array,
  base: MultibasePrefix = "u",
): string {
  const code = HASH_CODE_BY_NAME[name];
  if (code === undefined) {
    throw new TypeError(`unsupported hash function name: ${name}`);
  }
  const digest = requireHashFunction(code).fn(data);
  return encodeMbHash(code, digest, base);
}

/** The all-zeros placeholder MBHash for a hash function chosen by name. */
export function placeholderForFunction(
  name: HashFunctionName,
  base: MultibasePrefix = "u",
): string {
  return placeholderMbHash(hashWithFunction(name, new Uint8Array(0), base));
}

/**
 * Encode raw public key bytes as a multibase multicodec key string
 * (e.g. `u7Q...` for Ed25519). EC curves expect the compressed point,
 * matching the reference implementation's `mbx` crate.
 */
export function formatMbPubKey(
  keyBytes: Uint8Array,
  curve: CurveName = "ed25519",
  base: MultibasePrefix = "u",
): string {
  const expected = PUB_KEY_LENGTH_BY_CURVE[curve];
  if (keyBytes.length !== expected) {
    throw new TypeError(`${curve} public key must be ${expected} bytes, got ${keyBytes.length}`);
  }
  return encodeMultibase(
    base,
    concatBytes(varintEncode(PUB_KEY_CODE_BY_CURVE[curve]), keyBytes),
  );
}

/** Decode a multibase multicodec public key like `u7QG2O2Vm...` into its curve and raw key bytes. */
export function parseMbPubKey(mbPubKey: string): {
  curve: CurveName;
  keyBytes: Uint8Array;
  base: MultibasePrefix;
} {
  const { base, bytes } = decodeMultibase(mbPubKey, "MBPubKey");
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
  return { curve, keyBytes, base };
}
