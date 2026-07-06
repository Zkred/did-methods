const B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const B64URL_LOOKUP = new Map<string, number>(
  Array.from(B64URL_ALPHABET, (c, i) => [c, i] as const),
);

/** Encode bytes as base64url without padding. */
export function base64urlEncode(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    out += B64URL_ALPHABET[b0 >> 2]!;
    out += B64URL_ALPHABET[((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4)]!;
    if (b1 === undefined) break;
    out += B64URL_ALPHABET[((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6)]!;
    if (b2 === undefined) break;
    out += B64URL_ALPHABET[b2 & 0x3f]!;
  }
  return out;
}

/** Decode base64url (no padding) into bytes. Throws on invalid characters. */
export function base64urlDecode(text: string): Uint8Array {
  const rem = text.length % 4;
  if (rem === 1) {
    throw new TypeError("invalid base64url length");
  }
  const outLength = Math.floor((text.length * 3) / 4);
  const out = new Uint8Array(outLength);
  let bits = 0;
  let bitCount = 0;
  let o = 0;
  for (const char of text) {
    const value = B64URL_LOOKUP.get(char);
    if (value === undefined) {
      throw new TypeError(`invalid base64url character: ${JSON.stringify(char)}`);
    }
    bits = (bits << 6) | value;
    bitCount += 6;
    if (bitCount >= 8) {
      bitCount -= 8;
      out[o++] = (bits >> bitCount) & 0xff;
    }
  }
  return out;
}

/** Encode an unsigned integer as a multiformats varint (LEB128). */
export function varintEncode(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0) {
    throw new TypeError("varint value must be a non-negative integer");
  }
  const out: number[] = [];
  let v = value;
  do {
    let byte = v & 0x7f;
    v >>>= 7;
    if (v !== 0) byte |= 0x80;
    out.push(byte);
  } while (v !== 0);
  return Uint8Array.from(out);
}

/** Decode a multiformats varint at `offset`. Returns the value and bytes consumed. */
export function varintDecode(bytes: Uint8Array, offset = 0): { value: number; length: number } {
  let value = 0;
  let shift = 0;
  let length = 0;
  for (let i = offset; i < bytes.length; i++) {
    const byte = bytes[i]!;
    value |= (byte & 0x7f) << shift;
    length++;
    if ((byte & 0x80) === 0) {
      return { value: value >>> 0, length };
    }
    shift += 7;
    if (shift > 28) {
      throw new TypeError("varint too long");
    }
  }
  throw new TypeError("truncated varint");
}

export function utf8Encode(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}
