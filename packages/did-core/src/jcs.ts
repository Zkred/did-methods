/**
 * JSON Canonicalization Scheme (JCS), RFC 8785.
 *
 * Produces the canonical serialization used for hashing and signing:
 * object keys sorted by UTF-16 code units, no whitespace, ECMAScript
 * number formatting (which JSON.stringify implements).
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("cannot canonicalize non-finite number");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalize(v === undefined ? null : v)).join(",")}]`;
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const parts: string[] = [];
    for (const key of Object.keys(record).sort()) {
      if (record[key] === undefined) continue;
      parts.push(`${JSON.stringify(key)}:${canonicalize(record[key])}`);
    }
    return `{${parts.join(",")}}`;
  }
  throw new TypeError(`cannot canonicalize value of type ${typeof value}`);
}