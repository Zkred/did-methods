import { utf8Encode } from "@zkred/did-core";
import { hashAsMbHash } from "./multiformat.js";
import type { UpdateRules } from "./types.js";

/**
 * Evaluate an updateRules tree against the set of public keys (multibase
 * multicodec strings, i.e. JWS `kid` values) that produced valid proofs.
 *
 * Rule forms, mirroring the reference implementation:
 * - `{ key }`        — some valid proof key equals `key` exactly
 * - `{ hashedKey }`  — hashing some valid proof key's *string bytes* (with the
 *                      hash function encoded in `hashedKey`) equals `hashedKey`
 * - `{ any: [...] }` — at least one sub-rule is satisfied
 * - `{ all: [...] }` — every sub-rule is satisfied
 * - `{ atLeast, of: [...] }` — the weights (default 1) of satisfied sub-rules
 *                      sum to at least `atLeast`
 * - `{}`             — updates disallowed; never satisfied
 */
export function evaluateUpdateRules(rules: UpdateRules, validProofKeys: string[]): boolean {
  if ("key" in rules && typeof rules.key === "string") {
    return validProofKeys.includes(rules.key);
  }
  if ("hashedKey" in rules && typeof rules.hashedKey === "string") {
    const hashedKey = rules.hashedKey;
    return validProofKeys.some((key) => hashAsMbHash(hashedKey, utf8Encode(key)) === hashedKey);
  }
  if ("any" in rules && Array.isArray(rules.any)) {
    return rules.any.some((rule) => evaluateUpdateRules(rule, validProofKeys));
  }
  if ("all" in rules && Array.isArray(rules.all)) {
    return rules.all.every((rule) => evaluateUpdateRules(rule, validProofKeys));
  }
  if ("atLeast" in rules && typeof rules.atLeast === "number" && Array.isArray(rules.of)) {
    let weightSum = 0;
    for (const weighted of rules.of) {
      const { weight = 1, ...rule } = weighted;
      if (evaluateUpdateRules(rule as UpdateRules, validProofKeys)) {
        weightSum += weight;
      }
    }
    return weightSum >= rules.atLeast;
  }
  if (Object.keys(rules).length === 0) {
    // UpdatesDisallowed: no update can ever satisfy it.
    return false;
  }
  throw new TypeError(`unrecognized updateRules form: ${JSON.stringify(rules)}`);
}