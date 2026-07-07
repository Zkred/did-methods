import { describe, expect, it } from "vitest";
import { createDidDocument, hashedKeyRule, keyRule, updateDidDocument } from "../src/controller.js";
import {
  ed25519KeyPair,
  p256KeyPair,
  publicKeyJwkParams,
  secp256k1KeyPair,
  signDetachedJws,
} from "../src/sign.js";
import { verifyDetachedJws } from "../src/jws.js";
import { formatMbPubKey, parseMbPubKey } from "../src/multiformat.js";
import { validateMicroledger } from "../src/microledger.js";
import { verifyDocumentSelfHash } from "../src/selfhash.js";
import { utf8Encode } from "@zkred/did-core";

const seed = (n: number) => Uint8Array.from({ length: 32 }, (_, i) => (i * 11 + n + 1) & 0xff);

describe("multicodec public keys per curve", () => {
  it("round-trips secp256k1 and P-256 compressed keys", () => {
    for (const pair of [secp256k1KeyPair(seed(1)), p256KeyPair(seed(2))]) {
      expect(pair.publicKey).toHaveLength(33);
      const parsed = parseMbPubKey(pair.mbPubKey);
      expect(parsed.curve).toBe(pair.curve);
      expect(Buffer.from(parsed.keyBytes)).toEqual(Buffer.from(pair.publicKey));
      expect(formatMbPubKey(parsed.keyBytes, parsed.curve)).toBe(pair.mbPubKey);
    }
  });

  it("rejects wrong key lengths per curve", () => {
    expect(() => formatMbPubKey(new Uint8Array(32), "secp256k1")).toThrow(/33 bytes/);
    expect(() => formatMbPubKey(new Uint8Array(33), "ed25519")).toThrow(/32 bytes/);
  });
});

describe("JWS sign/verify per curve", () => {
  const payload = utf8Encode("did:webplus multi-curve payload");

  it.each([
    ["Ed25519", () => ed25519KeyPair(seed(3))],
    ["ES256K", () => secp256k1KeyPair(seed(4))],
    ["ES256", () => p256KeyPair(seed(5))],
  ] as const)("signs and verifies with alg %s", (alg, make) => {
    const pair = make();
    const jws = signDetachedJws(payload, pair);
    const headerJson = JSON.parse(
      Buffer.from(jws.split(".")[0]!, "base64url").toString("utf8"),
    ) as { alg: string; b64: boolean };
    expect(headerJson.alg).toBe(alg);
    expect(headerJson.b64).toBe(false);
    expect(verifyDetachedJws(jws, payload)).toBe(pair.mbPubKey);
    expect(() => verifyDetachedJws(jws, utf8Encode("tampered"))).toThrow(/verification failed/);
  });
});

describe("publicKeyJwkParams", () => {
  it("produces OKP JWKs for Ed25519 and EC JWKs with x/y for EC curves", () => {
    const ed = publicKeyJwkParams(ed25519KeyPair(seed(6)).publicKey, "ed25519");
    expect(ed).toMatchObject({ kty: "OKP", crv: "Ed25519" });
    expect(ed.y).toBeUndefined();

    const k1 = publicKeyJwkParams(secp256k1KeyPair(seed(7)).publicKey, "secp256k1");
    expect(k1).toMatchObject({ kty: "EC", crv: "secp256k1" });
    expect(k1.x).toHaveLength(43); // 32 bytes base64url
    expect(k1.y).toHaveLength(43);

    const r1 = publicKeyJwkParams(p256KeyPair(seed(8)).publicKey, "p256");
    expect(r1).toMatchObject({ kty: "EC", crv: "P-256" });
  });
});

describe("multi-curve microledger round-trip", () => {
  it("creates and updates a DID using secp256k1 and P-256 keys, passing full verification", async () => {
    const vmKey = secp256k1KeyPair(seed(9));
    const updateKey = p256KeyPair(seed(10));
    const nextVmKey = p256KeyPair(seed(11));

    const root = createDidDocument({
      host: "example.com",
      keys: [{ publicKey: vmKey.publicKey, curve: "secp256k1" }],
      updateRules: hashedKeyRule(updateKey.publicKey, "blake3", "p256"),
      validFrom: "2026-07-07T06:00:00.000Z",
      signers: [vmKey],
    });
    expect(verifyDocumentSelfHash(root)).toEqual({ valid: true });
    expect(root.verificationMethod?.[0]?.publicKeyJwk?.crv).toBe("secp256k1");

    const next = updateDidDocument(root, {
      keys: [{ publicKey: nextVmKey.publicKey, curve: "p256" }],
      updateRules: keyRule(nextVmKey.publicKey, "p256"),
      signers: [updateKey],
      validFrom: "2026-07-07T06:00:01.000Z",
    });

    const result = await validateMicroledger([root, next], { expectedDid: root.id });
    expect(result.errors).toEqual([]);
  });

  it("rejects an update whose EC proof does not satisfy the rules", async () => {
    const vmKey = ed25519KeyPair(seed(12));
    const updateKey = secp256k1KeyPair(seed(13));
    const wrongKey = secp256k1KeyPair(seed(14));

    const root = createDidDocument({
      host: "example.com",
      keys: [{ publicKey: vmKey.publicKey }],
      updateRules: keyRule(updateKey.publicKey, "secp256k1"),
      validFrom: "2026-07-07T06:00:00.000Z",
    });
    const forged = updateDidDocument(root, {
      keys: [{ publicKey: vmKey.publicKey }],
      updateRules: keyRule(wrongKey.publicKey, "secp256k1"),
      signers: [wrongKey],
      validFrom: "2026-07-07T06:00:01.000Z",
    });
    const result = await validateMicroledger([root, forged]);
    expect(result.valid).toBe(false);
  });
});
