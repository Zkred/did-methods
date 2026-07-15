# @zkred/did-webplus

## 0.5.0

### Minor Changes

- e961c11: Interop fixes driven by the reference implementation's interoperability test suite, plus DID deactivation.

  - **SHA3 support**: sha3-224/256/384/512 MBHash values (multicodec 0x17/0x16/0x15/0x14) are now supported everywhere hashes are computed or verified, as the spec requires.
  - **JCS on the wire**: `registerDid` / `submitDidUpdate` now POST/PUT the JCS (RFC 8785) serialization of DID documents, which VDRs are required to enforce.
  - **`deactivateDidDocument`**: creates the spec's tombstone document (`updateRules: {}`, no verification methods), permanently ending the DID's update history.

- 60dc36c: Add `publicKeyBytesFromJwk` (recover raw key bytes / compressed points from `publicKeyJwk` fields) and conformance tests against the reference implementation's JWK round-trip vectors (30 vectors across Ed25519, secp256k1, and P-256; both directions pass exactly).

## 0.4.0

### Minor Changes

- 8e47229: VDG resolution and multi-curve (secp256k1 / P-256) support.

  - **Verifiable Data Gateway**: the resolver accepts a `vdg` option (hostname or base URL); single-document resolution goes through `/webplus/v1/resolve/{didQuery}` and `verify: true` fetches full microledgers through `/webplus/v1/fetch/{did}/did-documents.jsonl`. New exports: `vdgResolutionUrl`, `vdgMicroledgerUrl`.
  - **secp256k1 + P-256**: key pairs (`secp256k1KeyPair`, `p256KeyPair`), EC `publicKeyJwk` entries (kty EC with x/y), `ES256K`/`ES256` JWS proofs, and multicodec compressed-point public keys — usable in verification methods, proof signing/verification, and `keyRule`/`hashedKeyRule` (which now take an optional curve). `Ed25519KeyPair` is renamed `SigningKeyPair` (old name kept as a deprecated alias), and `ed25519PublicKeyJwkX` is replaced by `publicKeyJwkParams`.

## 0.3.0

### Minor Changes

- d5f2964: Complete the core did:webplus feature set: verified resolution, versionTime, and controller operations.

  - **Fetch-and-verify resolution**: `resolve(didUrl, { verify: true })` (and `getResolver({ verify: true })`) fetches the DID's complete microledger from the VDR's `did-documents.jsonl` endpoint and cryptographically verifies it — self-hashes, Ed25519 proofs against `updateRules`, and chain integrity — before returning the requested document. Verification failures surface as `error: "invalidDidDocument"`.
  - **`versionTime` resolution**: `?versionTime=<RFC 3339>` DID URL queries select the document that was valid at that instant from the version history.
  - **Controller operations**: `createDidDocument` / `updateDidDocument` build self-hashed, proof-signed documents exactly as the reference implementation does (placeholders → proofs → self-hash), with `ed25519KeyPair`, `keyRule` / `hashedKeyRule` (pre-rotation) helpers and per-key purposes. `registerDid` / `submitDidUpdate` POST/PUT to the VDR. New exports also include `signProof`, `signDetachedJws`, `fetchMicroledger`, `selectFromMicroledger`, `selfHashDocument`, `formatMbPubKey`, `hashWithFunction`.

## 0.2.0

### Minor Changes

- 5eed4ab: Built-in cryptographic verification for did:webplus microledgers, validated against the Rust reference implementation's test vectors.

  - **@zkred/did-webplus**: `validateMicroledger` now verifies cryptography by default — document self-hashes are recomputed via the selfhash self-addressing scheme (JCS canonicalization, multibase multihash, BLAKE3 + SHA-2 family), and detached Ed25519 JWS proofs (RFC 7797 `b64:false`) are verified against the predecessor's `updateRules` (`key`, `hashedKey`, `any`, `all`, weighted `atLeast`/`of`). New exports: `WebplusCryptoVerifier`, `verifyDocumentSelfHash`, `proofSigningInput`, `validProofKeys`, `evaluateUpdateRules`, `verifyDetachedJws`, `parseMbHash`, `parseMbPubKey`, `placeholderMbHash`, `hashAsMbHash`. Pass `verifier: null` for structural-only validation.
  - **@zkred/did-core**: new dependency-free primitives — `canonicalize` (JCS, RFC 8785), `base64urlEncode`/`base64urlDecode`, `varintEncode`/`varintDecode`, `utf8Encode`, `concatBytes`.

### Patch Changes

- Updated dependencies [5eed4ab]
  - @zkred/did-core@0.2.0
