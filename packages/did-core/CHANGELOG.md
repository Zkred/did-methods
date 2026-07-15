# @zkred/did-core

## 0.3.0

### Minor Changes

- a2dbf05: Enforce the spec's JCS wire-format rule (fixes a lenient-verifier conformance bug found by cross-implementation testing).

  The did:webplus spec requires each serialized DID document to be byte-for-byte equal to its own JCS (RFC 8785) serialization. Previously `fetchMicroledger` parsed `did-documents.jsonl` lines and discarded the raw bytes, so key-order-permuted or whitespace-padded lines validated successfully. Now:

  - `fetchMicroledger` (and therefore `resolve` with `verify: true`) rejects non-canonical lines with `error: "invalidDidDocument"` and a `not-jcs-canonical` message naming the offending line.
  - New `validateMicroledgerBytes(jsonl, options)` validates a microledger from raw bytes, enforcing the wire rule before the structural/cryptographic checks; `parseJcsCanonicalLines` is exported for lower-level use. The parsed-object `validateMicroledger` is unchanged (raw bytes are unrecoverable after parsing; use the bytes API when you have the wire form).
  - `@zkred/did-core` adds `invalidDidDocument` to `ResolutionErrorCode`.

## 0.2.0

### Minor Changes

- 5eed4ab: Built-in cryptographic verification for did:webplus microledgers, validated against the Rust reference implementation's test vectors.

  - **@zkred/did-webplus**: `validateMicroledger` now verifies cryptography by default — document self-hashes are recomputed via the selfhash self-addressing scheme (JCS canonicalization, multibase multihash, BLAKE3 + SHA-2 family), and detached Ed25519 JWS proofs (RFC 7797 `b64:false`) are verified against the predecessor's `updateRules` (`key`, `hashedKey`, `any`, `all`, weighted `atLeast`/`of`). New exports: `WebplusCryptoVerifier`, `verifyDocumentSelfHash`, `proofSigningInput`, `validProofKeys`, `evaluateUpdateRules`, `verifyDetachedJws`, `parseMbHash`, `parseMbPubKey`, `placeholderMbHash`, `hashAsMbHash`. Pass `verifier: null` for structural-only validation.
  - **@zkred/did-core**: new dependency-free primitives — `canonicalize` (JCS, RFC 8785), `base64urlEncode`/`base64urlDecode`, `varintEncode`/`varintDecode`, `utf8Encode`, `concatBytes`.
