# @zkred/did-core

## 0.2.0

### Minor Changes

- 5eed4ab: Built-in cryptographic verification for did:webplus microledgers, validated against the Rust reference implementation's test vectors.

  - **@zkred/did-webplus**: `validateMicroledger` now verifies cryptography by default — document self-hashes are recomputed via the selfhash self-addressing scheme (JCS canonicalization, multibase multihash, BLAKE3 + SHA-2 family), and detached Ed25519 JWS proofs (RFC 7797 `b64:false`) are verified against the predecessor's `updateRules` (`key`, `hashedKey`, `any`, `all`, weighted `atLeast`/`of`). New exports: `WebplusCryptoVerifier`, `verifyDocumentSelfHash`, `proofSigningInput`, `validProofKeys`, `evaluateUpdateRules`, `verifyDetachedJws`, `parseMbHash`, `parseMbPubKey`, `placeholderMbHash`, `hashAsMbHash`. Pass `verifier: null` for structural-only validation.
  - **@zkred/did-core**: new dependency-free primitives — `canonicalize` (JCS, RFC 8785), `base64urlEncode`/`base64urlDecode`, `varintEncode`/`varintDecode`, `utf8Encode`, `concatBytes`.
