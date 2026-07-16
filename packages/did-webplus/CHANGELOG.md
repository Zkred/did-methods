# @zkred/did-webplus

## 0.8.0

### Minor Changes

- 046077d: Implement a spec-conformant Full DID Resolver (persistent, incremental, duplicity-detecting), adopt the spec's resolver terminology, and remove the legacy URL mapping. Follows maintainer review in LedgerDomain/did-webplus#36.

  - **Persistent Full resolver (default).** `resolve()` now stores verified microledger portions (`MicroledgerStore`; in-memory default via `defaultMicroledgerStore`, `store: null` to disable, or bring your own). Re-resolution issues a range-based HTTP GET and verifies only new documents; duplicity (forks, history rewrites, rollbacks against the verified store) fails with `invalidDidDocument`; `versionId`/`selfHash` (and settled `versionTime`) queries are answered offline from the store. New exports: `MicroledgerStore`, `StoredMicroledger`, `InMemoryMicroledgerStore`, `defaultMicroledgerStore`, `validateMicroledgerExtension`.
  - **Modes replace `verify`.** `mode: "full" | "thin" | "unverified"` (default `"full"`). Thin mode requires a trusted VDG per the spec and errors without one. `"unverified"` is explicitly development/testing-only (JCS wire checks, no cryptography). The `verify` boolean is removed.
  - **Legacy URL mapping removed.** `resolutionUrl` and the `did.json` / `did/versionId/<n>.json` / `did/selfHash/<hash>.json` mapping are gone; the spec defines exactly one resolution URL per DID (`…/did-documents.jsonl`). Queries select from the fetched microledger.
  - **Localhost rule tightened to the spec.** Only exactly `localhost` defaults to `http` (the spec's DID-to-URL mapping step 5); `127.0.0.1` etc. require an explicit `scheme`.

## 0.7.0

### Minor Changes

- cd13ce8: Trust-posture changes from cross-implementation review.

  - **`resolve()` verifies by default.** Previously the default fetched a single document and trusted the VDR (did:web posture); verification required opting in. Now the full microledger is fetched and cryptographically verified unless `verify: false` is passed explicitly for thin-resolver mode, which marks results `didDocumentMetadata.verified: false`. Verified resolution costs the same number of HTTP requests, so the safe posture is now the default. Behavior change for callers that relied on the old default; add `verify: false` to keep it.
  - **Localhost defaults to http.** `resolutionUrl`, `microledgerUrl`, and the VDG URL builders now default to `http` for `localhost`, `*.localhost`, `127.0.0.1`, and `::1` (as the spec permits) instead of requiring `scheme: "http"`. Explicit `scheme` always wins. New exports: `isLocalhostHost`, `schemeForHost`.

## 0.6.0

### Minor Changes

- a2dbf05: Enforce the spec's JCS wire-format rule (fixes a lenient-verifier conformance bug found by cross-implementation testing).

  The did:webplus spec requires each serialized DID document to be byte-for-byte equal to its own JCS (RFC 8785) serialization. Previously `fetchMicroledger` parsed `did-documents.jsonl` lines and discarded the raw bytes, so key-order-permuted or whitespace-padded lines validated successfully. Now:

  - `fetchMicroledger` (and therefore `resolve` with `verify: true`) rejects non-canonical lines with `error: "invalidDidDocument"` and a `not-jcs-canonical` message naming the offending line.
  - New `validateMicroledgerBytes(jsonl, options)` validates a microledger from raw bytes, enforcing the wire rule before the structural/cryptographic checks; `parseJcsCanonicalLines` is exported for lower-level use. The parsed-object `validateMicroledger` is unchanged (raw bytes are unrecoverable after parsing; use the bytes API when you have the wire form).
  - `@zkred/did-core` adds `invalidDidDocument` to `ResolutionErrorCode`.

### Patch Changes

- Updated dependencies [a2dbf05]
  - @zkred/did-core@0.3.0

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
