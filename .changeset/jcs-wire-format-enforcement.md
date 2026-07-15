---
"@zkred/did-webplus": minor
"@zkred/did-core": minor
---

Enforce the spec's JCS wire-format rule (fixes a lenient-verifier conformance bug found by cross-implementation testing).

The did:webplus spec requires each serialized DID document to be byte-for-byte equal to its own JCS (RFC 8785) serialization. Previously `fetchMicroledger` parsed `did-documents.jsonl` lines and discarded the raw bytes, so key-order-permuted or whitespace-padded lines validated successfully. Now:

- `fetchMicroledger` (and therefore `resolve` with `verify: true`) rejects non-canonical lines with `error: "invalidDidDocument"` and a `not-jcs-canonical` message naming the offending line.
- New `validateMicroledgerBytes(jsonl, options)` validates a microledger from raw bytes, enforcing the wire rule before the structural/cryptographic checks; `parseJcsCanonicalLines` is exported for lower-level use. The parsed-object `validateMicroledger` is unchanged (raw bytes are unrecoverable after parsing; use the bytes API when you have the wire form).
- `@zkred/did-core` adds `invalidDidDocument` to `ResolutionErrorCode`.
