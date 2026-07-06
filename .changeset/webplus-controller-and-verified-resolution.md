---
"@zkred/did-webplus": minor
---

Complete the core did:webplus feature set: verified resolution, versionTime, and controller operations.

- **Fetch-and-verify resolution**: `resolve(didUrl, { verify: true })` (and `getResolver({ verify: true })`) fetches the DID's complete microledger from the VDR's `did-documents.jsonl` endpoint and cryptographically verifies it — self-hashes, Ed25519 proofs against `updateRules`, and chain integrity — before returning the requested document. Verification failures surface as `error: "invalidDidDocument"`.
- **`versionTime` resolution**: `?versionTime=<RFC 3339>` DID URL queries select the document that was valid at that instant from the version history.
- **Controller operations**: `createDidDocument` / `updateDidDocument` build self-hashed, proof-signed documents exactly as the reference implementation does (placeholders → proofs → self-hash), with `ed25519KeyPair`, `keyRule` / `hashedKeyRule` (pre-rotation) helpers and per-key purposes. `registerDid` / `submitDidUpdate` POST/PUT to the VDR. New exports also include `signProof`, `signDetachedJws`, `fetchMicroledger`, `selectFromMicroledger`, `selfHashDocument`, `formatMbPubKey`, `hashWithFunction`.