---
"@zkred/did-webplus": minor
---

Full conformance with the official did:webplus test vectors: all 259 published vectors pass (https://ledgerdomain.github.io/did-webplus-spec/test-vector), and CI now runs the complete suite on every commit.

- **All six key types**: Ed448 (`Ed448`), P-384 (`ES384`), and P-521 (`ES512`) join Ed25519, secp256k1, and P-256 for verification methods, proofs, and update rules; key pairs via `ed448KeyPair` / `p384KeyPair` / `p521KeyPair`.
- **All three multibases**: base58btc (`z`) and base32lower (`b`) MBHash/MBPubKey values are now supported alongside base64url (`u`); derived values (placeholders, computed hashes) preserve the base of the value they derive from, so mixed-base histories verify.
- **Strictness fixes (behavioral changes)**: any malformed or cryptographically invalid proof now rejects the document, even on roots and even when other proofs satisfy the update rules (`validProofKeys` throws instead of skipping); `validFrom` is strictly validated (uppercase T/Z, at most millisecond precision, real calendar dates, not pre-epoch); JSONL is strict (CRLF endings and blank lines are malformed; an empty file is well-formed with zero documents); `updateRules` is a required field.
