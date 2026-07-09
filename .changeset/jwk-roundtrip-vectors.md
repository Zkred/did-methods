---
"@zkred/did-webplus": minor
---

Add `publicKeyBytesFromJwk` (recover raw key bytes / compressed points from `publicKeyJwk` fields) and conformance tests against the reference implementation's JWK round-trip vectors (30 vectors across Ed25519, secp256k1, and P-256; both directions pass exactly).
