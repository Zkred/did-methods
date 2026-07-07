---
"@zkred/did-webplus": minor
---

VDG resolution and multi-curve (secp256k1 / P-256) support.

- **Verifiable Data Gateway**: the resolver accepts a `vdg` option (hostname or base URL); single-document resolution goes through `/webplus/v1/resolve/{didQuery}` and `verify: true` fetches full microledgers through `/webplus/v1/fetch/{did}/did-documents.jsonl`. New exports: `vdgResolutionUrl`, `vdgMicroledgerUrl`.
- **secp256k1 + P-256**: key pairs (`secp256k1KeyPair`, `p256KeyPair`), EC `publicKeyJwk` entries (kty EC with x/y), `ES256K`/`ES256` JWS proofs, and multicodec compressed-point public keys — usable in verification methods, proof signing/verification, and `keyRule`/`hashedKeyRule` (which now take an optional curve). `Ed25519KeyPair` is renamed `SigningKeyPair` (old name kept as a deprecated alias), and `ed25519PublicKeyJwkX` is replaced by `publicKeyJwkParams`.
