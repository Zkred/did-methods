# @zkred/did-webplus

TypeScript implementation of the [`did:webplus`](https://ledgerdomain.github.io/did-webplus-spec)
DID method, and the first TS/JS-native implementation (the Rust reference
implementation also provides a WASM-backed TS/JS SDK, not yet published to npm). `did:webplus` extends the
familiar web-hosted DID model with a self-addressed, hash-chained **microledger** of DID
documents, giving long-term non-repudiability, auditable key rotation, and full key usage
history.

The reference implementation (Rust) lives at
[LedgerDomain/did-webplus](https://github.com/LedgerDomain/did-webplus); this package is
validated against its published examples.

## Install

```sh
npm install @zkred/did-webplus did-resolver
```

## Usage

### Resolve with `did-resolver`

```ts
import { Resolver } from "did-resolver";
import { getResolver } from "@zkred/did-webplus";

const resolver = new Resolver(getResolver({ verify: true }));
const result = await resolver.resolve(
  "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ",
);
```

With `verify: true`, resolution fetches the DID's complete microledger
(`did-documents.jsonl`) and cryptographically verifies it — self-hashes,
Ed25519 proofs against `updateRules`, and chain integrity — before returning
the requested document. Without it, a single document is fetched as-is.

DID URL query parameters are supported: `?versionId=2`, `?selfHash=uHiC...`,
and `?versionTime=2026-01-01T00:00:00Z` (versionTime selects the document
that was valid at that instant from the version history).

### Create and update DIDs (controller operations)

```ts
import {
  createDidDocument, updateDidDocument, registerDid, submitDidUpdate,
  ed25519KeyPair, keyRule, hashedKeyRule,
} from "@zkred/did-webplus";

const signingKey = ed25519KeyPair();
const updateKey = ed25519KeyPair(); // committed by hash, revealed on first use

const root = createDidDocument({
  host: "example.com",
  keys: [{ publicKey: signingKey.publicKey }],
  updateRules: hashedKeyRule(updateKey.publicKey), // pre-rotation
});
await registerDid(root); // POST …/did-documents.jsonl on the VDR

const nextKey = ed25519KeyPair();
const next = updateDidDocument(root, {
  keys: [{ publicKey: nextKey.publicKey }],
  updateRules: keyRule(nextKey.publicKey),
  signers: [updateKey], // must satisfy root.updateRules
});
await submitDidUpdate(next); // PUT …/did-documents.jsonl
```

Documents are constructed exactly as the reference implementation does:
placeholder self-hashes, proofs attached, then self-hashed — so everything
you create passes `validateMicroledger`'s full cryptographic verification.

### Parse and inspect DIDs

```ts
import { parseDid, resolutionUrl } from "@zkred/did-webplus";

const parsed = parseDid("did:webplus:localhost%3A8085:dids:uHiAg...");
// { host: "localhost", port: 8085, path: ["dids"], rootSelfHash: "uHiAg..." }

resolutionUrl(parsed, { versionId: 2 }, { scheme: "http" });
// http://localhost:8085/dids/uHiAg.../did/versionId/2.json
```

### Validate a microledger — full cryptographic verification

```ts
import { validateMicroledger } from "@zkred/did-webplus";

const { valid, errors } = await validateMicroledger(didDocuments, {
  expectedDid: "did:webplus:example.com:uHiAg...",
});
```

Validation is cryptographic by default:

- **Self-hash verification** — every document's `selfHash` is recomputed via the
  selfhash self-addressing scheme (JCS/RFC 8785 canonicalization + multibase
  multihash; BLAKE3 and the SHA-2 family), including all self-hash slots in the
  `id`, verification method ids/kids, and controllers.
- **Proof verification** — each update's detached Ed25519 JWS proofs
  (RFC 7797, `b64: false`) are verified and checked against the predecessor
  document's `updateRules` (`key`, `hashedKey`, `any`, `all`, and weighted
  `atLeast`/`of` thresholds).
- Plus the structural checks: hash chaining, contiguous versionIds, timestamp
  monotonicity.

Both layers are tested against the Rust reference implementation's published
test vectors. Pass `verifier: null` for structural-only validation, or supply
your own `CryptoVerifier`.

Lower-level primitives are exported too: `verifyDocumentSelfHash`,
`validProofKeys`, `evaluateUpdateRules`, `verifyDetachedJws`, `proofSigningInput`.

## Status & roadmap

The `did:webplus` spec itself is still marked *proposed*. Roadmap:

- [x] Built-in self-hash verification (selfhash self-addressing scheme, BLAKE3 + SHA-2)
- [x] Built-in JWS proof verification against `updateRules` (key / hashedKey / any / all / threshold rules)
- [x] Conformance testing against the Rust reference implementation's test vectors
- [x] Full-microledger fetch-and-verify during resolution (`verify: true`)
- [x] `versionTime` resolution
- [x] DID creation and update (controller operations) against a VDR
- [x] Verifiable Data Gateway (VDG) support (`vdg` resolver option)
- [x] secp256k1 (ES256K) and P-256 (ES256) keys and proofs alongside Ed25519

### VDG resolution

Pass `vdg` to resolve through a Verifiable Data Gateway instead of the DID's
VDR — the VDG's `/webplus/v1/resolve` endpoint serves single documents, and
`/webplus/v1/fetch/…/did-documents.jsonl` serves full microledgers for
`verify: true`:

```ts
const resolver = new Resolver(getResolver({ vdg: "vdg.example.com", verify: true }));
```

### Signature curves

Ed25519 (`Ed25519`), secp256k1 (`ES256K`), and P-256 (`ES256`) are supported
for verification methods, proofs, and update rules — key pairs via
`ed25519KeyPair` / `secp256k1KeyPair` / `p256KeyPair`, with EC public keys
encoded as 33-byte compressed points per the reference implementation's
multicodec conventions. Note: Ed25519 is conformance-tested against published
reference vectors; the reference implementation has not yet published EC
vectors, so EC support is validated by internal round-trip today.

Contributions welcome: https://github.com/Zkred/did-methods

## License

Apache-2.0