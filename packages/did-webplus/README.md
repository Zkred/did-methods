# @zkred/did-webplus

TypeScript implementation of the [`did:webplus`](https://ledgerdomain.github.io/did-webplus-spec)
DID method — the first JavaScript implementation of the method. `did:webplus` extends the
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

const resolver = new Resolver(getResolver());
const result = await resolver.resolve(
  "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ",
);
```

DID URL query parameters are supported: `?versionId=2`, `?selfHash=uHiC...`.

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
- [ ] Full-microledger fetch-and-verify during resolution
- [ ] `versionTime` resolution
- [ ] DID creation and update (controller operations) against a VDR

Contributions welcome: https://github.com/Zkred/did-methods

## License

Apache-2.0