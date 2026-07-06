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

### Validate a microledger

```ts
import { validateMicroledger } from "@zkred/did-webplus";

const { valid, errors } = await validateMicroledger(didDocuments, {
  expectedDid: "did:webplus:example.com:uHiAg...",
});
```

Structural validation (hash chaining, version ordering, timestamp monotonicity,
proof presence) is built in. Cryptographic verification — self-hash computation and
JWS proof verification against `updateRules` — is pluggable today via the
`CryptoVerifier` interface.

## Status & roadmap

Early release; the `did:webplus` spec itself is still marked *proposed*. Roadmap:

- [ ] Built-in self-hash verification (selfhash self-addressing scheme)
- [ ] Built-in JWS proof verification against `updateRules` (key / hashedKey / threshold rules)
- [ ] Full-microledger fetch-and-verify during resolution
- [ ] `versionTime` resolution
- [ ] DID creation and update (controller operations) against a VDR
- [ ] Conformance testing against the Rust reference implementation's test vectors

Contributions welcome: https://github.com/Zkred/did-methods

## License

Apache-2.0