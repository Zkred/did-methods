# did-methods

[![CI](https://github.com/Zkred/did-methods/actions/workflows/ci.yml/badge.svg)](https://github.com/Zkred/did-methods/actions/workflows/ci.yml)
[![did-webplus](https://img.shields.io/npm/v/%40zkred%2Fdid-webplus?label=%40zkred%2Fdid-webplus)](https://www.npmjs.com/package/@zkred/did-webplus)
[![did-webvh](https://img.shields.io/npm/v/%40zkred%2Fdid-webvh?label=%40zkred%2Fdid-webvh)](https://www.npmjs.com/package/@zkred/did-webvh)

TypeScript implementations of web-based [DID methods](https://www.w3.org/TR/did-core/),
published as small per-method packages that plug into the
[`did-resolver`](https://www.npmjs.com/package/did-resolver) ecosystem.

| Package | Method | What it is |
| --- | --- | --- |
| [`@zkred/did-webplus`](packages/did-webplus) | [`did:webplus`](https://ledgerdomain.github.io/did-webplus-spec) | First TS/JS-native implementation: parsing, verified resolution, controller operations |
| [`@zkred/did-webvh`](packages/did-webvh) | [`did:webvh`](https://identity.foundation/didwebvh/) | Thin `did-resolver` adapter over DIF's [`didwebvh-ts`](https://www.npmjs.com/package/didwebvh-ts) |
| [`@zkred/did-cid`](packages/did-cid) | [`did:cid`](https://github.com/archetech/archon) | Thin `did-resolver` client for an Archon gatekeeper |
| [`@zkred/did-core`](packages/did-core) | — | Shared DID data-model types, resolution errors, and HTTP utilities |

These provide **three of the four DIF Recommended DID methods** (did:webvh,
did:webplus, and did:cid), the three that lacked a JS-native `did-resolver`
package. The fourth, did:ethr, already has a first-party plugin
([`ethr-did-resolver`](https://www.npmjs.com/package/ethr-did-resolver)) that
composes into the same registry, so all four resolve through one `Resolver`.
New methods land as new packages in `packages/`.

## Quick start

```ts
import { Resolver } from "did-resolver";
import { getResolver as webplus } from "@zkred/did-webplus";
import { getResolver as webvh } from "@zkred/did-webvh";

const resolver = new Resolver({ ...webplus(), ...webvh() });

await resolver.resolve("did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ");
await resolver.resolve("did:webvh:QmScid...:example.com");
```

## Development

```sh
pnpm install
pnpm build
pnpm test
```

Releases are managed with [Changesets](https://github.com/changesets/changesets):
run `pnpm changeset` alongside your change; merging to `main` opens a release PR,
and merging that publishes to npm with provenance.

## Status

Early stage. `@zkred/did-webplus` implements DID parsing, VDR resolution, and
structural microledger validation, with cryptographic verification pluggable via the
`CryptoVerifier` interface — see its [roadmap](packages/did-webplus/README.md#status--roadmap).

## License

Apache-2.0