# did-methods

TypeScript implementations of web-based [DID methods](https://www.w3.org/TR/did-core/),
published as small per-method packages that plug into the
[`did-resolver`](https://www.npmjs.com/package/did-resolver) ecosystem.

| Package | Method | What it is |
| --- | --- | --- |
| [`@zkred/did-webplus`](packages/did-webplus) | [`did:webplus`](https://ledgerdomain.github.io/did-webplus-spec) | First JavaScript implementation — DID parsing, resolution, and microledger validation |
| [`@zkred/did-webvh`](packages/did-webvh) | [`did:webvh`](https://identity.foundation/didwebvh/) | Thin `did-resolver` adapter over DIF's [`didwebvh-ts`](https://www.npmjs.com/package/didwebvh-ts) |
| [`@zkred/did-core`](packages/did-core) | — | Shared DID data-model types, resolution errors, and HTTP utilities |

New methods land as new packages in `packages/` — the monorepo is designed to grow
(did:webs is a likely next candidate).

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