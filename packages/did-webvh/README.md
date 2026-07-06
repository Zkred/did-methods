# @zkred/did-webvh

[`did:webvh`](https://identity.foundation/didwebvh/) resolution as a
[`did-resolver`](https://www.npmjs.com/package/did-resolver) plugin.

This is intentionally a **thin adapter** over
[`didwebvh-ts`](https://www.npmjs.com/package/didwebvh-ts) — the implementation maintained
by the Decentralized Identity Foundation — rather than a reimplementation. It reshapes
`didwebvh-ts` output into the W3C DID resolution result structure and plugs into the
`did-resolver` registry, so did:webvh composes cleanly with other methods (like its sibling
[`@zkred/did-webplus`](https://www.npmjs.com/package/@zkred/did-webplus)).

## Install

```sh
npm install @zkred/did-webvh did-resolver
```

## Usage

```ts
import { Resolver } from "did-resolver";
import { getResolver } from "@zkred/did-webvh";
import { getResolver as webplus } from "@zkred/did-webplus";

const resolver = new Resolver({ ...getResolver(), ...webplus() });

const result = await resolver.resolve("did:webvh:QmScid...:example.com");
```

DID URL query parameters `versionId`, `versionNumber`, and `versionTime` are passed
through to the underlying resolver.

The full `didwebvh-ts` controller API (`createDID`, `updateDID`, `deactivateDID`,
`resolveDIDFromLog`) is re-exported for convenience.

## License

Apache-2.0