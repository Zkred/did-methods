# @zkred/did-cid

[`did:cid`](https://github.com/archetech/archon) resolution as a
[`did-resolver`](https://www.npmjs.com/package/did-resolver) plugin.

did:cid is content-addressed (the identifier is a CIDv1) and DIF Recommended.
Its reference implementation is the [Archon](https://github.com/archetech/archon)
platform, whose **gatekeeper** node performs resolution, update tracking, and
verification, exposing a standards-conformant endpoint at
`GET /1.0/identifiers/{did}`.

This package is deliberately a **thin client**: you point it at a gatekeeper
you trust (typically your own node) and it maps DID URLs onto that endpoint,
passing the gatekeeper's W3C resolution result through unchanged. Choosing the
gatekeeper is the method's central trust decision, so `gatekeeperUrl` is
required and has no default.

## Install

```sh
npm install @zkred/did-cid did-resolver
```

## Usage

```ts
import { Resolver } from "did-resolver";
import { getResolver } from "@zkred/did-cid";

const resolver = new Resolver(getResolver({ gatekeeperUrl: "https://my-gatekeeper.example" }));

const result = await resolver.resolve(
  "did:cid:bafkreiawdmk6fmqc5p237vffyctazpzdgvgqfdj2i3hx2idtodxkwhyj5m",
);
```

Archetech operates a public node at `https://archon.technology` that works as a
`gatekeeperUrl` for evaluation (remember: whichever gatekeeper you configure is
the party you trust for resolution; run your own node for production use).

DID URL query parameters `versionTime` and `versionSequence` (and the standard
`service` / `relativeRef`) are passed through to the gatekeeper; fragments are
left for client-side processing per DID Core.

### All three DIF Recommended methods in one resolver

```ts
import { Resolver } from "did-resolver";
import { getResolver as webplus } from "@zkred/did-webplus";
import { getResolver as webvh } from "@zkred/did-webvh";
import { getResolver as cid } from "@zkred/did-cid";

const resolver = new Resolver({
  ...webplus(),
  ...webvh(),
  ...cid({ gatekeeperUrl: "https://my-gatekeeper.example" }),
});
```

### Dereferencing

did:cid defines two dereferenceable resources, `/data` and `/registration`:

```ts
import { dereference } from "@zkred/did-cid";

const data = await dereference(`${did}/data`, { gatekeeperUrl });
```

## Security

This package makes outbound HTTPS requests by design: every resolution is a
request to the gatekeeper you configured, and no request is made except in
response to an explicit `resolve` / `dereference` call. A `fetchImpl` option
is accepted everywhere for instrumented or policy-restricted fetch. Trust
model: the gatekeeper verifies did:cid's content-addressed history; this
client trusts the gatekeeper you chose, analogous to a did:webplus Thin DID
Resolver trusting its VDG.

## License

Apache-2.0
