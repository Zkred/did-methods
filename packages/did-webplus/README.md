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

> **Upgrading from 0.x:** 1.0.0 is a breaking release that brings `resolve()`
> in line with the spec's new DID Resolution Options and metadata-locality
> rules. `didDocumentMetadata` no longer includes `mode`, `verified`,
> `selfHash`, or `cached`, and no longer unconditionally includes `created`;
> see [DID Resolution Options](#did-resolution-options) for what replaced
> them. `didResolutionMetadata.error` for a resolution-process failure is now
> an RFC 9457 object instead of a short string; see [Errors](#errors).

## Usage

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

The default is a **Full DID Resolver** in the spec's terminology: the DID's
microledger is fetched from the spec's single resolution URL
(`…/did-documents.jsonl`), cryptographically verified — self-hashes, proofs
against `updateRules`, chain integrity, and the JCS wire-format rule — and the
verified portion is **persisted**. Repeated resolution then issues a
range-based HTTP GET and verifies only new documents, giving near-constant
cost per re-resolution, plus:

- **duplicity detection**: any served history that contradicts the verified
  store (forks, rewrites, rollbacks) fails with `invalidDidDocument`
  (see [Errors](#errors) below for the exact shape);
- **offline historical resolution**: `?versionId=` / `?selfHash=` (and
  settled `?versionTime=`) queries answer from the store with no network
  request at all, per the spec's metadata-locality rules.

### DID Resolution Options

Five method-specific options control what `didDocumentMetadata` includes and
whether a resolution is allowed to touch the network, all defaulting to
`false`:

```ts
resolve(did, { requestCreate: true });      // adds created / createdMilliseconds
resolve(did, { requestNext: true });        // adds nextUpdate* / nextVersionId, if a successor is known
resolve(did, { requestLatest: true });      // adds latestUpdate* / latestVersionId
resolve(did, { requestDeactivated: true }); // adds deactivated: false (deactivated: true is always reported)
resolve(did, { localResolutionOnly: true }); // zero network requests; fails if not locally satisfiable
```

Each is honored only by the (default) Full DID Resolver mode, since locality
is defined in terms of its persisted store; a plain DID request still always
triggers a fetch unless the locally-known tip is deactivated (in which case
it's provably the whole history). Only fields relevant to the resolved
document and the options actually requested appear in `didDocumentMetadata`;
nothing is populated speculatively.

### Errors

`didResolutionMetadata.error` for a resolution-process failure (not found,
conflicting `selfHash`/`versionId`, `localResolutionOnly` with insufficient
local data, the VDR unreachable, failed verification) is an
[RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) Problem Details object —
`{ type, title, detail }` — matching the spec's reference implementations,
rather than the short string code most DID methods use:

```ts
const result = await resolver.resolve("did:webplus:example.com:…?versionId=999");
// result.didResolutionMetadata.error ===
//   { type: "https://www.w3.org/ns/did#NOT_FOUND", title: "Not Found", detail: "..." }
```

A malformed DID string (a syntax error, before resolution begins) still
carries the standard `@zkred/did-core` short code (e.g. `"invalidDid"`).

Persistence defaults to a shared in-memory store, which only helps within one
running process. For durability across process restarts — a CLI invoked
fresh each run, a server that redeploys — use the bundled filesystem store
(Node.js only, so it's a separate subpath and never pulled into a browser
bundle of the main entry point):

```ts
import { FileMicroledgerStore } from "@zkred/did-webplus/node";

resolve(did, { store: new FileMicroledgerStore("./did-store") });
```

Or supply any `MicroledgerStore` (`get`/`put`) of your own — a database, an
IndexedDB wrapper for the browser — or disable persistence entirely:

```ts
resolve(did, { store: myDurableStore });
resolve(did, { store: null }); // full fetch + verify on every resolution
```

Two other modes exist via `mode`:

- `mode: "thin"` — a **Thin DID Resolver** per the spec: delegates fetching,
  verification, and archiving to a trusted VDG (the `vdg` option is
  required); one request per resolution. Fetches only the resolved document,
  so `requestCreate`/`requestNext`/`requestLatest`/`localResolutionOnly`
  aren't honored (they need the rest of the history).
- `mode: "unverified"` — development/testing only. Enforces the JCS wire
  format but performs no cryptographic verification and trusts the host.
  Non-conformant; never use in production.

DID URL query parameters are supported: `?versionId=2`, `?selfHash=uHiC...`,
and `?versionTime=2026-01-01T00:00:00Z`. Queries select documents from the
verified microledger; they do not map to separate URLs.

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

// and, when the DID's life is over:
const tombstone = deactivateDidDocument(next, { signers: [nextKey] });
await submitDidUpdate(tombstone); // updateRules {} makes this permanent
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
  multihash; BLAKE3, SHA-2, and SHA-3 families), including all self-hash slots in the
  `id`, verification method ids/kids, and controllers.
- **Proof verification** — each update's detached Ed25519 JWS proofs
  (RFC 7797, `b64: false`) are verified and checked against the predecessor
  document's `updateRules` (`key`, `hashedKey`, `any`, `all`, and weighted
  `atLeast`/`of` thresholds).
- Plus the structural checks: hash chaining, contiguous versionIds, timestamp
  monotonicity.
- **Wire-format rule** — when validating from raw bytes (`resolve` in full
  mode, or `validateMicroledgerBytes`), each `did-documents.jsonl`
  line must be byte-equal to its own JCS serialization, as the spec requires;
  reordered keys or stray whitespace are rejected as `not-jcs-canonical`. The
  parsed-object `validateMicroledger` cannot check this (the bytes are gone),
  so prefer the bytes API when you hold the wire form.

Both layers are tested against the Rust reference implementation's published
test vectors. Pass `verifier: null` for structural-only validation, or supply
your own `CryptoVerifier`.

Lower-level primitives are exported too: `verifyDocumentSelfHash`,
`validProofKeys`, `evaluateUpdateRules`, `verifyDetachedJws`, `proofSigningInput`.

## Status & roadmap

The `did:webplus` spec itself is still marked *proposed*. Roadmap:

- [x] Built-in self-hash verification (selfhash self-addressing scheme, BLAKE3 + SHA-2 + SHA-3)
- [x] Built-in JWS proof verification against `updateRules` (key / hashedKey / any / all / threshold rules)
- [x] Conformance testing against the Rust reference implementation's test vectors
- [x] Full-microledger fetch-and-verify during resolution (the default, Full DID Resolver mode)
- [x] `versionTime` resolution
- [x] DID creation and update (controller operations) against a VDR
- [x] Verifiable Data Gateway (VDG) support (`vdg` resolver option)
- [x] secp256k1 (ES256K) and P-256 (ES256) keys and proofs alongside Ed25519
- [x] DID Resolution Options and metadata-locality rules (`requestCreate`/`requestNext`/`requestLatest`/`requestDeactivated`/`localResolutionOnly`)

### VDG resolution

Pass `vdg` to resolve through a Verifiable Data Gateway instead of the DID's
VDR — the VDG's `/webplus/v1/resolve` endpoint serves single documents, and
`/webplus/v1/fetch/…/did-documents.jsonl` serves full microledgers for
full-mode verification:

```ts
const resolver = new Resolver(getResolver({ vdg: "vdg.example.com" }));
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

## Security

This package makes outbound HTTPS requests by design: resolving a DID fetches
its document or microledger from the DID's VDR (or a VDG), and the controller
operations POST/PUT DID documents to a VDR. Supply-chain scanners flag this as
a network access capability; it is the package's purpose, not telemetry. No
request is made except in response to an explicit `resolve` / `fetchMicroledger` /
`registerDid` / `submitDidUpdate` call, and every network entry point accepts a
`fetchImpl` option so you can inject an instrumented or policy-restricted fetch.
Cryptographic operations use the audited [noble](https://paulmillr.com/noble/)
libraries; keys you generate never leave your process.

## License

Apache-2.0