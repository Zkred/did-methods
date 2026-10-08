---
"@zkred/did-webplus": major
---

Implement the did:webplus spec's DID Resolution Options and metadata-locality
rules, closing the official interop suite's `resolution-scenario` conformance
gap (per LedgerDomain's `ZKRED_RESOLUTION_CONFORMANCE.md`). This is a breaking
release:

- `resolve()` now accepts five new options, all defaulting to `false`:
  `requestCreate`, `requestNext`, `requestLatest`, `requestDeactivated`, and
  `localResolutionOnly`. Each is honored by the default (Full DID Resolver)
  mode, which now determines — before any network request — whether the
  requested document and every requested metadata group are already
  satisfiable from the persisted store, per the spec's locality rules
  (including the deactivation short-circuits: a deactivated local tip proves
  it is the whole history, so later versions/unknown self-hashes resolve to
  `notFound` with zero fetches, and `localResolutionOnly` fails closed rather
  than falling back to the network).
- **`didDocumentMetadata` no longer includes `mode`, `verified`, `selfHash`,
  or `cached`** (none of these are part of the did:webplus
  `didDocumentMetadata` shape). `versionId` is still always present;
  `updated`/`updatedMilliseconds` appear only for a non-root document;
  `created`/`createdMilliseconds`, `nextUpdate`/`nextUpdateMilliseconds`/`nextVersionId`,
  and `latestUpdate`/`latestUpdateMilliseconds`/`latestVersionId` appear only
  when their requesting option is set (and, for `next`, only when a successor
  is actually known); `deactivated: true` is always reported for a
  deactivated document, `deactivated: false` only when `requestDeactivated`
  was set.
- **`didResolutionMetadata.error` for a resolution-process failure (not
  found, conflicting `selfHash`/`versionId`, `localResolutionOnly` without
  enough local data, an unreachable VDR, failed verification) is now an
  RFC 9457 Problem Details object** (`{ type, title, detail }`) instead of a
  short string code, matching the spec's Rust and Python reference
  implementations. A malformed DID string (a syntax error, before resolution
  begins) is unaffected and still carries the standard `@zkred/did-core`
  short code.
- `didResolutionMetadata` gains three booleans on every resolution, success
  or failure, fixed at the pre-fetch locality determination:
  `didDocumentResolvedLocally`, `didDocumentMetadataResolvedLocally`,
  `fetchedUpdatesFromVDR`.
- A VDR that errors or is unreachable now falls back to already-verified
  local data when it can answer the request (the specific document asked
  for, or — for a plain DID, which the locality rules never call "locally
  satisfiable" on their own — the local tip as a best-effort answer),
  succeeding with `fetchedUpdatesFromVDR: true` rather than failing outright.
  A query for a specific version/selfHash/versionTime not yet known locally
  gets no such fallback. Verification or duplicity failures never fall back,
  regardless: data that failed to verify is never grounds for silently
  serving older local data instead.
- `selectFromMicroledger` now rejects a query naming both `selfHash` and
  `versionId` when they identify different documents (previously `selfHash`
  silently took precedence).

`@zkred/did-core`'s `DidResolutionMetadata.error` type is widened to
`string | object` to allow this; `@zkred/did-webvh` and `@zkred/did-cid` are
unaffected and continue returning the standard short string codes.
