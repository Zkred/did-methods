---
"@zkred/did-webplus": patch
---

Security fix: when a required VDR fetch fails, resolution now fails with
`VDR_FETCH_FAILED` instead of answering from the local store. 1.0.0 fell back
to stored data, including serving the stored tip for a plain DID, which let
anyone able to block the resolver's path to the VDR get a rotated-out key
accepted or hide a deactivation behind a successful result. A fetch only
happens when the store cannot answer on its own (a plain DID, or
latest/next/deactivated metadata that needs fresh data), so there is no safe
local answer to fall back to.

Also aligned with the official resolution-scenario catalog, which the test
suite now runs in full (19/19 passing):

- The two did:webplus-specific error types are
  `https://ledgerdomain.github.io/did-webplus-spec/#LOCAL_RESOLUTION_NOT_POSSIBLE`
  and `…/did-webplus-spec/#VDR_FETCH_FAILED` (1.0.0 omitted the `/` before `#`).
- A query naming both `selfHash` and `versionId` is an `INVALID_DID_URL`
  conflict, with no fetch, as soon as either one matches a stored document
  whose other value disagrees. 1.0.0 required both to match stored documents.
