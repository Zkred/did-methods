---
"@zkred/did-webplus": minor
---

Trust-posture changes from cross-implementation review.

- **`resolve()` verifies by default.** Previously the default fetched a single document and trusted the VDR (did:web posture); verification required opting in. Now the full microledger is fetched and cryptographically verified unless `verify: false` is passed explicitly for thin-resolver mode, which marks results `didDocumentMetadata.verified: false`. Verified resolution costs the same number of HTTP requests, so the safe posture is now the default. Behavior change for callers that relied on the old default; add `verify: false` to keep it.
- **Localhost defaults to http.** `resolutionUrl`, `microledgerUrl`, and the VDG URL builders now default to `http` for `localhost`, `*.localhost`, `127.0.0.1`, and `::1` (as the spec permits) instead of requiring `scheme: "http"`. Explicit `scheme` always wins. New exports: `isLocalhostHost`, `schemeForHost`.
