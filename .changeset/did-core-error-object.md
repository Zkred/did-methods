---
"@zkred/did-core": minor
---

Widen `DidResolutionMetadata.error` to `string | object`. Most DID methods
use the DID Core convention of a short ASCII error code (unaffected); a
method whose own spec mandates a structured error — did:webplus now returns
an RFC 9457 Problem Details object — can use an object instead. Purely
additive: any existing string assignment still type-checks.
