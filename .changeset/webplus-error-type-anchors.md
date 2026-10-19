---
"@zkred/did-webplus": patch
---

The two did:webplus-specific error types are now
`https://ledgerdomain.github.io/did-webplus-spec#LOCAL_RESOLUTION_NOT_POSSIBLE`
and `…/did-webplus-spec#VDR_FETCH_FAILED`, with no `/` before `#`. The spec
intended this form all along. The `/` that 1.0.1 added came from a browser
rewriting the URL, and the spec, the reference implementations and the
resolution-scenario catalog have since dropped it. Code that compares against
`WEBPLUS_ERROR_TYPE` needs no change.
