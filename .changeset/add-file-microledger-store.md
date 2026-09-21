---
"@zkred/did-webplus": minor
---

Add `FileMicroledgerStore`, a filesystem-backed `MicroledgerStore` for
Node.js, importable from the `@zkred/did-webplus/node` subpath so it never
reaches a browser bundle of the main entry point. A Full DID Resolver's
range-GET-and-verify-only-new-documents behavior requires the verified
prefix to survive between resolutions; `InMemoryMicroledgerStore` only does
that within one running process, which makes it of limited use for a CLI or
a server that restarts. `FileMicroledgerStore` persists one JSON file per DID
under a given directory (named by a hash of the DID, since DIDs contain `:`,
illegal in Windows filenames) and writes via a temp-file-then-rename so a
process killed mid-write can't leave a corrupt file behind.
