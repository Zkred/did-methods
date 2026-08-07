---
"@zkred/did-webplus": patch
---

An empty `did-documents.jsonl` now fails verification (no root DID document means nothing can be verified), tracking the `jsonl-empty-file` conformance vector's change to a negative test on 2026-08-07.
