---
"@zkred/did-webplus": patch
---

Range-based GETs now start immediately after the final `}` of the last archived document, per the spec's newly added normative language for the Full DID Resolver. This makes incremental resolution work against VDRs that store `did-documents.jsonl` without a trailing newline. Archived `raw` values are stored without a trailing newline going forward; values persisted by 0.8.0 are normalized on read.
