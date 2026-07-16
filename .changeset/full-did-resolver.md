---
"@zkred/did-webplus": minor
---

Implement a spec-conformant Full DID Resolver (persistent, incremental, duplicity-detecting), adopt the spec's resolver terminology, and remove the legacy URL mapping. Follows maintainer review in LedgerDomain/did-webplus#36.

- **Persistent Full resolver (default).** `resolve()` now stores verified microledger portions (`MicroledgerStore`; in-memory default via `defaultMicroledgerStore`, `store: null` to disable, or bring your own). Re-resolution issues a range-based HTTP GET and verifies only new documents; duplicity (forks, history rewrites, rollbacks against the verified store) fails with `invalidDidDocument`; `versionId`/`selfHash` (and settled `versionTime`) queries are answered offline from the store. New exports: `MicroledgerStore`, `StoredMicroledger`, `InMemoryMicroledgerStore`, `defaultMicroledgerStore`, `validateMicroledgerExtension`.
- **Modes replace `verify`.** `mode: "full" | "thin" | "unverified"` (default `"full"`). Thin mode requires a trusted VDG per the spec and errors without one. `"unverified"` is explicitly development/testing-only (JCS wire checks, no cryptography). The `verify` boolean is removed.
- **Legacy URL mapping removed.** `resolutionUrl` and the `did.json` / `did/versionId/<n>.json` / `did/selfHash/<hash>.json` mapping are gone; the spec defines exactly one resolution URL per DID (`…/did-documents.jsonl`). Queries select from the fetched microledger.
- **Localhost rule tightened to the spec.** Only exactly `localhost` defaults to `http` (the spec's DID-to-URL mapping step 5); `127.0.0.1` etc. require an explicit `scheme`.