# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately via
[GitHub private vulnerability reporting](https://github.com/Zkred/did-methods/security/advisories/new).
Do not open a public issue for a security finding. You can expect an initial
response within 72 hours.

## Supported versions

The latest published version of each package receives security fixes:

| Package | npm |
| --- | --- |
| `@zkred/did-webplus` | [![npm](https://img.shields.io/npm/v/%40zkred%2Fdid-webplus)](https://www.npmjs.com/package/@zkred/did-webplus) |
| `@zkred/did-webvh` | [![npm](https://img.shields.io/npm/v/%40zkred%2Fdid-webvh)](https://www.npmjs.com/package/@zkred/did-webvh) |
| `@zkred/did-cid` | [![npm](https://img.shields.io/npm/v/%40zkred%2Fdid-cid)](https://www.npmjs.com/package/@zkred/did-cid) |
| `@zkred/did-core` | [![npm](https://img.shields.io/npm/v/%40zkred%2Fdid-core)](https://www.npmjs.com/package/@zkred/did-core) |

## Scope

Reports about these packages' own code are always in scope. Note the layering,
so findings reach the right upstream too:

- `@zkred/did-webplus` implements the did:webplus method in TypeScript.
  Findings against the method specification itself belong upstream at
  [LedgerDomain/did-webplus](https://github.com/LedgerDomain/did-webplus);
  we are happy to coordinate.
- `@zkred/did-webvh` is a thin adapter over DIF's
  [didwebvh-ts](https://github.com/decentralized-identity/didwebvh-ts), which
  contains the actual verification logic. Findings in that logic belong
  upstream; findings in the adapter (result mapping, error handling) belong
  here. When upstream ships a security fix we release an aligned version
  promptly.
- `@zkred/did-cid` is a thin client for an Archon gatekeeper. The gatekeeper
  performs verification; gatekeeper-side findings belong at
  [archetech/archon](https://github.com/archetech/archon).

Supply-chain posture: all packages publish to npm via OIDC trusted publishing
with provenance from GitHub Actions in this repository; no npm tokens exist.
