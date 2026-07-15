---
"@zkred/did-webplus": minor
---

Interop fixes driven by the reference implementation's interoperability test suite, plus DID deactivation.

- **SHA3 support**: sha3-224/256/384/512 MBHash values (multicodec 0x17/0x16/0x15/0x14) are now supported everywhere hashes are computed or verified, as the spec requires.
- **JCS on the wire**: `registerDid` / `submitDidUpdate` now POST/PUT the JCS (RFC 8785) serialization of DID documents, which VDRs are required to enforce.
- **`deactivateDidDocument`**: creates the spec's tombstone document (`updateRules: {}`, no verification methods), permanently ending the DID's update history.
