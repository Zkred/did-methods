---
"@zkred/did-webplus": patch
---

Fix a self-hash verification bypass on non-root DID documents: a verification
method's `id` or `publicKeyJwk.kid` could carry a self-hash query value that
disagreed with the document's own `selfHash` and still pass verification,
because the placeholder substitution used to recompute the hash overwrote
that exact field before comparing, erasing the mismatch. `collectSelfHashSlots`
now checks every verification method's self-hash slot against `doc.selfHash`
for non-root documents too, matching the slots `withSelfHashSlotsSetTo`
actually overwrites. Root documents were unaffected. Found via new official
conformance vectors (non-root-self-hash-inconsistent-slots,
non-root-vm-id-self-hash-mismatch, non-root-vm-id-self-hash-mismatch-one-of-many,
non-root-vm-kid-self-hash-mismatch); the full 299-vector suite now passes.
