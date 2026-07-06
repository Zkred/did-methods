import type { WebplusDidDocument } from "../../src/types.js";

/**
 * Root DID documents produced by the Rust reference implementation with
 * different hash functions, including root-level proofs:
 * https://github.com/LedgerDomain/did-webplus/blob/main/doc/example-hash-function-selection.md
 */

export const blake3RootDoc: WebplusDidDocument = {
  id: "did:webplus:example.com:uHiC1437lGfqHIGxAMHE9_EfccbNddoEMWRG7x0yrPNYSFg",
  selfHash: "uHiC1437lGfqHIGxAMHE9_EfccbNddoEMWRG7x0yrPNYSFg",
  updateRules: {
    hashedKey: "uHiAxGu_wGQaRr6otJ0Nk2c-T3Yyd9YU6DkPLYzMdBP9gzg",
  },
  proofs: [
    "eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoidTdRSExFWndFVGNtQnQ2aWtKdnpSSTdwdXpJaUstQ3BDcDlGVHRJNXhPVXk0T3ciLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..h8aoDI_23ANgXvhOq-ZvK8IVOf6lIxpFFUsNO3GAd2zbY2W-qj8ZGXcz1ymwOkNpuqbwegR92URYFHVlMErmBA",
  ],
  validFrom: "2026-02-04T07:32:08.797Z",
  versionId: 0,
  verificationMethod: [
    {
      id: "did:webplus:example.com:uHiC1437lGfqHIGxAMHE9_EfccbNddoEMWRG7x0yrPNYSFg?selfHash=uHiC1437lGfqHIGxAMHE9_EfccbNddoEMWRG7x0yrPNYSFg&versionId=0#0",
      type: "JsonWebKey2020",
      controller: "did:webplus:example.com:uHiC1437lGfqHIGxAMHE9_EfccbNddoEMWRG7x0yrPNYSFg",
      publicKeyJwk: {
        kid: "did:webplus:example.com:uHiC1437lGfqHIGxAMHE9_EfccbNddoEMWRG7x0yrPNYSFg?selfHash=uHiC1437lGfqHIGxAMHE9_EfccbNddoEMWRG7x0yrPNYSFg&versionId=0#0",
        kty: "OKP",
        crv: "Ed25519",
        x: "F7wa_6IRhGtV0eRbIcVNsIUlh80LqYXIQOd2uP-9pto",
      },
    },
  ],
  authentication: ["#0"],
  assertionMethod: ["#0"],
  keyAgreement: ["#0"],
  capabilityInvocation: ["#0"],
  capabilityDelegation: ["#0"],
};

export const sha224RootDoc: WebplusDidDocument = {
  id: "did:webplus:example.com:ukyAcgxcsbm3WekLpMlt2OFiShZGqZofPmS7SdtcLNQ",
  selfHash: "ukyAcgxcsbm3WekLpMlt2OFiShZGqZofPmS7SdtcLNQ",
  updateRules: {
    hashedKey: "ukyAcTkcmEdPB51KOEN8rUL2QKF43rzvc1igUzPOATA",
  },
  proofs: [
    "eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoidTdRRkNKM3R5dlFkU3dHSms4YmVyeHk5bjA4M19xcDBxMjdnc3pHYm9pR0NMRGciLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..-IUwW6ulyvKInIZD2zWnFD-JnO7BQgmhQa8SKiXWaVlms-sulVN4dE7oRHeOLQGYGq31ZhZ2BzyO-fu1K4tGBg",
  ],
  validFrom: "2026-02-04T07:32:08.836Z",
  versionId: 0,
  verificationMethod: [
    {
      id: "did:webplus:example.com:ukyAcgxcsbm3WekLpMlt2OFiShZGqZofPmS7SdtcLNQ?selfHash=ukyAcgxcsbm3WekLpMlt2OFiShZGqZofPmS7SdtcLNQ&versionId=0#0",
      type: "JsonWebKey2020",
      controller: "did:webplus:example.com:ukyAcgxcsbm3WekLpMlt2OFiShZGqZofPmS7SdtcLNQ",
      publicKeyJwk: {
        kid: "did:webplus:example.com:ukyAcgxcsbm3WekLpMlt2OFiShZGqZofPmS7SdtcLNQ?selfHash=ukyAcgxcsbm3WekLpMlt2OFiShZGqZofPmS7SdtcLNQ&versionId=0#0",
        kty: "OKP",
        crv: "Ed25519",
        x: "05ku96ivM5psJIJg5oxEnx7ZKsXrMIIFehL8cKYw_Fk",
      },
    },
  ],
  authentication: ["#0"],
  assertionMethod: ["#0"],
  keyAgreement: ["#0"],
  capabilityInvocation: ["#0"],
  capabilityDelegation: ["#0"],
};