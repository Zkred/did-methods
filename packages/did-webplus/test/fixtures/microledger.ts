import type { WebplusDidDocument } from "../../src/types.js";

/**
 * Example microledger from the did:webplus reference implementation:
 * https://github.com/LedgerDomain/did-webplus/blob/main/doc/example-did-microledger.md
 */
export const DID = "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ";

export const rootDoc: WebplusDidDocument = {
  id: DID,
  selfHash: "uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ",
  updateRules: {
    hashedKey: "uHiCMmFumKCTx6yxWPtoRM_VZj4DvdcHs2KEBK941pr8SXQ",
  },
  validFrom: "2025-11-19T01:43:26.979Z",
  versionId: 0,
  verificationMethod: [
    {
      id: `${DID}?selfHash=uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ&versionId=0#0`,
      type: "JsonWebKey2020",
      controller: DID,
      publicKeyJwk: {
        kid: `${DID}?selfHash=uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ&versionId=0#0`,
        kty: "OKP",
        crv: "Ed25519",
        x: "iR2bJQmYXszbiuW1yfeRmLtBkGsEczp99ZfEuQSPxwM",
      },
    },
  ],
  authentication: ["#0"],
  assertionMethod: ["#0"],
  keyAgreement: ["#0"],
  capabilityInvocation: ["#0"],
  capabilityDelegation: ["#0"],
};

export const secondDoc: WebplusDidDocument = {
  id: DID,
  selfHash: "uHiCH05FmexvfpT8lxesItafqipzHvm_npUt4PRRCc8scEw",
  prevDIDDocumentSelfHash: "uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ",
  updateRules: {
    key: "u7QF0zsY-DxwlvuzDsosc0ZgD5drHhvNHXVkxwDDCMZHSIQ",
  },
  proofs: [
    "eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoidTdRRzJPMlZtMjJlMWc0djZWUnhqWTlRZ205WHFKQUtmX2IzY0g2T2M0UjBiaHciLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..gjcKygeSmc9XC8h6Eosu1zPkjVF9_vPTI5Dm0PbNT7UZU4GvfvN1NsVEBWcXTEcCL22CW1ID5rb3SmjtsJnxBg",
  ],
  validFrom: "2025-11-19T01:43:26.992Z",
  versionId: 1,
  verificationMethod: [
    {
      id: `${DID}?selfHash=uHiCH05FmexvfpT8lxesItafqipzHvm_npUt4PRRCc8scEw&versionId=1#0`,
      type: "JsonWebKey2020",
      controller: DID,
      publicKeyJwk: {
        kid: `${DID}?selfHash=uHiCH05FmexvfpT8lxesItafqipzHvm_npUt4PRRCc8scEw&versionId=1#0`,
        kty: "OKP",
        crv: "Ed25519",
        x: "I87S--BfzauBtdJ4FkYLj9-bOF8gwj6iOMIx_lE-vhM",
      },
    },
    {
      id: `${DID}?selfHash=uHiCH05FmexvfpT8lxesItafqipzHvm_npUt4PRRCc8scEw&versionId=1#1`,
      type: "JsonWebKey2020",
      controller: DID,
      publicKeyJwk: {
        kid: `${DID}?selfHash=uHiCH05FmexvfpT8lxesItafqipzHvm_npUt4PRRCc8scEw&versionId=1#1`,
        kty: "OKP",
        crv: "Ed25519",
        x: "iR2bJQmYXszbiuW1yfeRmLtBkGsEczp99ZfEuQSPxwM",
      },
    },
  ],
  authentication: ["#0"],
  assertionMethod: ["#1"],
  keyAgreement: ["#1"],
  capabilityInvocation: ["#0"],
  capabilityDelegation: ["#1"],
};