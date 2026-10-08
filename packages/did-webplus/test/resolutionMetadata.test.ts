import { describe, expect, it } from "vitest";
import {
  buildDidDocumentMetadata,
  computeDocLocality,
  computeMetadataLocality,
  isDeactivated,
  millisForm,
  secondsForm,
} from "../src/resolutionMetadata.js";
import type { WebplusDidDocument } from "../src/types.js";

const DID = "did:webplus:example.com:uHiAroot";

/** Minimal synthetic document: only the fields resolutionMetadata.ts reads. */
function doc(versionId: number, validFrom: string, updateRules?: Record<string, unknown>): WebplusDidDocument {
  return {
    id: DID,
    selfHash: `uHiA${versionId}`,
    ...(versionId > 0 ? { prevDIDDocumentSelfHash: `uHiA${versionId - 1}` } : {}),
    updateRules: updateRules ?? { key: "u7QFsomeKey" },
    validFrom,
    versionId,
  };
}

// Matches the four-version ledger implied by vdods' worked examples.
const v0 = doc(0, "2025-01-01T00:00:00.001Z");
const v1 = doc(1, "2025-01-01T00:00:01.633Z");
const v2 = doc(2, "2025-01-01T00:00:02.242Z");
const v3 = doc(3, "2025-01-01T00:00:03.875Z");
const docs = [v0, v1, v2, v3];
const deactivatedV3 = doc(3, "2025-01-01T00:00:03.875Z", {});
const docsDeactivated = [v0, v1, v2, deactivatedV3];

describe("secondsForm / millisForm", () => {
  it("floors to whole seconds", () => {
    expect(secondsForm("2025-01-01T00:00:03.875Z")).toBe("2025-01-01T00:00:03Z");
    expect(secondsForm("2025-01-01T00:00:00.001Z")).toBe("2025-01-01T00:00:00Z");
  });

  it("preserves non-trailing-zero fractional digits exactly", () => {
    expect(millisForm("2025-01-01T00:00:03.875Z")).toBe("2025-01-01T00:00:03.875Z");
    expect(millisForm("2025-01-01T00:00:00.001Z")).toBe("2025-01-01T00:00:00.001Z");
  });

  it("collapses equal-value fractional forms to one canonical form", () => {
    expect(millisForm("2025-01-01T00:00:00.5Z")).toBe("2025-01-01T00:00:00.5Z");
    expect(millisForm("2025-01-01T00:00:00.50Z")).toBe("2025-01-01T00:00:00.5Z");
    expect(millisForm("2025-01-01T00:00:00.500Z")).toBe("2025-01-01T00:00:00.5Z");
  });

  it("drops an all-zero fractional part entirely, matching secondsForm", () => {
    expect(millisForm("2025-01-01T00:00:00.000Z")).toBe("2025-01-01T00:00:00Z");
    expect(millisForm("2025-01-01T00:00:00Z")).toBe("2025-01-01T00:00:00Z");
  });
});

describe("isDeactivated", () => {
  it("is true only for an empty updateRules object", () => {
    expect(isDeactivated(v3)).toBe(false);
    expect(isDeactivated(deactivatedV3)).toBe(true);
  });
});

describe("computeDocLocality", () => {
  it("a plain DID is never locally satisfiable unless the tip is deactivated", () => {
    expect(computeDocLocality(docs, {})).toEqual({ status: "needs-fetch" });
    expect(computeDocLocality(docsDeactivated, {})).toEqual({ status: "found", doc: deactivatedV3 });
  });

  it("an empty local store never locally satisfies anything but a deactivated-tip plain DID", () => {
    expect(computeDocLocality([], {})).toEqual({ status: "needs-fetch" });
    expect(computeDocLocality([], { versionId: 0 })).toEqual({ status: "needs-fetch" });
  });

  it("selfHash: found, needs-fetch, or known-absent behind a deactivation", () => {
    expect(computeDocLocality(docs, { selfHash: v1.selfHash })).toEqual({ status: "found", doc: v1 });
    expect(computeDocLocality(docs, { selfHash: "uHiAunknown" })).toEqual({ status: "needs-fetch" });
    expect(computeDocLocality(docsDeactivated, { selfHash: "uHiAunknown" })).toEqual({
      status: "known-absent",
    });
  });

  it("versionId: found, needs-fetch for an unserved version, known-absent beyond a deactivation", () => {
    expect(computeDocLocality(docs, { versionId: 2 })).toEqual({ status: "found", doc: v2 });
    expect(computeDocLocality(docs, { versionId: 9 })).toEqual({ status: "needs-fetch" });
    expect(computeDocLocality(docsDeactivated, { versionId: 9 })).toEqual({ status: "known-absent" });
  });

  it("versionTime: final only once a later local document proves it, or the store is complete", () => {
    const betweenV1AndV2 = "2025-01-01T00:00:02.000Z";
    expect(computeDocLocality(docs, { versionTime: betweenV1AndV2 })).toEqual({
      status: "found",
      doc: v1,
    });
    // tip itself: not provably final without either a later doc or deactivation
    const afterTip = "2025-01-01T00:00:04.000Z";
    expect(computeDocLocality(docs, { versionTime: afterTip })).toEqual({ status: "needs-fetch" });
    expect(computeDocLocality(docsDeactivated, { versionTime: afterTip })).toEqual({
      status: "found",
      doc: deactivatedV3,
    });
    const beforeRoot = "2024-01-01T00:00:00.000Z";
    expect(computeDocLocality(docs, { versionTime: beforeRoot })).toEqual({ status: "needs-fetch" });
    expect(computeDocLocality(docsDeactivated, { versionTime: beforeRoot })).toEqual({
      status: "known-absent",
    });
  });

  it("selfHash and versionId agreeing locally: found; disagreeing: conflict", () => {
    expect(computeDocLocality(docs, { selfHash: v1.selfHash, versionId: 1 })).toEqual({
      status: "found",
      doc: v1,
    });
    expect(computeDocLocality(docs, { selfHash: v1.selfHash, versionId: 2 })).toEqual({
      status: "conflict",
    });
  });

  it("selfHash and versionId, only one locally known: needs-fetch (or known-absent if complete)", () => {
    expect(computeDocLocality(docs, { selfHash: v1.selfHash, versionId: 9 })).toEqual({
      status: "needs-fetch",
    });
    expect(computeDocLocality(docsDeactivated, { selfHash: v1.selfHash, versionId: 9 })).toEqual({
      status: "known-absent",
    });
  });
});

describe("computeMetadataLocality", () => {
  it("is vacuously true when nothing is requested", () => {
    expect(computeMetadataLocality(docs, v3, {})).toBe(true);
    expect(computeMetadataLocality([], undefined, {})).toBe(true);
  });

  it("requestCreate needs version 0 locally", () => {
    expect(computeMetadataLocality(docs, v3, { requestCreate: true })).toBe(true);
    expect(computeMetadataLocality([], undefined, { requestCreate: true })).toBe(false);
  });

  it("requestNext is local when a successor is known, or the resolved doc is deactivated", () => {
    expect(computeMetadataLocality(docs, v1, { requestNext: true })).toBe(true); // v2 known
    expect(computeMetadataLocality(docs, v3, { requestNext: true })).toBe(false); // tip, not deactivated
    expect(computeMetadataLocality(docsDeactivated, deactivatedV3, { requestNext: true })).toBe(true);
    expect(computeMetadataLocality(docs, undefined, { requestNext: true })).toBe(false);
  });

  it("requestLatest / requestDeactivated need a deactivated local tip", () => {
    expect(computeMetadataLocality(docs, v1, { requestLatest: true })).toBe(false);
    expect(computeMetadataLocality(docsDeactivated, v1, { requestLatest: true })).toBe(true);
    expect(computeMetadataLocality(docs, v0, { requestDeactivated: true })).toBe(false);
    expect(computeMetadataLocality(docsDeactivated, v0, { requestDeactivated: true })).toBe(true);
  });
});

describe("buildDidDocumentMetadata (worked examples)", () => {
  it("cold plain DID, no options, latest document is version 3", () => {
    expect(buildDidDocumentMetadata(v3, docs, {})).toEqual({
      versionId: "3",
      updated: "2025-01-01T00:00:03Z",
      updatedMilliseconds: "2025-01-01T00:00:03.875Z",
    });
  });

  it("root only (version 0), no options", () => {
    expect(buildDidDocumentMetadata(v0, docs, {})).toEqual({ versionId: "0" });
  });

  it("requestCreate on a version-3 document", () => {
    expect(buildDidDocumentMetadata(v3, docs, { requestCreate: true })).toEqual({
      versionId: "3",
      updated: "2025-01-01T00:00:03Z",
      updatedMilliseconds: "2025-01-01T00:00:03.875Z",
      created: "2025-01-01T00:00:00Z",
      createdMilliseconds: "2025-01-01T00:00:00.001Z",
    });
  });

  it("requestNext when version 1 is resolved and version 2 exists", () => {
    expect(buildDidDocumentMetadata(v1, docs, { requestNext: true })).toEqual({
      versionId: "1",
      updated: "2025-01-01T00:00:01Z",
      updatedMilliseconds: "2025-01-01T00:00:01.633Z",
      nextUpdate: "2025-01-01T00:00:02Z",
      nextUpdateMilliseconds: "2025-01-01T00:00:02.242Z",
      nextVersionId: "2",
    });
  });

  it("requestLatest when version 1 is resolved and version 3 is latest", () => {
    expect(buildDidDocumentMetadata(v1, docs, { requestLatest: true })).toEqual({
      versionId: "1",
      updated: "2025-01-01T00:00:01Z",
      updatedMilliseconds: "2025-01-01T00:00:01.633Z",
      latestUpdate: "2025-01-01T00:00:03Z",
      latestUpdateMilliseconds: "2025-01-01T00:00:03.875Z",
      latestVersionId: "3",
    });
  });

  it("requestDeactivated on the root, DID not deactivated", () => {
    expect(buildDidDocumentMetadata(v0, docs, { requestDeactivated: true })).toEqual({
      versionId: "0",
      deactivated: false,
    });
  });

  it("deactivated latest document, option not required", () => {
    expect(buildDidDocumentMetadata(deactivatedV3, docsDeactivated, {})).toEqual({
      deactivated: true,
      updated: "2025-01-01T00:00:03Z",
      updatedMilliseconds: "2025-01-01T00:00:03.875Z",
      versionId: "3",
    });
  });

  it("requestNext omits the whole group when the resolved document is the latest", () => {
    const meta = buildDidDocumentMetadata(v3, docs, { requestNext: true });
    expect(meta).not.toHaveProperty("nextUpdate");
    expect(meta).not.toHaveProperty("nextVersionId");
  });
});
