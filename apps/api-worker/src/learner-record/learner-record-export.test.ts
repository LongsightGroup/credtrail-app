import { describe, expect, it } from "vitest";

import type {
  LearnerProfileRecord,
  LearnerRecordAssertionExportRecord,
  LearnerRecordEntryRecord,
} from "@credtrail/db";
import type { LearnerRecordExportProfile } from "@credtrail/validation";

import {
  LEARNER_RECORD_STANDARDS_MAPPING_CATALOG,
  buildLearnerRecordStandardsMappingResponse,
  createLearnerRecordStandardsMappingCatalog,
  serializeLearnerRecordExport,
  type LearnerRecordClrAlignedExport,
  type LearnerRecordExportBundle,
  type LearnerRecordPortableExport,
} from "./learner-record-export";
import {
  mapAssertionToCanonicalLearnerRecordItem,
  mapLearnerRecordEntryToCanonicalLearnerRecordItem,
} from "./learner-record-contract";

const sampleLearnerProfile = (overrides?: Partial<LearnerProfileRecord>): LearnerProfileRecord => {
  return {
    id: "lpr_123",
    tenantId: "tenant_123",
    subjectId: "urn:credtrail:learner:tenant_123:lpr_123",
    displayName: "Learner One",
    createdAt: "2026-03-25T12:00:00.000Z",
    updatedAt: "2026-03-25T12:00:00.000Z",
    ...overrides,
  };
};

const sampleAssertionExportRecord = (
  overrides?: Partial<LearnerRecordAssertionExportRecord>,
): LearnerRecordAssertionExportRecord => {
  return {
    assertionId: "tenant_123:assertion_456",
    assertionPublicId: "public_assertion_456",
    tenantId: "tenant_123",
    learnerProfileId: "lpr_123",
    badgeTemplateId: "badge_template_001",
    badgeTitle: "Applied Analytics Badge",
    badgeDescription: "Awarded for applied analytics work.",
    badgeCriteriaUri: "https://credtrail.example.edu/badges/applied-analytics/criteria",
    badgeImageUri: "https://credtrail.example.edu/badges/applied-analytics/image.png",
    recipientIdentity: "learner@example.edu",
    recipientIdentityType: "email",
    vcR2Key: "tenants/tenant_123/assertions/assertion_456.jsonld",
    statusListIndex: 12,
    idempotencyKey: "idem_123",
    issuedAt: "2026-03-24T15:00:00.000Z",
    issuedByUserId: "usr_admin",
    revokedAt: null,
    issuerName: "CredTrail University",
    createdAt: "2026-03-24T15:00:00.000Z",
    updatedAt: "2026-03-24T15:00:00.000Z",
    ...overrides,
  };
};

const sampleLearnerRecordEntry = (
  overrides?: Partial<LearnerRecordEntryRecord>,
): LearnerRecordEntryRecord => {
  return {
    id: "lre_123",
    tenantId: "tenant_123",
    learnerProfileId: "lpr_123",
    trustLevel: "issuer_verified",
    recordType: "course",
    status: "active",
    title: "Clinical Placement Seminar",
    description: "Completed with distinction.",
    issuerName: "CredTrail University",
    issuerUserId: "usr_admin",
    sourceSystem: "credtrail_admin",
    sourceRecordId: null,
    issuedAt: "2026-03-23T15:00:00.000Z",
    revisedAt: null,
    revokedAt: null,
    evidenceLinksJson: '["https://credtrail.example.edu/evidence/clinical-placement-seminar"]',
    detailsJson: '{"grade":"A"}',
    createdAt: "2026-03-23T15:00:00.000Z",
    updatedAt: "2026-03-23T15:00:00.000Z",
    ...overrides,
  };
};

const sampleBundle = (): LearnerRecordExportBundle => {
  return {
    tenantId: "tenant_123",
    learnerProfile: sampleLearnerProfile(),
    generatedAt: "2026-03-25T15:00:00.000Z",
    standardsMapping: LEARNER_RECORD_STANDARDS_MAPPING_CATALOG,
    items: [
      mapAssertionToCanonicalLearnerRecordItem({
        assertion: {
          id: sampleAssertionExportRecord().assertionId,
          tenantId: "tenant_123",
          publicId: "public_assertion_456",
          learnerProfileId: "lpr_123",
          badgeTemplateId: "badge_template_001",
          issuedAt: "2026-03-24T15:00:00.000Z",
          issuedByUserId: "usr_admin",
          revokedAt: null,
        },
        badgeTitle: "Applied Analytics Badge",
        badgeDescription: "Awarded for applied analytics work.",
        issuerName: "CredTrail University",
        evidenceLinks: [],
      }),
      mapLearnerRecordEntryToCanonicalLearnerRecordItem(sampleLearnerRecordEntry()),
    ],
  };
};

describe("learner-record export contract", () => {
  it("defines explicit native, mapped, and unavailable standards support states", () => {
    const catalog = createLearnerRecordStandardsMappingCatalog();
    const ob3 = catalog.frameworks.find((framework) => framework.framework === "ob3");
    const clr = catalog.frameworks.find((framework) => framework.framework === "clr");

    expect(ob3).toBeDefined();
    expect(ob3?.fields.some((field) => field.status === "native")).toBe(true);
    expect(ob3?.fields.some((field) => field.status === "unavailable")).toBe(true);
    expect(clr?.fields.every((field) => field.status === "mapped")).toBe(true);
  });

  it("keeps badge-native and non-badge aligned support distinguishable in the mapping catalog", () => {
    const ob3 = LEARNER_RECORD_STANDARDS_MAPPING_CATALOG.frameworks.find(
      (framework) => framework.framework === "ob3",
    );

    expect(ob3?.fields).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          nativeFieldPath: "id",
          status: "native",
          appliesToKinds: ["badge_assertion"],
        }),
        expect.objectContaining({
          nativeFieldPath: "recordType",
          status: "unavailable",
          appliesToKinds: ["record_entry"],
        }),
      ]),
    );
  });

  it("serializes portable and clr-aligned learner-record exports without losing trust semantics", () => {
    const bundle = sampleBundle();

    const nativeExport = serializeLearnerRecordExport(
      bundle,
      "native_portable_json",
    ) as LearnerRecordPortableExport;
    const clrExport = serializeLearnerRecordExport(
      bundle,
      "clr_alignment_json",
    ) as LearnerRecordClrAlignedExport;

    expect(nativeExport.profile).toBe("native_portable_json");
    expect(nativeExport.counts.totalItems).toBe(2);
    expect(nativeExport.counts.badgeAssertions).toBe(1);
    expect(nativeExport.counts.learnerSupplemental).toBe(0);
    expect(nativeExport.items.map((item) => item.trustLevel)).toEqual([
      "issuer_verified",
      "issuer_verified",
    ]);

    expect(clrExport.profile).toBe("clr_alignment_json");
    expect(clrExport.records).toHaveLength(2);
    expect(clrExport.records[0]?.alignment).toEqual({
      clr: "mapped",
      pesc: "mapped",
      ctdl: "mapped",
      ceds: "mapped",
    });
  });

  it("builds a standards-mapping response that exposes profile and item counts", () => {
    const response = buildLearnerRecordStandardsMappingResponse(
      sampleBundle(),
      "clr_alignment_json" satisfies LearnerRecordExportProfile,
    );

    expect(response.profile).toBe("clr_alignment_json");
    expect(response.itemCounts.totalItems).toBe(2);
    expect(response.itemCounts.badgeAssertions).toBe(1);
    expect(response.standardsMapping.frameworks).toHaveLength(6);
  });
});
