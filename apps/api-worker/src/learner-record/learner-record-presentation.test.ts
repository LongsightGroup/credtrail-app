import { describe, expect, it } from "vitest";

import type { LearnerProfileRecord } from "@credtrail/db";

import type { CanonicalLearnerRecordItem } from "./learner-record-contract";
import type { LearnerRecordExportBundle } from "./learner-record-export";
import { createLearnerRecordPresentation } from "./learner-record-presentation";

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

const sampleItem = (
  overrides?: Partial<CanonicalLearnerRecordItem>,
): CanonicalLearnerRecordItem => {
  return {
    id: "tenant_123:item_001",
    kind: "record_entry",
    tenantId: "tenant_123",
    learnerProfileId: "lpr_123",
    trustLevel: "issuer_verified",
    status: "active",
    recordType: "course",
    title: "Clinical Placement Seminar",
    description: "Completed with distinction.",
    sourceEntryId: "lre_001",
    badgeTemplateId: null,
    publicBadgeId: null,
    editable: true,
    details: {
      grade: "A",
    },
    provenance: {
      issuerName: "CredTrail University",
      issuerUserId: "usr_admin",
      sourceSystem: "credtrail_admin",
      sourceRecordId: "sis:course:clinical-placement",
      issuedAt: "2026-03-24T15:00:00.000Z",
      revisedAt: null,
      revokedAt: null,
      evidenceLinks: ["https://credtrail.example.edu/evidence/clinical-placement"],
    },
    ...overrides,
  };
};

const sampleBundle = (items: readonly CanonicalLearnerRecordItem[]): LearnerRecordExportBundle => {
  return {
    tenantId: "tenant_123",
    learnerProfile: sampleLearnerProfile(),
    generatedAt: "2026-03-26T12:00:00.000Z",
    items,
    standardsMapping: {
      catalogVersion: "credtrail-learner-record-standards/v1",
      frameworks: [],
    },
  };
};

describe("createLearnerRecordPresentation", () => {
  it("groups mixed learner-record truth into active verified, supplemental, and historical sections", () => {
    const model = createLearnerRecordPresentation(
      sampleBundle([
        sampleItem({
          id: "tenant_123:assertion_001",
          kind: "badge_assertion",
          recordType: "badge",
          title: "Applied Analytics Badge",
          sourceEntryId: null,
          badgeTemplateId: "badge_template_001",
          publicBadgeId: "public_assertion_001",
          editable: false,
          details: {
            criteriaUri: "https://credtrail.example.edu/badges/applied-analytics/criteria",
          },
          provenance: {
            issuerName: "CredTrail University",
            issuerUserId: "usr_admin",
            sourceSystem: "badge_assertion",
            sourceRecordId: "tenant_123:assertion_001",
            issuedAt: "2026-03-25T15:00:00.000Z",
            revisedAt: null,
            revokedAt: null,
            evidenceLinks: [],
          },
        }),
        sampleItem(),
        sampleItem({
          id: "lre_supp_001",
          trustLevel: "learner_supplemental",
          recordType: "supplemental_artifact",
          title: "Portfolio Reflection",
          description: "Learner-supplied capstone reflection.",
          details: {
            portfolioUrl: "https://portfolio.example.edu/learner-one",
          },
          provenance: {
            issuerName: "Learner self report",
            issuerUserId: null,
            sourceSystem: "learner_self_reported",
            sourceRecordId: null,
            issuedAt: "2026-03-23T15:00:00.000Z",
            revisedAt: null,
            revokedAt: null,
            evidenceLinks: ["https://portfolio.example.edu/learner-one"],
          },
        }),
        sampleItem({
          id: "lre_old_001",
          status: "revoked",
          title: "Membership Standing",
          recordType: "membership",
          provenance: {
            issuerName: "CredTrail University",
            issuerUserId: "usr_admin",
            sourceSystem: "csv_import",
            sourceRecordId: "legacy:membership:001",
            issuedAt: "2026-03-20T15:00:00.000Z",
            revisedAt: null,
            revokedAt: "2026-03-22T15:00:00.000Z",
            evidenceLinks: [],
          },
        }),
      ]),
    );

    expect(model.summary).toEqual({
      total: 4,
      issuerVerified: 3,
      supplemental: 1,
      active: 3,
      historical: 1,
      badgeAssertions: 1,
      recordEntries: 3,
    });
    expect(model.sections.map((section) => section.key)).toEqual([
      "issuerVerifiedActive",
      "supplementalActive",
      "historical",
    ]);
    expect(model.sections[0]?.items.map((item) => item.title)).toEqual([
      "Applied Analytics Badge",
      "Clinical Placement Seminar",
    ]);
  });

  it("keeps issuer-verified and learner-supplemental trust visible in the presentation output", () => {
    const model = createLearnerRecordPresentation(
      sampleBundle([
        sampleItem({
          id: "verified_001",
          title: "Institutional Internship",
        }),
        sampleItem({
          id: "supp_001",
          trustLevel: "learner_supplemental",
          recordType: "supplemental_artifact",
          title: "Independent Design Notes",
          provenance: {
            issuerName: "Learner self report",
            issuerUserId: null,
            sourceSystem: "learner_self_reported",
            sourceRecordId: null,
            issuedAt: "2026-03-23T15:00:00.000Z",
            revisedAt: null,
            revokedAt: null,
            evidenceLinks: [],
          },
        }),
      ]),
    );

    expect(model.sections[0]?.title).toBe("Institution-verified record");
    expect(model.sections[0]?.items[0]?.trustLabel).toBe("Issuer verified");
    expect(model.sections[1]?.title).toBe("Learner-supplemental record");
    expect(model.sections[1]?.items[0]?.trustLabel).toBe("Learner supplemental");
    expect(model.sections[1]?.items[0]?.provenanceSummary).toContain("Learner self report");
  });

  it("keeps revoked history visible without displacing the active record story", () => {
    const model = createLearnerRecordPresentation(
      sampleBundle([
        sampleItem({
          id: "active_001",
          title: "Current Teaching Certificate",
        }),
        sampleItem({
          id: "revoked_001",
          status: "revoked",
          title: "Prior Teaching Certificate",
          provenance: {
            issuerName: "CredTrail University",
            issuerUserId: "usr_admin",
            sourceSystem: "migration",
            sourceRecordId: "legacy:cert:001",
            issuedAt: "2026-03-18T15:00:00.000Z",
            revisedAt: null,
            revokedAt: "2026-03-21T15:00:00.000Z",
            evidenceLinks: [],
          },
        }),
      ]),
    );

    expect(model.sections[0]?.items.map((item) => item.title)).toEqual([
      "Current Teaching Certificate",
    ]);
    expect(model.sections[1]?.key).toBe("historical");
    expect(model.sections[1]?.items[0]).toEqual(
      expect.objectContaining({
        title: "Prior Teaching Certificate",
        statusLabel: "Revoked",
      }),
    );
  });

  it("produces honest sparse output for badge-only, supplemental-only, and empty learners", () => {
    const badgeOnly = createLearnerRecordPresentation(
      sampleBundle([
        sampleItem({
          id: "tenant_123:assertion_001",
          kind: "badge_assertion",
          recordType: "badge",
          title: "Applied Analytics Badge",
          sourceEntryId: null,
          badgeTemplateId: "badge_template_001",
          publicBadgeId: "public_assertion_001",
          editable: false,
          details: null,
          provenance: {
            issuerName: "CredTrail University",
            issuerUserId: "usr_admin",
            sourceSystem: "badge_assertion",
            sourceRecordId: "tenant_123:assertion_001",
            issuedAt: "2026-03-25T15:00:00.000Z",
            revisedAt: null,
            revokedAt: null,
            evidenceLinks: [],
          },
        }),
      ]),
    );
    const supplementalOnly = createLearnerRecordPresentation(
      sampleBundle([
        sampleItem({
          id: "supp_001",
          trustLevel: "learner_supplemental",
          recordType: "supplemental_artifact",
          title: "Independent Study Notes",
          provenance: {
            issuerName: "Learner self report",
            issuerUserId: null,
            sourceSystem: "learner_self_reported",
            sourceRecordId: null,
            issuedAt: "2026-03-23T15:00:00.000Z",
            revisedAt: null,
            revokedAt: null,
            evidenceLinks: [],
          },
        }),
      ]),
    );
    const emptyModel = createLearnerRecordPresentation(sampleBundle([]));

    expect(badgeOnly.sections.map((section) => section.key)).toEqual(["issuerVerifiedActive"]);
    expect(badgeOnly.sections[0]?.items[0]?.publicBadgePath).toBe("/badges/public_assertion_001");
    expect(supplementalOnly.summary.issuerVerified).toBe(0);
    expect(supplementalOnly.sections.map((section) => section.key)).toEqual(["supplementalActive"]);
    expect(emptyModel.summary.total).toBe(0);
    expect(emptyModel.sections).toEqual([]);
  });
});
