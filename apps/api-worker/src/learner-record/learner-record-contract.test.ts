import { describe, expect, it } from "vitest";

import type { AssertionRecord, LearnerRecordEntryRecord } from "@credtrail/db";

import {
  type CanonicalLearnerRecordItem,
  learnerRecordDisplayTypeLabel,
  mapAssertionToCanonicalLearnerRecordItem,
  mapLearnerRecordEntryToCanonicalLearnerRecordItem,
} from "./learner-record-contract";

const sampleAssertion = (overrides?: Partial<AssertionRecord>): AssertionRecord => {
  return {
    id: "assertion_123",
    tenantId: "tenant_123",
    publicId: "public_assertion_123",
    learnerProfileId: "lpr_123",
    badgeTemplateId: "badge_template_123",
    achievementSnapshot: {
      badgeTemplateId: "badge_template_123",
      title: "Applied Analytics Badge",
      description: "Awarded for applied analytics work.",
      criteriaUri: "https://credtrail.example.edu/criteria/applied-analytics",
      imageUri: null,
      trustedCredentialMetadataJson: null,
    },
    recipientIdentity: "learner@example.edu",
    recipientIdentityType: "email",
    vcR2Key: "vc_r2_key_123",
    statusListIndex: 42,
    idempotencyKey: "idempotency_123",
    issuedAt: "2026-03-24T15:00:00.000Z",
    issuedByUserId: "usr_issuer",
    revokedAt: null,
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
    title: "Applied Analytics Practicum",
    description: "Completed with distinction.",
    issuerName: "CredTrail University",
    issuerUserId: "usr_admin",
    sourceSystem: "credtrail_admin",
    sourceRecordId: null,
    issuedAt: "2026-03-24T15:00:00.000Z",
    revisedAt: null,
    revokedAt: null,
    evidenceLinksJson: '["https://credtrail.example.edu/evidence/applied-analytics/practicum"]',
    detailsJson: '{"grade":"A","credits":3}',
    createdAt: "2026-03-24T15:00:00.000Z",
    updatedAt: "2026-03-24T15:00:00.000Z",
    ...overrides,
  };
};

describe("learner record contract", () => {
  it("maps a current badge assertion into the canonical learner-record vocabulary", () => {
    const record = mapAssertionToCanonicalLearnerRecordItem({
      assertion: sampleAssertion(),
      badgeTitle: "Applied Analytics Badge",
      badgeDescription: "Awarded for applied analytics work.",
      issuerName: "CredTrail University",
      evidenceLinks: ["https://credtrail.example.edu/evidence/applied-analytics"],
    });

    expect(record).toEqual({
      id: "assertion_123",
      kind: "badge_assertion",
      tenantId: "tenant_123",
      learnerProfileId: "lpr_123",
      trustLevel: "issuer_verified",
      status: "active",
      recordType: "badge",
      title: "Applied Analytics Badge",
      description: "Awarded for applied analytics work.",
      sourceEntryId: null,
      badgeTemplateId: "badge_template_123",
      publicBadgeId: "public_assertion_123",
      editable: false,
      details: null,
      provenance: {
        issuerName: "CredTrail University",
        issuerUserId: "usr_issuer",
        sourceSystem: "badge_assertion",
        sourceRecordId: "assertion_123",
        issuedAt: "2026-03-24T15:00:00.000Z",
        revisedAt: null,
        revokedAt: null,
        evidenceLinks: ["https://credtrail.example.edu/evidence/applied-analytics"],
      },
    } satisfies CanonicalLearnerRecordItem);
  });

  it("keeps revoked badge assertions honest in the canonical learner-record contract", () => {
    const record = mapAssertionToCanonicalLearnerRecordItem({
      assertion: sampleAssertion({
        revokedAt: "2026-03-25T15:00:00.000Z",
        updatedAt: "2026-03-25T15:00:00.000Z",
      }),
      badgeTitle: "Clinical Readiness Badge",
      issuerName: "CredTrail University",
      evidenceLinks: [],
    });

    expect(record.status).toBe("revoked");
    expect(record.editable).toBe(false);
    expect(record.provenance.revokedAt).toBe("2026-03-25T15:00:00.000Z");
    expect(record.provenance.revisedAt).toBeNull();
  });

  it("maps managed learner-record entries into the same canonical contract", () => {
    const record = mapLearnerRecordEntryToCanonicalLearnerRecordItem(sampleLearnerRecordEntry());

    expect(record).toEqual({
      id: "lre_123",
      kind: "record_entry",
      tenantId: "tenant_123",
      learnerProfileId: "lpr_123",
      trustLevel: "issuer_verified",
      status: "active",
      recordType: "course",
      title: "Applied Analytics Practicum",
      description: "Completed with distinction.",
      sourceEntryId: "lre_123",
      badgeTemplateId: null,
      publicBadgeId: null,
      editable: true,
      details: {
        grade: "A",
        credits: 3,
      },
      provenance: {
        issuerName: "CredTrail University",
        issuerUserId: "usr_admin",
        sourceSystem: "credtrail_admin",
        sourceRecordId: null,
        issuedAt: "2026-03-24T15:00:00.000Z",
        revisedAt: null,
        revokedAt: null,
        evidenceLinks: ["https://credtrail.example.edu/evidence/applied-analytics/practicum"],
      },
    } satisfies CanonicalLearnerRecordItem);
  });

  it("exposes human-readable labels for the fixed native learner-record types", () => {
    expect(learnerRecordDisplayTypeLabel("course")).toBe("Course");
    expect(learnerRecordDisplayTypeLabel("work_based_learning")).toBe("Work-based learning");
    expect(learnerRecordDisplayTypeLabel("supplemental_artifact")).toBe("Supplemental artifact");
  });
});
