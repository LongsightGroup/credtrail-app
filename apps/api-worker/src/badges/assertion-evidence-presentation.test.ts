import { describe, expect, it } from "vitest";

import type { AssertionEvidenceLoadedData } from "./assertion-evidence-payload";
import { buildAssertionEvidencePresentation } from "./assertion-evidence-presentation";
import { sampleBadgeRuleVersionSnapshot } from "../test-support/badge-rule-version-snapshot";

const versionRecordFixtureFields = {
  snapshot: sampleBadgeRuleVersionSnapshot,
  effectiveStartsAt: null,
  expiresAt: null,
  expiredAt: null,
  suspendedAt: null,
  suspendedByUserId: null,
  suspensionReason: null,
  recertifiedAt: null,
  recertificationDueAt: null,
  expiryReminderSentAt: null,
  recertificationReminderSentAt: null,
};

const sampleLoadedData = (
  overrides?: Partial<AssertionEvidenceLoadedData>,
): AssertionEvidenceLoadedData => {
  return {
    assertion: {
      id: "tenant_123:assertion_456",
      tenantId: "tenant_123",
      publicId: "cred-abc123",
      learnerProfileId: null,
      badgeTemplateId: "tenant_123:badge_template_001",
      recipientIdentity: "learner@example.edu",
      recipientIdentityType: "email",
      vcR2Key: "tenants/tenant_123/assertions/tenant_123:assertion_456.jsonld",
      statusListIndex: null,
      idempotencyKey: "manual:tenant_123:assertion_456",
      issuedAt: "2026-03-24T15:00:00.000Z",
      issuedByUserId: "usr_admin",
      revokedAt: null,
      createdAt: "2026-03-24T15:00:00.000Z",
      updatedAt: "2026-03-24T15:00:00.000Z",
    },
    badgeTemplate: {
      id: "tenant_123:badge_template_001",
      tenantId: "tenant_123",
      slug: "applied-analytics",
      title: "Applied Analytics",
      description: "Awarded for analytics coursework.",
      criteriaUri: "https://example.edu/criteria",
      imageUri: "https://example.edu/badges/analytics.png",
      createdByUserId: "usr_admin",
      ownerOrgUnitId: "tenant_123:org:institution",
      governanceMetadataJson: null,
      isArchived: false,
      createdAt: "2026-03-24T15:00:00.000Z",
      updatedAt: "2026-03-24T15:00:00.000Z",
    },
    lifecycle: {
      state: "active",
      source: "default_active",
      reasonCode: null,
      reason: null,
      transitionedAt: null,
      revokedAt: null,
    },
    lifecycleEvents: [],
    auditLogs: [],
    attributedOrgUnitName: "Computer Science",
    issuerLabel: "admin@tenant-123.edu",
    evaluation: null,
    provenance: null,
    rule: null,
    version: null,
    approvalEvents: [],
    approvalSteps: [],
    actorLabels: new Map([["usr_admin", "admin@tenant-123.edu"]]),
    generatedAt: "2026-03-24T16:00:00.000Z",
    ...overrides,
  };
};

describe("buildAssertionEvidencePresentation", () => {
  it("labels manual issuance when a user issued the badge without rule evaluation", () => {
    const presentation = buildAssertionEvidencePresentation(sampleLoadedData());

    expect(presentation.issuance.source).toBe("manual");
    expect(presentation.issuance.sourceLabel).toContain("manually");
    expect(presentation.summary.badgeTitle).toBe("Applied Analytics");
    expect(presentation.rule).toBeNull();
  });

  it("includes rule and evaluation sections when an evaluation row exists", () => {
    const presentation = buildAssertionEvidencePresentation(
      sampleLoadedData({
        evaluation: {
          id: "bre_123",
          tenantId: "tenant_123",
          ruleId: "tenant_123:brl_123",
          versionId: "tenant_123:brv_123",
          learnerId: "learner-001",
          recipientIdentity: "learner@example.edu",
          recipientIdentityType: "email",
          matched: true,
          issuanceStatus: "issued",
          assertionId: "tenant_123:assertion_456",
          evaluationJson: JSON.stringify({
            outcome: "matched",
            evaluation: {
              matched: true,
              tree: {
                type: "condition",
                matched: true,
                detail: "Final score meets threshold.",
              },
            },
            facts: {
              courses: [{ courseId: "course-101", finalScore: 92 }],
            },
          }),
          reviewStatus: null,
          reviewDecision: null,
          reviewComment: null,
          reviewedByUserId: null,
          reviewedAt: null,
          evaluatedAt: "2026-03-24T15:00:00.000Z",
          createdAt: "2026-03-24T15:00:00.000Z",
        },
        rule: {
          id: "tenant_123:brl_123",
          tenantId: "tenant_123",
          name: "CS101 Excellence",
          description: "Rule description",
          badgeTemplateId: "tenant_123:badge_template_001",
          orgUnitId: "tenant_123:org:institution",
          ownerOrgUnitId: "tenant_123:org:institution",
          lmsProviderKind: "canvas",
          lmsConnectionId: null,
          activeVersionId: "tenant_123:brv_123",
          createdByUserId: "usr_admin",
          createdAt: "2026-03-24T12:00:00.000Z",
          updatedAt: "2026-03-24T12:00:00.000Z",
        },
        version: {
          id: "tenant_123:brv_123",
          tenantId: "tenant_123",
          ruleId: "tenant_123:brl_123",
          versionNumber: 2,
          status: "active",
          ruleJson: "{}",
          changeSummary: "Activated for spring term",
          createdByUserId: "usr_admin",
          submittedByUserId: "usr_admin",
          submittedAt: "2026-03-20T12:00:00.000Z",
          approvedByUserId: "usr_reviewer",
          approvedAt: "2026-03-21T12:00:00.000Z",
          activatedByUserId: "usr_admin",
          activatedAt: "2026-03-22T12:00:00.000Z",
          ...versionRecordFixtureFields,
          snapshot: {
            ...sampleBadgeRuleVersionSnapshot,
            name: "CS101 Excellence",
          },
          createdAt: "2026-03-20T12:00:00.000Z",
          updatedAt: "2026-03-22T12:00:00.000Z",
        },
      }),
    );

    expect(presentation.issuance.source).toBe("rule_evaluate");
    expect(presentation.rule?.ruleName).toBe("CS101 Excellence");
    expect(presentation.rule?.versionNumber).toBe(2);
    expect(presentation.evaluationOutcomes.length).toBeGreaterThan(0);
  });

  it("merges revocation lifecycle events into changes after issuance", () => {
    const presentation = buildAssertionEvidencePresentation(
      sampleLoadedData({
        lifecycle: {
          state: "revoked",
          source: "lifecycle_event",
          reasonCode: "issuer_requested",
          reason: "Issued in error",
          transitionedAt: "2026-03-25T10:00:00.000Z",
          revokedAt: "2026-03-25T10:00:00.000Z",
        },
        lifecycleEvents: [
          {
            id: "ale_123",
            tenantId: "tenant_123",
            assertionId: "tenant_123:assertion_456",
            fromState: "active",
            toState: "revoked",
            reasonCode: "issuer_requested",
            reason: "Issued in error",
            transitionSource: "manual",
            actorUserId: "usr_admin",
            transitionedAt: "2026-03-25T10:00:00.000Z",
            createdAt: "2026-03-25T10:00:00.000Z",
          },
        ],
      }),
    );

    expect(presentation.summary.lifecycleState).toBe("revoked");
    expect(
      presentation.changesAfterIssuance.some((entry) => entry.summary.includes("Revoked")),
    ).toBe(true);
  });

  it("falls back to provenance when no evaluation row exists", () => {
    const presentation = buildAssertionEvidencePresentation(
      sampleLoadedData({
        assertion: {
          ...sampleLoadedData().assertion,
          issuedByUserId: null,
          idempotencyKey: "lti:tenant_123:resource-link-123:learner-001",
        },
        provenance: {
          assertionId: "tenant_123:assertion_456",
          tenantId: "tenant_123",
          source: "lti_roster",
          ruleId: "tenant_123:brl_123",
          versionId: "tenant_123:brv_123",
          provenanceJson: JSON.stringify({
            outcome: "matched",
            evaluation: {
              matched: true,
              tree: { type: "condition", matched: true, detail: "Eligible from roster." },
            },
          }),
          createdAt: "2026-03-24T15:00:00.000Z",
        },
        rule: {
          id: "tenant_123:brl_123",
          tenantId: "tenant_123",
          name: "LTI Roster Rule",
          description: null,
          badgeTemplateId: "tenant_123:badge_template_001",
          orgUnitId: "tenant_123:org:institution",
          ownerOrgUnitId: "tenant_123:org:institution",
          lmsProviderKind: "sakai",
          lmsConnectionId: "lms_123",
          activeVersionId: "tenant_123:brv_123",
          createdByUserId: "usr_admin",
          createdAt: "2026-03-24T12:00:00.000Z",
          updatedAt: "2026-03-24T12:00:00.000Z",
        },
        version: {
          id: "tenant_123:brv_123",
          tenantId: "tenant_123",
          ruleId: "tenant_123:brl_123",
          versionNumber: 1,
          status: "active",
          ruleJson: "{}",
          changeSummary: null,
          createdByUserId: "usr_admin",
          submittedByUserId: null,
          submittedAt: null,
          approvedByUserId: null,
          approvedAt: null,
          activatedByUserId: "usr_admin",
          activatedAt: "2026-03-22T12:00:00.000Z",
          ...versionRecordFixtureFields,
          snapshot: {
            ...sampleBadgeRuleVersionSnapshot,
            name: "LTI Roster Rule",
          },
          createdAt: "2026-03-20T12:00:00.000Z",
          updatedAt: "2026-03-22T12:00:00.000Z",
        },
      }),
    );

    expect(presentation.issuance.source).toBe("lti_roster");
    expect(presentation.rule?.ruleName).toBe("LTI Roster Rule");
  });
});
