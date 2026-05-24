import { describe, expect, it } from "vitest";

import type { BadgeTemplateRecord, TenantOrgUnitRecord } from "@credtrail/db";

import {
  buildLearnerRecordImportTemplateCsv,
  parseLearnerRecordImportFile,
  prepareLearnerRecordImportBatch,
} from "./learner-record-import";

const sampleOrgUnits = (): TenantOrgUnitRecord[] => {
  return [
    {
      id: "tenant_123:org:institution",
      tenantId: "tenant_123",
      unitType: "institution",
      slug: "institution",
      displayName: "CredTrail University",
      parentOrgUnitId: null,
      createdByUserId: "usr_admin",
      isActive: true,
      createdAt: "2026-03-26T12:00:00.000Z",
      updatedAt: "2026-03-26T12:00:00.000Z",
    },
    {
      id: "tenant_123:org:department-health",
      tenantId: "tenant_123",
      unitType: "department",
      slug: "department-health",
      displayName: "Department of Health",
      parentOrgUnitId: "tenant_123:org:institution",
      createdByUserId: "usr_admin",
      isActive: true,
      createdAt: "2026-03-26T12:00:00.000Z",
      updatedAt: "2026-03-26T12:00:00.000Z",
    },
  ];
};

const sampleBadgeTemplates = (): BadgeTemplateRecord[] => {
  return [
    {
      id: "badge_template_001",
      tenantId: "tenant_123",
      slug: "clinical-placement-badge",
      title: "Clinical Placement Badge",
      description: "Awarded for clinical readiness.",
      criteriaUri: null,
      imageUri: null,
      createdByUserId: "usr_admin",
      ownerOrgUnitId: "tenant_123:org:department-health",
      governanceMetadataJson: null,
      isArchived: false,
      createdAt: "2026-03-26T12:00:00.000Z",
      updatedAt: "2026-03-26T12:00:00.000Z",
    },
  ];
};

describe("learner-record import contract", () => {
  it("parses a low-friction CSV row with the shared template headers", () => {
    const csv = [
      "learnerEmail,title,recordType,issuedAt",
      "learner@example.edu,Clinical Placement Seminar,course,2026-03-26T12:00:00.000Z",
    ].join("\n");

    const result = parseLearnerRecordImportFile({
      fileName: "learner-records.csv",
      mimeType: "text/csv",
      content: csv,
    });

    expect(result.format).toBe("csv");
    expect(result.rows).toEqual([
      {
        rowNumber: 1,
        candidate: {
          learnerEmail: "learner@example.edu",
          title: "Clinical Placement Seminar",
          recordType: "course",
          issuedAt: "2026-03-26T12:00:00.000Z",
        },
      },
    ]);
  });

  it("accepts URL key headers while keeping legacy slug headers compatible", () => {
    const csv = [
      "learnerEmail,title,recordType,issuedAt,badgeTemplateUrlKey",
      "learner@example.edu,Clinical Placement Seminar,course,2026-03-26T12:00:00.000Z,clinical-placement-badge",
    ].join("\n");
    const legacyCsv = [
      "learnerEmail,title,recordType,issuedAt,badgeTemplateSlug",
      "learner@example.edu,Clinical Placement Seminar,course,2026-03-26T12:00:00.000Z,clinical-placement-badge",
    ].join("\n");

    expect(
      parseLearnerRecordImportFile({
        fileName: "learner-records.csv",
        mimeType: "text/csv",
        content: csv,
      }).rows[0]?.candidate,
    ).toMatchObject({
      badgeTemplateSlug: "clinical-placement-badge",
    });
    expect(
      parseLearnerRecordImportFile({
        fileName: "learner-records.csv",
        mimeType: "text/csv",
        content: legacyCsv,
      }).rows[0]?.candidate,
    ).toMatchObject({
      badgeTemplateSlug: "clinical-placement-badge",
    });
  });

  it("uses smart defaults from badge-template ownership and preserves pathway as metadata", () => {
    const prepared = prepareLearnerRecordImportBatch({
      rows: [
        {
          rowNumber: 1,
          candidate: {
            learnerEmail: "learner@example.edu",
            learnerDisplayName: "Learner Example",
            title: "Clinical Placement Seminar",
            recordType: "course",
            issuedAt: "2026-03-26T12:00:00.000Z",
            badgeTemplateSlug: "clinical-placement-badge",
            pathwayLabel: "Clinical readiness",
          },
        },
      ],
      defaults: {
        defaultTrustLevel: "issuer_verified",
      },
      tenantDisplayName: "CredTrail University",
      orgUnits: sampleOrgUnits(),
      badgeTemplates: sampleBadgeTemplates(),
      fileName: "learner-records.csv",
      batchId: "batch_123",
      requestedAt: "2026-03-26T12:00:00.000Z",
    });

    expect(prepared.queuePayloads).toHaveLength(1);
    expect(prepared.reports[0]).toMatchObject({
      rowNumber: 1,
      status: "valid",
      errors: [],
      preview: {
        trustLevel: "issuer_verified",
        issuerName: "CredTrail University",
        smartContext: {
          orgUnitId: "tenant_123:org:department-health",
          badgeTemplateId: "badge_template_001",
          pathwayLabel: "Clinical readiness",
          inferredFrom: ["row", "badge_template"],
        },
      },
    });
    expect(prepared.reports[0]?.warnings).toContain(
      "Pathway is preserved as imported metadata only. CredTrail does not yet treat pathway as a native learner-record relation.",
    );
  });

  it("keeps missing context explicit instead of inventing it", () => {
    const prepared = prepareLearnerRecordImportBatch({
      rows: [
        {
          rowNumber: 3,
          candidate: {
            learnerEmail: "learner@example.edu",
            title: "Independent Study Reflection",
            recordType: "experience",
            issuedAt: "2026-03-26T12:00:00.000Z",
          },
        },
      ],
      defaults: {
        defaultTrustLevel: "issuer_verified",
      },
      tenantDisplayName: "CredTrail University",
      orgUnits: sampleOrgUnits(),
      badgeTemplates: sampleBadgeTemplates(),
      fileName: "learner-records.csv",
      batchId: "batch_123",
      requestedAt: "2026-03-26T12:00:00.000Z",
    });

    expect(prepared.reports[0]).toMatchObject({
      status: "valid",
      preview: {
        smartContext: {
          orgUnitId: null,
          badgeTemplateId: null,
          pathwayLabel: null,
          inferredFrom: ["none"],
        },
      },
    });
    expect(prepared.reports[0]?.warnings).toContain(
      "No org-unit or badge-template context matched this row. The record will import without smart-default grouping metadata.",
    );
  });

  it("does not let supplemental artifacts silently import as issuer verified", () => {
    const prepared = prepareLearnerRecordImportBatch({
      rows: [
        {
          rowNumber: 7,
          candidate: {
            learnerEmail: "learner@example.edu",
            title: "Portfolio Reflection",
            recordType: "supplemental_artifact",
            issuedAt: "2026-03-26T12:00:00.000Z",
          },
        },
      ],
      defaults: {
        defaultTrustLevel: "issuer_verified",
      },
      tenantDisplayName: "CredTrail University",
      orgUnits: sampleOrgUnits(),
      badgeTemplates: sampleBadgeTemplates(),
      fileName: "learner-records.csv",
      batchId: "batch_123",
      requestedAt: "2026-03-26T12:00:00.000Z",
    });

    expect(prepared.queuePayloads).toHaveLength(0);
    expect(prepared.reports[0]).toMatchObject({
      status: "invalid",
      errors: ["supplemental_artifact rows must import as learner_supplemental"],
      preview: null,
    });
  });

  it("builds a downloadable CSV template", () => {
    const csv = buildLearnerRecordImportTemplateCsv();

    expect(csv).toContain("learnerEmail,learnerDisplayName,title,recordType,issuedAt");
    expect(csv).toContain("orgUnitUrlKey");
    expect(csv).toContain("badgeTemplateUrlKey");
    expect(csv).not.toContain("orgUnitSlug");
    expect(csv).not.toContain("badgeTemplateSlug");
    expect(csv).toContain("Clinical Placement Seminar");
  });
});
