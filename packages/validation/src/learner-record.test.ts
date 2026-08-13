import { describe, expect, it } from "vitest";

import {
  parseCreateLearnerRecordEntryRequest,
  learnerRecordImportRowSchema,
  parseLearnerRecordImportBatchDefaults,
  parsePatchLearnerRecordEntryRequest,
} from "./learner-record.js";
import {
  parseAdminLearnerRecordReviewQuery,
  parseLearnerRecordEntryListQuery,
  parseLearnerRecordExportPathParams,
  parseLearnerRecordExportQuery,
  parseLearnerRecordStandardsMappingQuery,
} from "./list-queries.js";
import {
  parseLearnerRecordEntryPathParams,
  parseLearnerRecordImportBatchPathParams,
} from "./path-params.js";
import {
  parseLearnerRecordImportProgressQuery,
  parseLearnerRecordImportRetryRequest,
  parseLearnerRecordImportUploadQuery,
  parseQueueJob,
} from "./queue-migration.js";

describe("learner-record import parsers", () => {
  it("accepts a minimal learner-record import row with bounded batch defaults", () => {
    const row = learnerRecordImportRowSchema.parse({
      learnerEmail: "learner@example.edu",
      title: "Clinical Placement Seminar",
      recordType: "course",
      issuedAt: "2026-03-26T12:00:00.000Z",
    });
    const defaults = parseLearnerRecordImportBatchDefaults({});

    expect(row.learnerEmail).toBe("learner@example.edu");
    expect(defaults.defaultTrustLevel).toBe("issuer_verified");
  });

  it("rejects supplemental artifacts that try to override trust to issuer verified", () => {
    expect(() => {
      learnerRecordImportRowSchema.parse({
        learnerEmail: "learner@example.edu",
        title: "Portfolio Reflection",
        recordType: "supplemental_artifact",
        trustLevel: "issuer_verified",
        issuedAt: "2026-03-26T12:00:00.000Z",
      });
    }).toThrow(/./);
  });

  it("parses learner-record import upload, progress, retry, and batch path inputs", () => {
    const upload = parseLearnerRecordImportUploadQuery({
      dryRun: "false",
    });
    const progress = parseLearnerRecordImportProgressQuery({
      limit: "10",
    });
    const retry = parseLearnerRecordImportRetryRequest({
      rowNumbers: [2, 4, 6],
    });
    const pathParams = parseLearnerRecordImportBatchPathParams({
      tenantId: "tenant_123",
      batchId: "batch_123",
    });

    expect(upload.dryRun).toBe(false);
    expect(progress.limit).toBe(10);
    expect(retry.rowNumbers).toEqual([2, 4, 6]);
    expect(pathParams.batchId).toBe("batch_123");
  });

  it("accepts learner-record import queue jobs", () => {
    const job = parseQueueJob({
      jobType: "import_learner_record_batch",
      tenantId: "tenant_123",
      payload: {
        batchId: "batch_123",
        rowNumber: 1,
        fileName: "learner-records.csv",
        format: "csv",
        requestedAt: "2026-03-26T12:00:00.000Z",
        row: {
          learnerEmail: "learner@example.edu",
          learnerDisplayName: null,
          title: "Clinical Placement Seminar",
          recordType: "course",
          issuedAt: "2026-03-26T12:00:00.000Z",
          description: null,
          sourceRecordId: null,
          evidenceLinks: [],
          effectiveTrustLevel: "issuer_verified",
          effectiveIssuerName: "CredTrail University",
          smartContext: {
            orgUnitId: "tenant_123:org:department-health",
            badgeTemplateId: null,
            pathwayLabel: "Clinical readiness",
            inferredFrom: ["row", "org_unit"],
          },
        },
      },
      idempotencyKey: "idem_import_123",
    });

    expect(job.jobType).toBe("import_learner_record_batch");
  });
});

describe("learner-record parsers", () => {
  it("accepts a valid issuer-verified learner-record entry payload", () => {
    const payload = parseCreateLearnerRecordEntryRequest({
      learnerProfileId: "lpr_123",
      trustLevel: "issuer_verified",
      recordType: "course",
      title: "Intro to Cybersecurity",
      description: "Completed with distinction.",
      status: "active",
      provenance: {
        issuerName: "CredTrail University",
        sourceSystem: "credtrail_admin",
        issuedAt: "2026-03-24T15:00:00.000Z",
        evidenceLinks: ["https://credtrail.example.edu/evidence/intro-cybersecurity/project"],
      },
      details: {
        grade: "A",
      },
    });

    expect(payload.trustLevel).toBe("issuer_verified");
    expect(payload.recordType).toBe("course");
    expect(payload.provenance.evidenceLinks).toHaveLength(1);
  });

  it("rejects ambiguous supplemental trust and revoked-state payloads without provenance", () => {
    expect(() => {
      parseCreateLearnerRecordEntryRequest({
        learnerProfileId: "lpr_123",
        trustLevel: "issuer_verified",
        recordType: "supplemental_artifact",
        title: "Supplemental portfolio",
        provenance: {
          issuerName: "Learner upload",
          sourceSystem: "learner_self_reported",
          issuedAt: "2026-03-24T15:00:00.000Z",
          evidenceLinks: ["https://portfolio.example.edu/work"],
        },
      });
    }).toThrow(/./);

    expect(() => {
      parseCreateLearnerRecordEntryRequest({
        learnerProfileId: "lpr_123",
        trustLevel: "learner_supplemental",
        recordType: "experience",
        title: "Community leadership",
        status: "revoked",
        provenance: {
          issuerName: "Learner self report",
          sourceSystem: "learner_self_reported",
          issuedAt: "2026-03-24T15:00:00.000Z",
          evidenceLinks: [],
        },
      });
    }).toThrow(/./);
  });

  it("parses learner-record path params, filters, and patch payloads", () => {
    expect(
      parseLearnerRecordEntryPathParams({
        tenantId: "tenant_123",
        entryId: "lre_123",
      }),
    ).toEqual({
      tenantId: "tenant_123",
      entryId: "lre_123",
    });

    expect(
      parseLearnerRecordEntryListQuery({
        learnerProfileId: "lpr_123",
        trustLevel: "issuer_verified",
        status: "active",
      }),
    ).toEqual({
      learnerProfileId: "lpr_123",
      trustLevel: "issuer_verified",
      status: "active",
    });

    expect(
      parsePatchLearnerRecordEntryRequest({
        description: "Completed with distinction and capstone presentation.",
        status: "revoked",
        provenance: {
          issuerName: "CredTrail University",
          sourceSystem: "credtrail_admin",
          issuedAt: "2026-03-24T15:00:00.000Z",
          revokedAt: "2026-03-25T15:00:00.000Z",
          evidenceLinks: ["https://credtrail.example.edu/evidence/intro-cybersecurity/project"],
        },
      }),
    ).toEqual({
      description: "Completed with distinction and capstone presentation.",
      status: "revoked",
      provenance: {
        issuerName: "CredTrail University",
        sourceSystem: "credtrail_admin",
        issuedAt: "2026-03-24T15:00:00.000Z",
        revokedAt: "2026-03-25T15:00:00.000Z",
        evidenceLinks: ["https://credtrail.example.edu/evidence/intro-cybersecurity/project"],
      },
    });
  });

  it("parses learner-record export path params and export profiles", () => {
    expect(
      parseLearnerRecordExportPathParams({
        tenantId: "tenant_123",
        learnerProfileId: "lpr_123",
      }),
    ).toEqual({
      tenantId: "tenant_123",
      learnerProfileId: "lpr_123",
    });

    expect(
      parseLearnerRecordExportQuery({
        profile: "clr_alignment_json",
      }),
    ).toEqual({
      profile: "clr_alignment_json",
    });

    expect(parseLearnerRecordStandardsMappingQuery({})).toEqual({
      profile: "clr_alignment_json",
    });
  });

  it("rejects invalid learner-record export profile values", () => {
    expect(() => {
      parseLearnerRecordExportQuery({
        profile: "full_clr_conformance",
      });
    }).toThrow(/./);

    expect(() => {
      parseLearnerRecordStandardsMappingQuery({
        profile: "opaque_vendor_dump",
      });
    }).toThrow(/./);
  });

  it("parses bounded admin learner-record review queries", () => {
    expect(
      parseAdminLearnerRecordReviewQuery({
        learner: "learner-123",
      }),
    ).toEqual({
      learner: "learner-123",
    });

    expect(
      parseAdminLearnerRecordReviewQuery({
        learner: " learner@example.edu ",
      }),
    ).toEqual({
      learner: "learner@example.edu",
    });

    expect(
      parseAdminLearnerRecordReviewQuery({
        learner: " ",
      }),
    ).toEqual({});

    expect(parseAdminLearnerRecordReviewQuery({})).toEqual({});
  });

  it("rejects invalid admin learner-record review queries", () => {
    expect(() => {
      parseAdminLearnerRecordReviewQuery({
        learner: "x".repeat(321),
      });
    }).toThrow(/./);
  });
});
