import { describe, expect, it } from "vitest";

import { parseMigrationBatchPathParams } from "./path-params.js";
import {
  parseMigrationBatchRetryRequest,
  parseMigrationBatchUploadQuery,
  parseMigrationProgressQuery,
  parseOb2ImportConversionRequest,
  parseProcessQueueRequest,
  parseQueueJob,
} from "./queue-migration.js";

describe("parseQueueJob", () => {
  it("accepts a valid issue_badge queue payload", () => {
    const job = parseQueueJob({
      jobType: "issue_badge",
      tenantId: "tenant_123",
      payload: {
        assertionId: "assertion_456",
        badgeTemplateId: "badge_template_001",
        recipientIdentity: "learner@example.edu",
        recipientIdentityType: "email",
        requestedAt: "2026-02-10T15:00:00.000Z",
      },
      idempotencyKey: "idem_abc",
    });

    expect(job.jobType).toBe("issue_badge");
  });

  it("accepts issue_badge queue payload with recipient identifiers", () => {
    const job = parseQueueJob({
      jobType: "issue_badge",
      tenantId: "tenant_123",
      payload: {
        assertionId: "assertion_456",
        badgeTemplateId: "badge_template_001",
        recipientIdentity: "learner@example.edu",
        recipientIdentityType: "email",
        recipientIdentifiers: [
          {
            identifierType: "emailAddress",
            identifier: "learner@example.edu",
          },
          {
            identifierType: "studentId",
            identifier: "student-123",
          },
        ],
        recipientDisplayName: "Learner Example",
        issuerImageUri: "https://issuer.example.edu/logo.svg",
        requestedAt: "2026-02-10T15:00:00.000Z",
      },
      idempotencyKey: "idem_abc",
    });

    expect(job.jobType).toBe("issue_badge");

    if (job.jobType !== "issue_badge") {
      throw new Error("Expected issue_badge queue payload");
    }

    expect(job.payload.recipientIdentifiers).toHaveLength(2);
    expect(job.payload.recipientDisplayName).toBe("Learner Example");
    expect(job.payload.issuerImageUri).toBe("https://issuer.example.edu/logo.svg");
  });

  it("accepts a valid revoke_badge queue payload", () => {
    const job = parseQueueJob({
      jobType: "revoke_badge",
      tenantId: "tenant_123",
      payload: {
        revocationId: "revocation_456",
        assertionId: "assertion_456",
        reason: "Issued in error",
        requestedAt: "2026-02-10T15:00:00.000Z",
      },
      idempotencyKey: "idem_def",
    });

    expect(job.jobType).toBe("revoke_badge");
  });

  it("accepts a valid generate_badge_template_image queue payload", () => {
    const job = parseQueueJob({
      jobType: "generate_badge_template_image",
      tenantId: "tenant_123",
      payload: {
        generationId: "btig_123",
        badgeTemplateId: "badge_template_001",
        promptText: "Create a square badge image.",
        stylePreset: "institutional",
        requestedAt: "2026-02-10T15:00:00.000Z",
        requestedByUserId: "usr_admin",
      },
      idempotencyKey: "btig_123",
    });

    expect(job.jobType).toBe("generate_badge_template_image");
  });

  it("rejects malformed queue jobs", () => {
    expect(() => {
      parseQueueJob({
        tenantId: "tenant_123",
      });
    }).toThrow(/./);
  });
});

describe("process queue request parser", () => {
  it("accepts an empty payload", () => {
    const request = parseProcessQueueRequest({});
    expect(request.limit).toBeUndefined();
  });

  it("accepts bounded queue processor settings", () => {
    const request = parseProcessQueueRequest({
      limit: 25,
      leaseSeconds: 30,
      retryDelaySeconds: 120,
    });

    expect(request.limit).toBe(25);
    expect(request.leaseSeconds).toBe(30);
    expect(request.retryDelaySeconds).toBe(120);
  });

  it("rejects invalid queue processor settings", () => {
    expect(() => {
      parseProcessQueueRequest({
        limit: 0,
      });
    }).toThrow(/./);
  });
});

describe("OB2 import conversion parser", () => {
  it("accepts OB2 assertion JSON payload", () => {
    const request = parseOb2ImportConversionRequest({
      ob2Assertion: {
        "@context": "https://w3id.org/openbadges/v2",
        type: "Assertion",
        recipient: {
          type: "email",
          identity: "learner@example.edu",
        },
        badge: {
          type: "BadgeClass",
          name: "Intro Badge",
        },
      },
    });

    expect(request.ob2Assertion?.type).toBe("Assertion");
  });

  it("accepts bakedBadgeImage payloads without assertion JSON", () => {
    const request = parseOb2ImportConversionRequest({
      bakedBadgeImage: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB",
    });

    expect(request.bakedBadgeImage).toContain("iVBOR");
  });

  it("rejects payloads without an assertion source", () => {
    expect(() => {
      parseOb2ImportConversionRequest({});
    }).toThrow(/./);
  });
});

describe("migration batch upload query parser", () => {
  it("defaults dryRun to true", () => {
    const query = parseMigrationBatchUploadQuery({});
    expect(query.dryRun).toBe(true);
  });

  it("parses explicit dryRun false", () => {
    const query = parseMigrationBatchUploadQuery({
      dryRun: "false",
    });
    expect(query.dryRun).toBe(false);
  });

  it("rejects invalid dryRun values", () => {
    expect(() => {
      parseMigrationBatchUploadQuery({
        dryRun: "nope",
      });
    }).toThrow(/./);
  });
});

describe("migration progress parser", () => {
  it("defaults progress query values", () => {
    const query = parseMigrationProgressQuery({});
    expect(query.source).toBe("all");
    expect(query.limit).toBe(50);
  });

  it("parses source and limit filters", () => {
    const query = parseMigrationProgressQuery({
      source: "credly_export",
      limit: "25",
    });
    expect(query.source).toBe("credly_export");
    expect(query.limit).toBe(25);
  });

  it("parses parchment export source filters", () => {
    const query = parseMigrationProgressQuery({
      source: "parchment_export",
      limit: "10",
    });

    expect(query.source).toBe("parchment_export");
    expect(query.limit).toBe(10);
  });

  it("rejects invalid source filters", () => {
    expect(() => {
      parseMigrationProgressQuery({
        source: "legacy_csv",
      });
    }).toThrow(/./);
  });

  it("parses migration batch path params", () => {
    const params = parseMigrationBatchPathParams({
      tenantId: "tenant_123",
      batchId: "cc8f1dc6-ff06-4f4f-b915-c0de703ff5e0",
    });

    expect(params.batchId).toContain("cc8f");
  });

  it("parses retry payload row filters", () => {
    const request = parseMigrationBatchRetryRequest({
      source: "parchment_export",
      rowNumbers: [1, 2, 3],
    });

    expect(request.source).toBe("parchment_export");
    expect(request.rowNumbers).toEqual([1, 2, 3]);
  });
});
