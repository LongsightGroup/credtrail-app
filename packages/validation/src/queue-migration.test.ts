import { describe, expect, it } from "vitest";

import { parseMigrationBatchPathParams } from "./path-params.js";
import {
  automatedBadgeRuleCommandIdempotencyKey,
  parseMigrationBatchRetryRequest,
  parseMigrationBatchUploadQuery,
  parseMigrationProgressQuery,
  parseOb2ImportConversionRequest,
  parseProcessQueueRequest,
  parseQueueJob,
} from "./queue-migration.js";

const sampleAchievementSnapshot = {
  badgeTemplateId: "badge_template_001",
  title: "TypeScript Foundations",
  description: "Awarded for completing TypeScript fundamentals.",
  criteriaUri: "https://example.edu/criteria/typescript-foundations",
  imageUri: "https://example.edu/badges/typescript-foundations.png",
  trustedCredentialMetadataJson: null,
} as const;

const sampleTemplateAchievementSource = {
  kind: "template_snapshot",
  snapshot: sampleAchievementSnapshot,
  provenance: { source: "programmatic" },
} as const;

describe("parseQueueJob", () => {
  it("accepts a strict migration row payload", () => {
    const job = parseQueueJob({
      jobType: "import_migration_batch",
      tenantId: "tenant_123",
      payload: {
        source: "file_upload",
        batchId: "batch_123",
        rowNumber: 1,
        fileName: "badges.json",
        format: "json",
        requestedAt: "2026-02-10T15:00:00.000Z",
        requestedByUserId: "usr_123",
        conversion: {
          createBadgeTemplateRequest: {
            slug: "migration-foundations",
            title: "Migration Foundations",
            imageUri: "https://issuer.example.edu/badges/migration.png",
          },
          manualIssueRequest: {
            recipientIdentity: "learner@example.edu",
            recipientIdentityType: "email",
          },
          issueOptions: {
            recipientDisplayName: "Learner Example",
            issuerName: "Example University",
            issuerUrl: "https://issuer.example.edu",
          },
          sourceMetadata: {
            assertionId: "https://issuer.example.edu/assertions/123",
            issuedOn: "2026-02-10T14:00:00.000Z",
            evidenceUrls: [],
            recipientHashed: false,
          },
          warnings: [],
        },
      },
      idempotencyKey: "migration-batch:batch_123:1",
    });

    expect(job.jobType).toBe("import_migration_batch");
  });

  it("rejects malformed migration rows and the removed cache job", () => {
    expect(() =>
      parseQueueJob({
        jobType: "import_migration_batch",
        tenantId: "tenant_123",
        payload: { batchId: "batch_123" },
        idempotencyKey: "migration-batch:batch_123:1",
      }),
    ).toThrow("Invalid input");
    expect(() =>
      parseQueueJob({
        jobType: "rebuild_verification_cache",
        tenantId: "tenant_123",
        payload: {},
        idempotencyKey: "cache:tenant_123",
      }),
    ).toThrow("Invalid discriminator value");
  });

  it("accepts a valid issue_badge queue payload", () => {
    const job = parseQueueJob({
      jobType: "issue_badge",
      tenantId: "tenant_123",
      payload: {
        assertionId: "assertion_456",
        achievementSource: sampleTemplateAchievementSource,
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
        achievementSource: sampleTemplateAchievementSource,
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

  it("accepts a connection-scoped LMS learner identity on automated issuance jobs", () => {
    const job = parseQueueJob({
      jobType: "issue_badge",
      tenantId: "tenant_123",
      payload: {
        assertionId: "assertion_456",
        achievementSource: sampleTemplateAchievementSource,
        recipientIdentity: "learner@example.edu",
        recipientIdentityType: "email",
        requestedAt: "2026-02-10T15:00:00.000Z",
        lmsLearnerIdentity: {
          connectionId: "lms_123",
          learnerId: "learner-123",
        },
      },
      idempotencyKey: "idem_lms_abc",
    });

    expect(job.jobType).toBe("issue_badge");

    if (job.jobType !== "issue_badge") {
      throw new Error("Expected issue_badge queue payload");
    }

    expect(job.payload.lmsLearnerIdentity).toEqual({
      connectionId: "lms_123",
      learnerId: "learner-123",
    });
  });

  it("accepts rule-backed issuance without a caller-supplied achievement snapshot", () => {
    const job = parseQueueJob({
      jobType: "issue_badge",
      tenantId: "tenant_123",
      payload: {
        assertionId: "assertion_456",
        recipientIdentity: "learner@example.edu",
        recipientIdentityType: "email",
        achievementSource: {
          kind: "rule_version",
          provenance: {
            source: "rule_evaluate",
            ruleId: "rule_123",
            versionId: "version_456",
            provenanceJson: "{}",
          },
        },
        requestedAt: "2026-02-10T15:00:00.000Z",
      },
      idempotencyKey: "idem_rule_abc",
    });

    expect(job.jobType).toBe("issue_badge");

    if (job.jobType !== "issue_badge") {
      throw new Error("Expected issue_badge queue payload");
    }

    expect(job.payload).not.toHaveProperty("badgeTemplateId");
    expect(job.payload).not.toHaveProperty("achievementSnapshot");
  });

  it("rejects rule-backed issuance carrying parallel mutable achievement fields", () => {
    expect(() =>
      parseQueueJob({
        jobType: "issue_badge",
        tenantId: "tenant_123",
        payload: {
          assertionId: "assertion_456",
          achievementSnapshot: sampleAchievementSnapshot,
          recipientIdentity: "learner@example.edu",
          recipientIdentityType: "email",
          achievementSource: {
            kind: "rule_version",
            provenance: {
              source: "rule_evaluate",
              ruleId: "rule_123",
              versionId: "version_456",
              provenanceJson: "{}",
            },
          },
          requestedAt: "2026-02-10T15:00:00.000Z",
        },
        idempotencyKey: "idem_rule_parallel_fields",
      }),
    ).toThrow("Unrecognized key");
  });

  it("rejects unknown issue job envelope, payload, and nested identity fields", () => {
    expect(() =>
      parseQueueJob({
        jobType: "issue_badge",
        tenantId: "tenant_123",
        payload: {
          assertionId: "assertion_456",
          achievementSource: sampleTemplateAchievementSource,
          recipientIdentity: "learner@example.edu",
          recipientIdentityType: "email",
          requestedAt: "2026-02-10T15:00:00.000Z",
          unexpectedPayloadField: true,
        },
        idempotencyKey: "idem_unknown_payload",
      }),
    ).toThrow("Unrecognized key");

    expect(() =>
      parseQueueJob({
        jobType: "issue_badge",
        tenantId: "tenant_123",
        payload: {
          assertionId: "assertion_456",
          achievementSource: sampleTemplateAchievementSource,
          recipientIdentity: "learner@example.edu",
          recipientIdentityType: "email",
          requestedAt: "2026-02-10T15:00:00.000Z",
          lmsLearnerIdentity: {
            connectionId: "lms_123",
            learnerId: "learner-123",
            unexpectedNestedField: true,
          },
        },
        idempotencyKey: "idem_unknown_nested",
      }),
    ).toThrow("Unrecognized key");

    expect(() =>
      parseQueueJob({
        jobType: "issue_badge",
        tenantId: "tenant_123",
        payload: {
          assertionId: "assertion_456",
          achievementSource: sampleTemplateAchievementSource,
          recipientIdentity: "learner@example.edu",
          recipientIdentityType: "email",
          requestedAt: "2026-02-10T15:00:00.000Z",
        },
        idempotencyKey: "idem_unknown_envelope",
        unexpectedEnvelopeField: true,
      }),
    ).toThrow("Unrecognized key");
  });

  it("rejects an unscoped LMS learner identity on issuance jobs", () => {
    expect(() =>
      parseQueueJob({
        jobType: "issue_badge",
        tenantId: "tenant_123",
        payload: {
          assertionId: "assertion_456",
          achievementSource: sampleTemplateAchievementSource,
          recipientIdentity: "learner@example.edu",
          recipientIdentityType: "email",
          requestedAt: "2026-02-10T15:00:00.000Z",
          lmsLearnerIdentity: {
            learnerId: "learner-123",
          },
        },
        idempotencyKey: "idem_unscoped_lms",
      }),
    ).toThrow(/connectionId/);
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

  it("rejects unknown fields on non-issuance queue jobs", () => {
    expect(() =>
      parseQueueJob({
        jobType: "revoke_badge",
        tenantId: "tenant_123",
        payload: {
          revocationId: "revocation_456",
          assertionId: "assertion_456",
          reason: "Issued in error",
          requestedAt: "2026-02-10T15:00:00.000Z",
          unexpectedPayloadField: true,
        },
        idempotencyKey: "idem_unknown_revoke",
      }),
    ).toThrow("Unrecognized key");
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

  it("accepts a valid badge rule approval notification queue payload", () => {
    const job = parseQueueJob({
      jobType: "send_badge_rule_approval_notification",
      tenantId: "tenant_123",
      payload: {
        notificationType: "approval_decision",
        ruleId: "brl_123",
        versionId: "brv_123",
        decision: "approved",
        comment: null,
        nextStepNumber: null,
      },
      idempotencyKey: "approval-decision-brv_123",
    });

    expect(job.jobType).toBe("send_badge_rule_approval_notification");
  });

  it("accepts a strict automated badge rule queue payload", () => {
    const job = parseQueueJob({
      jobType: "process_automated_badge_rule",
      tenantId: "tenant_123",
      payload: {
        ruleId: "brl_123",
        versionId: "brv_123",
        scheduledFor: "2026-02-10T15:00:00.000Z",
      },
      idempotencyKey: "automated-rule:brl_123:brv_123:hour:2026-02-10T15",
    });

    expect(job.jobType).toBe("process_automated_badge_rule");
  });

  it("keeps production-shaped automated command keys inside the queue contract", () => {
    const versionId = `brv_${"a".repeat(64)}`;
    const commandKeys = [
      automatedBadgeRuleCommandIdempotencyKey({
        versionId,
        command: { kind: "activation" },
      }),
      automatedBadgeRuleCommandIdempotencyKey({
        versionId,
        command: { kind: "hour", scheduledFor: "2026-09-02T18:00:59.000Z" },
      }),
      automatedBadgeRuleCommandIdempotencyKey({
        versionId,
        command: { kind: "expiry", expiresAt: "2026-12-31T23:59:59.000Z" },
      }),
      automatedBadgeRuleCommandIdempotencyKey({
        versionId,
        command: { kind: "manual", requestId: "123e4567-e89b-42d3-a456-426614174000" },
      }),
    ];

    expect(commandKeys.every((key) => key.length <= 128)).toBe(true);

    for (const idempotencyKey of commandKeys) {
      expect(() =>
        parseQueueJob({
          jobType: "process_automated_badge_rule",
          tenantId: "tenant_123",
          payload: {
            ruleId: `brl_${"b".repeat(64)}`,
            versionId,
            scheduledFor: "2026-09-02T18:00:59.000Z",
          },
          idempotencyKey,
        }),
      ).not.toThrow();
    }
  });

  it("rejects the removed placement-bound end-of-term job", () => {
    expect(() =>
      parseQueueJob({
        jobType: "process_end_of_term_badge_rule",
        tenantId: "tenant_123",
        payload: {
          ruleId: "brl_123",
          versionId: "brv_123",
          scheduledFor: "2026-02-10T15:00:00.000Z",
        },
        idempotencyKey: "old-end-of-term-job",
      }),
    ).toThrow(/Invalid discriminator value/);
  });

  it("rejects request-derived URLs in badge rule approval queue payloads", () => {
    expect(() =>
      parseQueueJob({
        jobType: "send_badge_rule_approval_notification",
        tenantId: "tenant_123",
        payload: {
          notificationType: "approval_submitted",
          ruleId: "brl_123",
          versionId: "brv_123",
          reviewUrl: "https://private-worker.example/review",
          targetStepNumber: 1,
        },
        idempotencyKey: "approval-submitted-brv_123",
      }),
    ).toThrow("Unrecognized key");
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
