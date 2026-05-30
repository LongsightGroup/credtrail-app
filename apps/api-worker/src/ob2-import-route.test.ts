import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  mockedResolveBetterAuthPrincipal,
  mockedResolveBetterAuthRequestedTenant,
  mockedFindActiveSessionByHash,
  mockedTouchSession,
} = vi.hoisted(() => {
  return {
    mockedResolveBetterAuthPrincipal: vi.fn(),
    mockedResolveBetterAuthRequestedTenant: vi.fn(),
    mockedFindActiveSessionByHash: vi.fn(),
    mockedTouchSession: vi.fn(),
  };
});

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    enqueueJobQueueMessage: vi.fn(),
    findActiveSessionByHash: mockedFindActiveSessionByHash,
    findLearnerProfileByIdentity: vi.fn(),
    findTenantMembership: vi.fn(),
    listImportMigrationBatchQueueMessages: vi.fn(),
    listBadgeTemplates: vi.fn(),
    retryFailedImportMigrationBatchQueueMessages: vi.fn(),
    touchSession: mockedTouchSession,
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

vi.mock("./auth/better-auth-adapter", async () => {
  const actual = await vi.importActual<typeof import("./auth/better-auth-adapter")>(
    "./auth/better-auth-adapter",
  );

  return {
    ...actual,
    createBetterAuthProvider: vi.fn(() => ({
      requestMagicLink: vi.fn(),
      createMagicLinkSession: vi.fn(),
      createLtiSession: vi.fn(),
      resolveAuthenticatedPrincipal: mockedResolveBetterAuthPrincipal,
      resolveRequestedTenantContext: mockedResolveBetterAuthRequestedTenant,
      revokeCurrentSession: vi.fn(async () => {}),
    })),
  };
});

import {
  enqueueJobQueueMessage,
  findLearnerProfileByIdentity,
  findTenantMembership,
  listImportMigrationBatchQueueMessages,
  listBadgeTemplates,
  retryFailedImportMigrationBatchQueueMessages,
  type BadgeTemplateRecord,
  type ImportMigrationBatchQueueMessageRecord,
  type LearnerProfileRecord,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRecord,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { app } from "./index";

const mockedEnqueueJobQueueMessage = vi.mocked(enqueueJobQueueMessage);
const mockedFindLearnerProfileByIdentity = vi.mocked(findLearnerProfileByIdentity);
const mockedFindTenantMembership = vi.mocked(findTenantMembership);
const mockedListImportMigrationBatchQueueMessages = vi.mocked(
  listImportMigrationBatchQueueMessages,
);
const mockedListBadgeTemplates = vi.mocked(listBadgeTemplates);
const mockedRetryFailedImportMigrationBatchQueueMessages = vi.mocked(
  retryFailedImportMigrationBatchQueueMessages,
);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
  };
};

const sampleSession = (): SessionRecord => {
  return {
    id: "ses_123",
    tenantId: "tenant_123",
    userId: "usr_123",
    sessionTokenHash: "session_hash",
    expiresAt: "2026-03-01T00:00:00.000Z",
    lastSeenAt: "2026-02-14T12:00:00.000Z",
    revokedAt: null,
    createdAt: "2026-02-14T12:00:00.000Z",
  };
};

const sampleMembership = (): TenantMembershipRecord => {
  return {
    tenantId: "tenant_123",
    userId: "usr_123",
    role: "issuer",
    createdAt: "2026-02-14T12:00:00.000Z",
    updatedAt: "2026-02-14T12:00:00.000Z",
  };
};

const sampleTemplate = (overrides?: Partial<BadgeTemplateRecord>): BadgeTemplateRecord => {
  return {
    id: "badge_template_123",
    tenantId: "tenant_123",
    slug: "migration-foundations",
    title: "Migration Foundations",
    description: "Old description",
    criteriaUri: "https://issuer.test/badges/old-criteria",
    imageUri: "https://issuer.test/badges/old-image",
    createdByUserId: "usr_123",
    ownerOrgUnitId: "tenant_123:org:institution",
    governanceMetadataJson: null,
    isArchived: false,
    createdAt: "2026-02-14T12:00:00.000Z",
    updatedAt: "2026-02-14T12:00:00.000Z",
    ...overrides,
  };
};

const sampleLearnerProfile = (): LearnerProfileRecord => {
  return {
    id: "lpr_123",
    tenantId: "tenant_123",
    subjectId: "did:key:z6Mkexample",
    displayName: "Learner",
    createdAt: "2026-02-14T12:00:00.000Z",
    updatedAt: "2026-02-14T12:00:00.000Z",
  };
};

const sampleMigrationQueueMessage = (
  overrides?: Partial<ImportMigrationBatchQueueMessageRecord>,
): ImportMigrationBatchQueueMessageRecord => {
  return {
    id: "job_mig_123",
    tenantId: "tenant_123",
    jobType: "import_migration_batch",
    payloadJson: '{"batchId":"batch_123"}',
    idempotencyKey: "migration-batch:batch_123:1",
    attemptCount: 1,
    maxAttempts: 8,
    availableAt: "2026-02-14T12:00:00.000Z",
    leasedUntil: null,
    leaseToken: null,
    lastError: null,
    completedAt: null,
    failedAt: null,
    status: "pending",
    createdAt: "2026-02-14T12:00:00.000Z",
    updatedAt: "2026-02-14T12:00:00.000Z",
    source: "file_upload",
    batchId: "batch_123",
    rowNumber: 1,
    fileName: "migration.csv",
    format: "csv",
    ...overrides,
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedResolveBetterAuthPrincipal.mockReset();
  mockedResolveBetterAuthPrincipal.mockImplementation(
    async (context: { req: { header(name: string): string | undefined } }) => {
      const cookieHeader = context.req.header("cookie") ?? "";

      if (!cookieHeader.includes("better-auth.session_token=")) {
        return null;
      }

      return {
        userId: "usr_123",
        authSessionId: "ba_ses_123",
        authMethod: "better_auth" as const,
        expiresAt: "2026-03-01T00:00:00.000Z",
      };
    },
  );
  mockedResolveBetterAuthRequestedTenant.mockReset();
  mockedResolveBetterAuthRequestedTenant.mockResolvedValue(null);
  mockedEnqueueJobQueueMessage.mockReset();
  mockedEnqueueJobQueueMessage.mockResolvedValue({
    id: "job_123",
    tenantId: "tenant_123",
    jobType: "import_migration_batch",
    payloadJson: "{}",
    idempotencyKey: "idem_123",
    attemptCount: 0,
    maxAttempts: 8,
    availableAt: "2026-02-14T12:00:00.000Z",
    leasedUntil: null,
    leaseToken: null,
    lastError: null,
    completedAt: null,
    failedAt: null,
    status: "pending",
    createdAt: "2026-02-14T12:00:00.000Z",
    updatedAt: "2026-02-14T12:00:00.000Z",
  });
  mockedFindActiveSessionByHash.mockReset();
  mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
  mockedFindLearnerProfileByIdentity.mockReset();
  mockedFindLearnerProfileByIdentity.mockResolvedValue(null);
  mockedFindTenantMembership.mockReset();
  mockedFindTenantMembership.mockResolvedValue(sampleMembership());
  mockedListImportMigrationBatchQueueMessages.mockReset();
  mockedListImportMigrationBatchQueueMessages.mockResolvedValue([]);
  mockedListBadgeTemplates.mockReset();
  mockedListBadgeTemplates.mockResolvedValue([]);
  mockedRetryFailedImportMigrationBatchQueueMessages.mockReset();
  mockedRetryFailedImportMigrationBatchQueueMessages.mockResolvedValue({
    matched: 0,
    retried: 0,
    skippedNotFailed: 0,
  });
  mockedTouchSession.mockReset();
  mockedTouchSession.mockResolvedValue(undefined);
});

describe("POST /v1/tenants/:tenantId/migrations/ob2/convert", () => {
  it("converts OB2 assertion payloads into normalized import candidates", async () => {
    const env = createEnv();

    const response = await app.request(
      "/v1/tenants/tenant_123/migrations/ob2/convert",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          cookie: "better-auth.session_token=test-session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          ob2Assertion: {
            "@context": "https://w3id.org/openbadges/v2",
            type: "Assertion",
            recipient: {
              type: "email",
              identity: "learner@example.edu",
            },
            badge: {
              type: "BadgeClass",
              id: "https://issuer.test/badges/24",
              name: "Migration Foundations",
              criteria: {
                id: "https://issuer.test/badges/24/criteria",
              },
              image: {
                id: "https://issuer.test/badges/24/image",
              },
              issuer: {
                id: "https://issuer.test/issuers/1",
                name: "Issuer Test",
                url: "https://issuer.test",
              },
            },
            issuedOn: "2025-10-01T12:00:00Z",
          },
        }),
      },
      env,
    );

    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.tenantId).toBe("tenant_123");

    const conversion = body.conversion as Record<string, unknown>;
    expect(conversion).toBeDefined();

    const createBadgeTemplateRequest = conversion.createBadgeTemplateRequest as Record<
      string,
      unknown
    >;
    const manualIssueRequest = conversion.manualIssueRequest as Record<string, unknown>;

    expect(createBadgeTemplateRequest.title).toBe("Migration Foundations");
    expect(manualIssueRequest.recipientIdentity).toBe("learner@example.edu");
    expect(manualIssueRequest.recipientIdentityType).toBe("email");
  });

  it("requires tenant authentication", async () => {
    const env = createEnv();

    const response = await app.request(
      "/v1/tenants/tenant_123/migrations/ob2/convert",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          ob2Assertion: {
            type: "Assertion",
          },
        }),
      },
      env,
    );

    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(401);
    expect(body.error).toBe("Not authenticated");
  });
});

describe("POST /v1/tenants/:tenantId/migrations/ob2/dry-run", () => {
  it("returns dry-run validation report with diff preview for valid payloads", async () => {
    const env = createEnv();
    mockedListBadgeTemplates.mockResolvedValue([
      sampleTemplate({
        slug: "migration-foundations",
      }),
    ]);
    mockedFindLearnerProfileByIdentity.mockResolvedValue(sampleLearnerProfile());

    const response = await app.request(
      "/v1/tenants/tenant_123/migrations/ob2/dry-run",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          cookie: "better-auth.session_token=test-session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          ob2Assertion: {
            "@context": "https://w3id.org/openbadges/v2",
            type: "Assertion",
            recipient: {
              type: "email",
              identity: "learner@example.edu",
            },
            badge: {
              type: "BadgeClass",
              id: "https://issuer.test/badges/24",
              name: "Migration Foundations",
              description: "New description",
              criteria: {
                id: "https://issuer.test/badges/24/criteria",
              },
              image: {
                id: "https://issuer.test/badges/24/image",
              },
              issuer: {
                id: "https://issuer.test/issuers/1",
                name: "Issuer Test",
                url: "https://issuer.test",
              },
            },
            issuedOn: "2025-10-01T12:00:00Z",
          },
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.status).toBe("valid");

    const validationReport = body.validationReport as Record<string, unknown>;
    const diffPreview = validationReport.diffPreview as Record<string, unknown>;
    const badgeTemplate = diffPreview.badgeTemplate as Record<string, unknown>;
    const learnerProfile = diffPreview.learnerProfile as Record<string, unknown>;
    const summary = diffPreview.summary as Record<string, unknown>;

    expect((validationReport.errors as unknown[]).length).toBe(0);
    expect(badgeTemplate.operation).toBe("update");
    expect((badgeTemplate.changedFields as unknown[]).length).toBeGreaterThan(0);
    expect(learnerProfile.operation).toBe("reuse");
    expect(summary.updates).toBe(1);
  });

  it("returns invalid status with parser errors for malformed payload", async () => {
    const env = createEnv();

    const response = await app.request(
      "/v1/tenants/tenant_123/migrations/ob2/dry-run",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          cookie: "better-auth.session_token=test-session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({}),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.status).toBe("invalid");

    const validationReport = body.validationReport as Record<string, unknown>;
    expect((validationReport.errors as unknown[]).length).toBeGreaterThan(0);
    expect(validationReport.diffPreview).toBeNull();
  });
});

describe("POST /v1/tenants/:tenantId/migrations/ob2/batch-upload", () => {
  it("parses uploaded JSON file and returns row validation summaries in dry-run mode", async () => {
    const env = createEnv();
    const formData = new FormData();
    formData.append(
      "file",
      new Blob(
        [
          JSON.stringify([
            {
              ob2Assertion: {
                "@context": "https://w3id.org/openbadges/v2",
                type: "Assertion",
                recipient: {
                  type: "email",
                  identity: "learner@example.edu",
                },
                badge: {
                  type: "BadgeClass",
                  name: "Batch JSON Badge",
                  issuer: {
                    id: "https://issuer.test/issuers/1",
                    name: "Issuer Test",
                    url: "https://issuer.test",
                  },
                },
                issuedOn: "2025-10-01T12:00:00Z",
              },
            },
            {
              ob2Assertion: {
                type: "Assertion",
              },
            },
          ]),
        ],
        {
          type: "application/json",
        },
      ),
      "migration.json",
    );

    const response = await app.request(
      "/v1/tenants/tenant_123/migrations/ob2/batch-upload?dryRun=true",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          cookie: "better-auth.session_token=test-session-token",
        },
        body: formData,
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.dryRun).toBe(true);
    expect(body.totalRows).toBe(2);
    expect(body.validRows).toBe(1);
    expect(body.invalidRows).toBe(1);
    expect(body.queuedRows).toBe(0);
    expect(mockedEnqueueJobQueueMessage).not.toHaveBeenCalled();

    const rows = body.rows as Record<string, unknown>[];
    expect(rows[0]?.status).toBe("valid");
    expect(rows[1]?.status).toBe("invalid");
  });

  it("queues valid rows when dryRun=false for CSV upload", async () => {
    const env = createEnv();
    const formData = new FormData();
    const csvCell = (value: string): string => {
      return `"${value.replaceAll('"', '""')}"`;
    };
    const csvRow = [
      csvCell(
        JSON.stringify({
          type: "Assertion",
          recipient: {
            type: "email",
            identity: "learner@example.edu",
          },
          badge: "https://issuer.test/badges/1",
          issuedOn: "2025-10-01T12:00:00Z",
        }),
      ),
      csvCell(
        JSON.stringify({
          type: "BadgeClass",
          id: "https://issuer.test/badges/1",
          name: "Batch CSV Badge",
          issuer: "https://issuer.test/issuers/1",
        }),
      ),
      csvCell(
        JSON.stringify({
          type: "Issuer",
          id: "https://issuer.test/issuers/1",
          name: "Issuer Test",
          url: "https://issuer.test",
        }),
      ),
    ].join(",");
    const csv = ["ob2Assertion,ob2BadgeClass,ob2Issuer", csvRow].join("\n");
    formData.append(
      "file",
      new Blob([csv], {
        type: "text/csv",
      }),
      "migration.csv",
    );

    const response = await app.request(
      "/v1/tenants/tenant_123/migrations/ob2/batch-upload?dryRun=false",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          cookie: "better-auth.session_token=test-session-token",
        },
        body: formData,
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.dryRun).toBe(false);
    expect(body.totalRows).toBe(1);
    expect(body.validRows).toBe(1);
    expect(body.invalidRows).toBe(0);
    expect(body.queuedRows).toBe(1);
    expect(mockedEnqueueJobQueueMessage).toHaveBeenCalledTimes(1);
    expect(mockedEnqueueJobQueueMessage).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        jobType: "import_migration_batch",
      }),
    );
  });
});

describe("POST /v1/tenants/:tenantId/migrations/credly/ingest", () => {
  it("parses Credly JSON export payloads in dry-run mode", async () => {
    const env = createEnv();
    const formData = new FormData();
    formData.append(
      "file",
      new Blob(
        [
          JSON.stringify({
            data: [
              {
                id: "issued_badge_123",
                issued_to_first_name: "Ada",
                issued_to_last_name: "Lovelace",
                issued_to_email: "ada@example.edu",
                issued_at: "2025-10-01T12:00:00Z",
                badge_template: {
                  id: "template_001",
                  name: "Foundations of AI",
                  description: "Awarded for completing foundations curriculum",
                  image_url: "https://images.credly.example/template_001.png",
                  global_activity_url: "https://issuer.example.edu/badges/foundations-ai",
                },
                issuer: {
                  entities: [
                    {
                      id: "issuer_001",
                      name: "Credly University",
                      url: "https://issuer.example.edu",
                    },
                  ],
                },
              },
            ],
          }),
        ],
        {
          type: "application/json",
        },
      ),
      "credly-issued-badges.json",
    );

    const response = await app.request(
      "/v1/tenants/tenant_123/migrations/credly/ingest?dryRun=true",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          cookie: "better-auth.session_token=test-session-token",
        },
        body: formData,
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.source).toBe("credly_export");
    expect(body.dryRun).toBe(true);
    expect(body.totalRows).toBe(1);
    expect(body.validRows).toBe(1);
    expect(body.invalidRows).toBe(0);
    expect(body.queuedRows).toBe(0);
    expect(mockedEnqueueJobQueueMessage).not.toHaveBeenCalled();
  });

  it("queues valid rows from Credly CSV exports when dryRun=false", async () => {
    const env = createEnv();
    const formData = new FormData();
    const csv = [
      "First Name,Last Name,Recipient Email,Badge Template ID,Issued At",
      "Ada,Lovelace,ada@example.edu,template_001,2025-10-01T12:00:00Z",
    ].join("\n");
    formData.append(
      "file",
      new Blob([csv], {
        type: "text/csv",
      }),
      "credly-export.csv",
    );

    const response = await app.request(
      "/v1/tenants/tenant_123/migrations/credly/ingest?dryRun=false",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          cookie: "better-auth.session_token=test-session-token",
        },
        body: formData,
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.source).toBe("credly_export");
    expect(body.dryRun).toBe(false);
    expect(body.totalRows).toBe(1);
    expect(body.validRows).toBe(1);
    expect(body.invalidRows).toBe(0);
    expect(body.queuedRows).toBe(1);
    expect(mockedEnqueueJobQueueMessage).toHaveBeenCalledTimes(1);
    expect(mockedEnqueueJobQueueMessage).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        jobType: "import_migration_batch",
      }),
    );
    const firstCall = mockedEnqueueJobQueueMessage.mock.calls[0];

    if (firstCall === undefined) {
      throw new Error("Expected queue enqueue call");
    }

    expect(firstCall[1].payload).toEqual(
      expect.objectContaining({
        source: "credly_export",
      }),
    );
  });
});

describe("POST /v1/tenants/:tenantId/migrations/parchment/ingest", () => {
  it("parses Parchment bulk-award CSV payloads in dry-run mode", async () => {
    const env = createEnv();
    const formData = new FormData();
    const csv = [
      "identifier,badge class id,first name,last name,issue date,narrative,evidence url,evidence narrative",
      "ada@example.edu,badge_class_001,Ada,Lovelace,2025-10-01T12:00:00Z,Completed final capstone,https://evidence.example.edu/ada-capstone,Capstone artifact",
    ].join("\n");
    formData.append(
      "file",
      new Blob([csv], {
        type: "text/csv",
      }),
      "parchment-bulk-awards.csv",
    );

    const response = await app.request(
      "/v1/tenants/tenant_123/migrations/parchment/ingest?dryRun=true",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          cookie: "better-auth.session_token=test-session-token",
        },
        body: formData,
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.source).toBe("parchment_export");
    expect(body.dryRun).toBe(true);
    expect(body.totalRows).toBe(1);
    expect(body.validRows).toBe(1);
    expect(body.invalidRows).toBe(0);
    expect(body.queuedRows).toBe(0);
    expect(mockedEnqueueJobQueueMessage).not.toHaveBeenCalled();
  });

  it("queues valid rows from Parchment assertion JSON exports when dryRun=false", async () => {
    const env = createEnv();
    const formData = new FormData();
    formData.append(
      "file",
      new Blob(
        [
          JSON.stringify({
            result: [
              {
                id: "assertion_123",
                recipient: {
                  type: "email",
                  identity: "ada@example.edu",
                },
                issuedOn: "2025-10-01T12:00:00Z",
                badgeclass: {
                  id: "badge_class_001",
                  name: "AI Foundations",
                  issuer: {
                    id: "issuer_001",
                    name: "Example University",
                    url: "https://issuer.example.edu",
                  },
                },
              },
            ],
          }),
        ],
        {
          type: "application/json",
        },
      ),
      "parchment-assertions.json",
    );

    const response = await app.request(
      "/v1/tenants/tenant_123/migrations/parchment/ingest?dryRun=false",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          cookie: "better-auth.session_token=test-session-token",
        },
        body: formData,
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.source).toBe("parchment_export");
    expect(body.dryRun).toBe(false);
    expect(body.totalRows).toBe(1);
    expect(body.validRows).toBe(1);
    expect(body.invalidRows).toBe(0);
    expect(body.queuedRows).toBe(1);
    expect(mockedEnqueueJobQueueMessage).toHaveBeenCalledTimes(1);
    expect(mockedEnqueueJobQueueMessage).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        jobType: "import_migration_batch",
      }),
    );
    const firstCall = mockedEnqueueJobQueueMessage.mock.calls[0];

    if (firstCall === undefined) {
      throw new Error("Expected queue enqueue call");
    }

    expect(firstCall[1].payload).toEqual(
      expect.objectContaining({
        source: "parchment_export",
      }),
    );
  });
});

describe("migration progress dashboard and retry controls", () => {
  it("returns migration batch progress summaries for tenant dashboards", async () => {
    const env = createEnv();
    mockedListImportMigrationBatchQueueMessages.mockResolvedValue([
      sampleMigrationQueueMessage({
        id: "job_mig_1",
        batchId: "batch_abc",
        rowNumber: 1,
        status: "completed",
        completedAt: "2026-02-14T12:05:00.000Z",
      }),
      sampleMigrationQueueMessage({
        id: "job_mig_2",
        batchId: "batch_abc",
        rowNumber: 2,
        status: "failed",
        lastError: "Badge template not found",
        failedAt: "2026-02-14T12:05:30.000Z",
        updatedAt: "2026-02-14T12:05:30.000Z",
      }),
      sampleMigrationQueueMessage({
        id: "job_mig_3",
        source: "credly_export",
        batchId: "batch_xyz",
        rowNumber: 1,
        status: "pending",
      }),
    ]);

    const response = await app.request(
      "/v1/tenants/tenant_123/migrations/progress?source=all&limit=25",
      {
        method: "GET",
        headers: {
          cookie: "better-auth.session_token=test-session-token",
        },
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(mockedListImportMigrationBatchQueueMessages).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        limit: 25,
      }),
    );
    expect(body.tenantId).toBe("tenant_123");

    const totals = body.totals as Record<string, unknown>;
    expect(totals.messages).toBe(3);
    expect(totals.batches).toBe(2);
    expect(totals.failedRows).toBe(1);

    const batches = body.batches as Record<string, unknown>[];
    const uploadBatch = batches.find((batch) => batch.batchId === "batch_abc");
    expect(uploadBatch?.failedRows).toBe(1);
    expect(uploadBatch?.retryableRows).toBe(1);
    expect(uploadBatch?.latestError).toBe("Badge template not found");
  });

  it("retries failed migration batch rows and returns refreshed batch state", async () => {
    const env = createEnv();
    mockedRetryFailedImportMigrationBatchQueueMessages.mockResolvedValue({
      matched: 2,
      retried: 1,
      skippedNotFailed: 1,
    });
    mockedListImportMigrationBatchQueueMessages.mockResolvedValue([
      sampleMigrationQueueMessage({
        id: "job_mig_1",
        batchId: "batch_retry",
        rowNumber: 1,
        status: "pending",
      }),
      sampleMigrationQueueMessage({
        id: "job_mig_2",
        batchId: "batch_retry",
        rowNumber: 2,
        status: "completed",
        completedAt: "2026-02-14T12:10:00.000Z",
      }),
    ]);

    const response = await app.request(
      "/v1/tenants/tenant_123/migrations/batches/batch_retry/retry",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          cookie: "better-auth.session_token=test-session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          source: "file_upload",
          rowNumbers: [1, 2],
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(mockedRetryFailedImportMigrationBatchQueueMessages).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        batchId: "batch_retry",
        source: "file_upload",
        rowNumbers: [1, 2],
      }),
    );

    const retry = body.retry as Record<string, unknown>;
    expect(retry.retried).toBe(1);

    const batch = body.batch as Record<string, unknown>;
    expect(batch.batchId).toBe("batch_retry");
    expect(batch.failedRows).toBe(0);
    expect(batch.pendingRows).toBe(1);
  });

  it("returns 404 when retry target batch does not exist", async () => {
    const env = createEnv();
    mockedRetryFailedImportMigrationBatchQueueMessages.mockResolvedValue({
      matched: 0,
      retried: 0,
      skippedNotFailed: 0,
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/migrations/batches/missing_batch/retry",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          cookie: "better-auth.session_token=test-session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({}),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(404);
    expect(body.error).toBe("Migration batch was not found for tenant");
  });
});
