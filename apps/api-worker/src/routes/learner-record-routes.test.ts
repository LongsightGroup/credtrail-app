import { beforeEach, describe, expect, it, vi } from "vitest";

import type {
  BadgeTemplateRecord,
  ImportLearnerRecordBatchQueueMessageRecord,
  TenantOrgUnitRecord,
} from "@credtrail/db";

const {
  mockedCreateLearnerRecordEntry,
  mockedEnqueueJobQueueMessage,
  mockedEnqueueJobQueueMessageOnce,
  mockedFindTenantById,
  mockedListLearnerRecordEntries,
  mockedListBadgeTemplates,
  mockedListImportLearnerRecordBatchQueueMessages,
  mockedListTenantOrgUnits,
  mockedPatchLearnerRecordEntry,
  mockedFindTenantMembership,
  mockedRetryFailedImportLearnerRecordBatchQueueMessages,
  mockedResolveBetterAuthPrincipal,
  mockedResolveBetterAuthRequestedTenant,
} = vi.hoisted(() => {
  return {
    mockedCreateLearnerRecordEntry: vi.fn(),
    mockedEnqueueJobQueueMessage: vi.fn(),
    mockedEnqueueJobQueueMessageOnce: vi.fn(),
    mockedFindTenantById: vi.fn(),
    mockedListLearnerRecordEntries: vi.fn(),
    mockedListBadgeTemplates: vi.fn(),
    mockedListImportLearnerRecordBatchQueueMessages: vi.fn(),
    mockedListTenantOrgUnits: vi.fn(),
    mockedPatchLearnerRecordEntry: vi.fn(),
    mockedFindTenantMembership: vi.fn(),
    mockedRetryFailedImportLearnerRecordBatchQueueMessages: vi.fn(),
    mockedResolveBetterAuthPrincipal: vi.fn(),
    mockedResolveBetterAuthRequestedTenant: vi.fn(),
  };
});

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    createLearnerRecordEntry: mockedCreateLearnerRecordEntry,
    enqueueJobQueueMessage: mockedEnqueueJobQueueMessage,
    enqueueJobQueueMessageOnce: mockedEnqueueJobQueueMessageOnce,
    findTenantById: mockedFindTenantById,
    listLearnerRecordEntries: mockedListLearnerRecordEntries,
    listBadgeTemplates: mockedListBadgeTemplates,
    listImportLearnerRecordBatchQueueMessages: mockedListImportLearnerRecordBatchQueueMessages,
    listTenantOrgUnits: mockedListTenantOrgUnits,
    patchLearnerRecordEntry: mockedPatchLearnerRecordEntry,
    findTenantMembership: mockedFindTenantMembership,
    retryFailedImportLearnerRecordBatchQueueMessages:
      mockedRetryFailedImportLearnerRecordBatchQueueMessages,
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(() => ({
      prepare: vi.fn(),
    })),
  };
});

vi.mock("../auth/better-auth-adapter", async () => {
  const actual = await vi.importActual<typeof import("../auth/better-auth-adapter")>(
    "../auth/better-auth-adapter",
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

import { app } from "../index";

const createEnv = () => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
    PUBLIC_APP_ORIGIN: "https://credtrail.test",
  };
};

const sampleLearnerRecordEntry = () => {
  return {
    id: "lre_123",
    tenantId: "tenant_123",
    learnerProfileId: "lpr_123",
    trustLevel: "issuer_verified" as const,
    recordType: "course" as const,
    status: "active" as const,
    title: "Intro to Cybersecurity",
    description: "Completed with distinction.",
    issuerName: "CredTrail University",
    issuerUserId: "usr_admin",
    sourceSystem: "credtrail_admin" as const,
    sourceRecordId: null,
    issuedAt: "2026-03-24T15:00:00.000Z",
    revisedAt: null,
    revokedAt: null,
    evidenceLinksJson: '["https://credtrail.example.edu/evidence/intro-cybersecurity/project"]',
    detailsJson: '{"grade":"A"}',
    createdAt: "2026-03-24T15:00:00.000Z",
    updatedAt: "2026-03-24T15:00:00.000Z",
  };
};

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
      createdAt: "2026-03-24T15:00:00.000Z",
      updatedAt: "2026-03-24T15:00:00.000Z",
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
      createdAt: "2026-03-24T15:00:00.000Z",
      updatedAt: "2026-03-24T15:00:00.000Z",
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
      createdAt: "2026-03-24T15:00:00.000Z",
      updatedAt: "2026-03-24T15:00:00.000Z",
    },
  ];
};

const sampleImportQueueMessage = (
  overrides?: Partial<ImportLearnerRecordBatchQueueMessageRecord>,
): ImportLearnerRecordBatchQueueMessageRecord => {
  return {
    id: "job_lr_123",
    tenantId: "tenant_123",
    jobType: "import_learner_record_batch",
    payloadJson:
      '{"batchId":"batch_123","rowNumber":1,"fileName":"learner-records.csv","format":"csv"}',
    idempotencyKey: "learner-record-import:batch_123:1",
    attemptCount: 0,
    maxAttempts: 8,
    availableAt: "2026-03-24T15:00:00.000Z",
    leasedUntil: null,
    leaseToken: null,
    lastError: null,
    completedAt: null,
    failedAt: null,
    status: "pending",
    createdAt: "2026-03-24T15:00:00.000Z",
    updatedAt: "2026-03-24T15:00:00.000Z",
    batchId: "batch_123",
    rowNumber: 1,
    fileName: "learner-records.csv",
    format: "csv",
    defaultTrustLevel: "issuer_verified",
    ...overrides,
  };
};

beforeEach(() => {
  mockedCreateLearnerRecordEntry.mockReset();
  mockedEnqueueJobQueueMessage.mockReset();
  mockedEnqueueJobQueueMessageOnce.mockReset();
  mockedFindTenantById.mockReset();
  mockedListLearnerRecordEntries.mockReset();
  mockedListBadgeTemplates.mockReset();
  mockedListImportLearnerRecordBatchQueueMessages.mockReset();
  mockedListTenantOrgUnits.mockReset();
  mockedPatchLearnerRecordEntry.mockReset();
  mockedFindTenantMembership.mockReset();
  mockedRetryFailedImportLearnerRecordBatchQueueMessages.mockReset();
  mockedResolveBetterAuthPrincipal.mockReset();
  mockedResolveBetterAuthRequestedTenant.mockReset();

  mockedFindTenantMembership.mockResolvedValue({
    tenantId: "tenant_123",
    userId: "usr_admin",
    role: "admin",
    createdAt: "2026-03-24T15:00:00.000Z",
    updatedAt: "2026-03-24T15:00:00.000Z",
  });
  mockedResolveBetterAuthPrincipal.mockResolvedValue({
    userId: "usr_admin",
    authSessionId: "ses_admin",
    authMethod: "better_auth",
    expiresAt: "2026-03-26T15:00:00.000Z",
  });
  mockedResolveBetterAuthRequestedTenant.mockResolvedValue({
    tenantId: "tenant_123",
  });
  mockedCreateLearnerRecordEntry.mockResolvedValue(sampleLearnerRecordEntry());
  mockedEnqueueJobQueueMessage.mockResolvedValue({
    id: "job_lr_123",
    tenantId: "tenant_123",
    jobType: "import_learner_record_batch",
    payloadJson: "{}",
    idempotencyKey: "learner-record-import:batch_123:1",
    attemptCount: 0,
    maxAttempts: 8,
    availableAt: "2026-03-24T15:00:00.000Z",
    leasedUntil: null,
    leaseToken: null,
    lastError: null,
    completedAt: null,
    failedAt: null,
    status: "pending",
    createdAt: "2026-03-24T15:00:00.000Z",
    updatedAt: "2026-03-24T15:00:00.000Z",
  });
  mockedEnqueueJobQueueMessageOnce.mockResolvedValue(true);
  mockedFindTenantById.mockResolvedValue({
    id: "tenant_123",
    slug: "tenant-123",
    displayName: "CredTrail University",
    planTier: "enterprise",
    issuerDomain: "tenant-123.credtrail.test",
    didWeb: "did:web:credtrail.test:tenant-123",
    isActive: true,
    createdAt: "2026-03-24T15:00:00.000Z",
    updatedAt: "2026-03-24T15:00:00.000Z",
  });
  mockedListLearnerRecordEntries.mockResolvedValue([sampleLearnerRecordEntry()]);
  mockedListBadgeTemplates.mockResolvedValue(sampleBadgeTemplates());
  mockedListImportLearnerRecordBatchQueueMessages.mockResolvedValue([]);
  mockedListTenantOrgUnits.mockResolvedValue(sampleOrgUnits());
  mockedPatchLearnerRecordEntry.mockResolvedValue(sampleLearnerRecordEntry());
  mockedRetryFailedImportLearnerRecordBatchQueueMessages.mockResolvedValue({
    matched: 1,
    retried: 1,
    skippedNotFailed: 0,
  });
});

describe("learner-record routes", () => {
  it("allows a tenant admin to create and list learner-record entries", async () => {
    const createResponse = await app.request(
      "/v1/tenants/tenant_123/learner-record-entries",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "content-type": "application/json",
          cookie: "better-auth.session_token=better-auth-test",
        },
        body: JSON.stringify({
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
        }),
      },
      createEnv(),
    );

    expect(createResponse.status).toBe(201);
    expect(await createResponse.json()).toEqual({
      status: "created",
      item: {
        id: "lre_123",
        kind: "record_entry",
        tenantId: "tenant_123",
        learnerProfileId: "lpr_123",
        trustLevel: "issuer_verified",
        status: "active",
        recordType: "course",
        title: "Intro to Cybersecurity",
        description: "Completed with distinction.",
        sourceEntryId: "lre_123",
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
          sourceRecordId: null,
          issuedAt: "2026-03-24T15:00:00.000Z",
          revisedAt: null,
          revokedAt: null,
          evidenceLinks: ["https://credtrail.example.edu/evidence/intro-cybersecurity/project"],
        },
      },
    });
    expect(mockedCreateLearnerRecordEntry).toHaveBeenCalledWith(
      expect.any(Object),
      expect.objectContaining({
        tenantId: "tenant_123",
        learnerProfileId: "lpr_123",
        trustLevel: "issuer_verified",
        recordType: "course",
        title: "Intro to Cybersecurity",
      }),
    );

    const listResponse = await app.request(
      "/v1/tenants/tenant_123/learner-record-entries?learnerProfileId=lpr_123",
      {
        headers: {
          cookie: "better-auth.session_token=better-auth-test",
        },
      },
      createEnv(),
    );

    expect(listResponse.status).toBe(200);
    expect(await listResponse.json()).toEqual({
      tenantId: "tenant_123",
      learnerProfileId: "lpr_123",
      count: 1,
      items: [
        {
          id: "lre_123",
          kind: "record_entry",
          tenantId: "tenant_123",
          learnerProfileId: "lpr_123",
          trustLevel: "issuer_verified",
          status: "active",
          recordType: "course",
          title: "Intro to Cybersecurity",
          description: "Completed with distinction.",
          sourceEntryId: "lre_123",
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
            sourceRecordId: null,
            issuedAt: "2026-03-24T15:00:00.000Z",
            revisedAt: null,
            revokedAt: null,
            evidenceLinks: ["https://credtrail.example.edu/evidence/intro-cybersecurity/project"],
          },
        },
      ],
    });
    expect(mockedListLearnerRecordEntries).toHaveBeenCalledWith(expect.any(Object), {
      tenantId: "tenant_123",
      learnerProfileId: "lpr_123",
      trustLevel: undefined,
      status: undefined,
    });
  });

  it("rejects non-admin access to learner-record management routes", async () => {
    mockedFindTenantMembership.mockResolvedValueOnce({
      tenantId: "tenant_123",
      userId: "usr_viewer",
      role: "viewer",
      createdAt: "2026-03-24T15:00:00.000Z",
      updatedAt: "2026-03-24T15:00:00.000Z",
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/learner-record-entries?learnerProfileId=lpr_123",
      {
        headers: {
          cookie: "better-auth.session_token=better-auth-test",
        },
      },
      createEnv(),
    );

    expect(response.status).toBe(403);
    expect(mockedListLearnerRecordEntries).not.toHaveBeenCalled();
  });

  it("allows updates that preserve the explicit trust and provenance contract", async () => {
    const response = await app.request(
      "/v1/tenants/tenant_123/learner-record-entries/lre_123",
      {
        method: "PATCH",
        headers: {
          Origin: "http://localhost",
          "content-type": "application/json",
          cookie: "better-auth.session_token=better-auth-test",
        },
        body: JSON.stringify({
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
      },
      createEnv(),
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      status: "updated",
      item: {
        id: "lre_123",
        kind: "record_entry",
        tenantId: "tenant_123",
        learnerProfileId: "lpr_123",
        trustLevel: "issuer_verified",
        status: "active",
        recordType: "course",
        title: "Intro to Cybersecurity",
        description: "Completed with distinction.",
        sourceEntryId: "lre_123",
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
          sourceRecordId: null,
          issuedAt: "2026-03-24T15:00:00.000Z",
          revisedAt: null,
          revokedAt: null,
          evidenceLinks: ["https://credtrail.example.edu/evidence/intro-cybersecurity/project"],
        },
      },
    });
    expect(mockedPatchLearnerRecordEntry).toHaveBeenCalledWith(
      expect.any(Object),
      expect.objectContaining({
        tenantId: "tenant_123",
        entryId: "lre_123",
        description: "Completed with distinction and capstone presentation.",
        status: "revoked",
      }),
    );
  });
});

describe("learner-record import routes", () => {
  it("returns a CSV template for issuer-scoped import work", async () => {
    mockedFindTenantMembership.mockResolvedValueOnce({
      tenantId: "tenant_123",
      userId: "usr_issuer",
      role: "issuer",
      createdAt: "2026-03-24T15:00:00.000Z",
      updatedAt: "2026-03-24T15:00:00.000Z",
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/learner-record-imports/template.csv",
      {
        headers: {
          cookie: "better-auth.session_token=better-auth-test",
        },
      },
      createEnv(),
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/csv");
    const body = await response.text();

    expect(body).toContain("learnerEmail,learnerDisplayName,title,recordType,issuedAt");
    expect(body).toContain("badgeTemplateUrlKey");
    expect(body).not.toContain("badgeTemplateSlug");
  });

  it("supports dry-run CSV preview without mutating queue state", async () => {
    mockedFindTenantMembership.mockResolvedValueOnce({
      tenantId: "tenant_123",
      userId: "usr_issuer",
      role: "issuer",
      createdAt: "2026-03-24T15:00:00.000Z",
      updatedAt: "2026-03-24T15:00:00.000Z",
    });
    const formData = new FormData();
    formData.set(
      "file",
      new File(
        [
          [
            "learnerEmail,title,recordType,issuedAt,badgeTemplateUrlKey,pathwayLabel",
            "learner@example.edu,Clinical Placement Seminar,course,2026-03-26T12:00:00.000Z,clinical-placement-badge,Clinical readiness",
          ].join("\n"),
        ],
        "learner-records.csv",
        {
          type: "text/csv",
        },
      ),
    );
    formData.set("defaultTrustLevel", "issuer_verified");

    const response = await app.request(
      "/v1/tenants/tenant_123/learner-record-imports/csv?dryRun=true",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          cookie: "better-auth.session_token=better-auth-test",
        },
        body: formData,
      },
      createEnv(),
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.dryRun).toBe(true);
    expect(body.validRows).toBe(1);
    expect(body.invalidRows).toBe(0);
    expect(body.queuedRows).toBe(0);
    expect(mockedEnqueueJobQueueMessageOnce).not.toHaveBeenCalled();

    const rows = body.rows as Array<Record<string, unknown>>;
    expect(rows[0]?.preview).toEqual(
      expect.objectContaining({
        trustLevel: "issuer_verified",
        smartContext: expect.objectContaining({
          orgUnitId: "tenant_123:org:department-health",
          badgeTemplateId: "badge_template_001",
          pathwayLabel: "Clinical readiness",
        }),
      }),
    );
  });

  it("queues valid learner-record rows on apply and reports truthful upload errors", async () => {
    mockedFindTenantMembership.mockResolvedValueOnce({
      tenantId: "tenant_123",
      userId: "usr_issuer",
      role: "issuer",
      createdAt: "2026-03-24T15:00:00.000Z",
      updatedAt: "2026-03-24T15:00:00.000Z",
    });
    const formData = new FormData();
    formData.set(
      "file",
      new File(
        [
          [
            "learnerEmail,title,recordType,issuedAt",
            "learner@example.edu,Clinical Placement Seminar,course,2026-03-26T12:00:00.000Z",
          ].join("\n"),
        ],
        "learner-records.csv",
        {
          type: "text/csv",
        },
      ),
    );

    const response = await app.request(
      "/v1/tenants/tenant_123/learner-record-imports/csv?dryRun=false",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          cookie: "better-auth.session_token=better-auth-test",
        },
        body: formData,
      },
      createEnv(),
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.dryRun).toBe(false);
    expect(body.queuedRows).toBe(1);
    expect(mockedEnqueueJobQueueMessageOnce).toHaveBeenCalledTimes(1);
    expect(mockedEnqueueJobQueueMessageOnce).toHaveBeenCalledWith(
      expect.any(Object),
      expect.objectContaining({
        tenantId: "tenant_123",
        jobType: "import_learner_record_batch",
      }),
    );

    const invalidResponse = await app.request(
      "/v1/tenants/tenant_123/learner-record-imports/csv?dryRun=false",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "content-type": "application/json",
          cookie: "better-auth.session_token=better-auth-test",
        },
        body: JSON.stringify({}),
      },
      createEnv(),
    );

    expect(invalidResponse.status).toBe(415);
    expect(await invalidResponse.json()).toEqual({
      error: 'Learner-record import requires multipart/form-data with a file field named "file"',
    });
  });

  it("returns progress summaries and targeted retry state for import batches", async () => {
    mockedFindTenantMembership.mockResolvedValueOnce({
      tenantId: "tenant_123",
      userId: "usr_issuer",
      role: "issuer",
      createdAt: "2026-03-24T15:00:00.000Z",
      updatedAt: "2026-03-24T15:00:00.000Z",
    });
    mockedListImportLearnerRecordBatchQueueMessages.mockResolvedValueOnce([
      sampleImportQueueMessage({
        id: "job_lr_1",
        batchId: "batch_progress",
        rowNumber: 1,
        status: "completed",
        completedAt: "2026-03-24T15:05:00.000Z",
      }),
      sampleImportQueueMessage({
        id: "job_lr_2",
        batchId: "batch_progress",
        rowNumber: 2,
        status: "failed",
        lastError: "Learner profile email is invalid",
        failedAt: "2026-03-24T15:06:00.000Z",
        updatedAt: "2026-03-24T15:06:00.000Z",
      }),
    ]);

    const progressResponse = await app.request(
      "/v1/tenants/tenant_123/learner-record-imports/progress?limit=25",
      {
        headers: {
          cookie: "better-auth.session_token=better-auth-test",
        },
      },
      createEnv(),
    );
    const progressBody = await progressResponse.json<Record<string, unknown>>();

    expect(progressResponse.status).toBe(200);
    expect(progressBody.totals).toEqual(
      expect.objectContaining({
        messages: 2,
        batches: 1,
        failedRows: 1,
      }),
    );
    const progressBatches = progressBody.batches as Array<Record<string, unknown>>;
    expect(progressBatches[0]).toEqual(
      expect.objectContaining({
        batchId: "batch_progress",
        failedRows: 1,
        retryableRows: 1,
        latestError: "Learner profile email is invalid",
      }),
    );

    mockedFindTenantMembership.mockResolvedValueOnce({
      tenantId: "tenant_123",
      userId: "usr_issuer",
      role: "issuer",
      createdAt: "2026-03-24T15:00:00.000Z",
      updatedAt: "2026-03-24T15:00:00.000Z",
    });
    mockedListImportLearnerRecordBatchQueueMessages.mockResolvedValueOnce([
      sampleImportQueueMessage({
        id: "job_lr_1",
        batchId: "batch_retry",
        rowNumber: 1,
        status: "pending",
      }),
    ]);

    const retryResponse = await app.request(
      "/v1/tenants/tenant_123/learner-record-imports/batch_retry/retry",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "content-type": "application/json",
          cookie: "better-auth.session_token=better-auth-test",
        },
        body: JSON.stringify({
          rowNumbers: [1],
        }),
      },
      createEnv(),
    );
    const retryBody = await retryResponse.json<Record<string, unknown>>();

    expect(retryResponse.status).toBe(200);
    expect(mockedRetryFailedImportLearnerRecordBatchQueueMessages).toHaveBeenCalledWith(
      expect.any(Object),
      expect.objectContaining({
        tenantId: "tenant_123",
        batchId: "batch_retry",
        rowNumbers: [1],
      }),
    );
    expect(retryBody.retry).toEqual(
      expect.objectContaining({
        retried: 1,
      }),
    );
    expect(retryBody.batch).toEqual(
      expect.objectContaining({
        batchId: "batch_retry",
        pendingRows: 1,
      }),
    );
  });
});
