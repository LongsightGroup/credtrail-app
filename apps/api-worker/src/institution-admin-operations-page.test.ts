import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  createEnv,
  fakeDb,
  fakeDbPrepare,
  mockedCreateLearnerRecordImportPreviewDb,
  mockedEnqueueJobQueueMessageOnce,
  mockedFindActiveLearnerRecordImportPreviewDb,
  mockedFindAssertionById,
  mockedFindBadgeTemplateById,
  mockedListLearnerProfilesForRecordLookupDb,
  mockedListLearnerRecordAssertionExportsDb,
  mockedListLearnerRecordEntriesDb,
  mockedListBadgeIssuanceRuleEvaluations,
  mockedFindBadgeIssuanceRuleVersionByIdDb,
  mockedMarkLearnerRecordImportPreviewQueuedDb,
  sampleLearnerRecordAssertionExport,
} from "./institution-admin-page-test-utils";
import { buildBadgeRuleVersionRecord } from "./test-support/badge-rule-version";

const { mockedIssueBadgeForTenant } = vi.hoisted(() => {
  return {
    mockedIssueBadgeForTenant: vi.fn(),
  };
});

vi.mock("./badges/direct-issue", async () => {
  const actual =
    await vi.importActual<typeof import("./badges/direct-issue")>("./badges/direct-issue");

  return {
    ...actual,
    createIssueBadgeForTenant: vi.fn(() => mockedIssueBadgeForTenant),
  };
});

import { app } from "./index";
import { getSeededDemoLearnerRecordFixture } from "./learner-record/seeded-demo-learner-record-fixture";
import { pageAssetPath } from "./ui/page-assets";

beforeEach(() => {
  mockedIssueBadgeForTenant.mockReset();
});

describe("GET /tenants/:tenantId/admin/operations", () => {
  it("redirects to the issue badge page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/operations",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/tenants/tenant_123/admin/operations/issue");
  });
});

describe("GET /tenants/:tenantId/admin/operations/issue", () => {
  it("renders the manual issue form on a dedicated page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/issue",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Issue Badge");
    expect(body).toContain('id="manual-issue-form"');
    expect(body).toContain('action="/tenants/tenant_123/admin/operations/issue"');
    expect(body).not.toMatch(/Back to /);
    expect(body).not.toContain('id="issued-badges-filter-form"');
    expect(body).toContain(pageAssetPath("institutionAdminShellJs"));
    expect(body).not.toContain(pageAssetPath("institutionAdminJs"));
  });
});

describe("POST /tenants/:tenantId/admin/operations/issue", () => {
  it("redirects successful manual issue posts with public next-step links", async () => {
    const env = createEnv();
    const assertion = sampleLearnerRecordAssertionExport();

    mockedFindBadgeTemplateById.mockResolvedValueOnce({
      id: assertion.badgeTemplateId,
      tenantId: assertion.tenantId,
      slug: "applied-analytics",
      title: assertion.badgeTitle,
      description: assertion.badgeDescription,
      criteriaUri: assertion.badgeCriteriaUri,
      imageUri: assertion.badgeImageUri,
      createdByUserId: "usr_admin",
      ownerOrgUnitId: "tenant_123:org:institution",
      governanceMetadataJson: null,
      isArchived: false,
      createdAt: assertion.createdAt,
      updatedAt: assertion.updatedAt,
    });
    mockedIssueBadgeForTenant.mockResolvedValue({
      status: "issued",
      assertionId: assertion.assertionId,
    });
    mockedFindAssertionById.mockResolvedValueOnce({
      id: assertion.assertionId,
      tenantId: assertion.tenantId,
      publicId: assertion.assertionPublicId,
      learnerProfileId: assertion.learnerProfileId,
      badgeTemplateId: assertion.badgeTemplateId,
      achievementSnapshotStatus: "captured",
      achievementSnapshot: {
        badgeTemplateId: assertion.badgeTemplateId,
        title: assertion.badgeTitle,
        description: assertion.badgeDescription,
        criteriaUri: assertion.badgeCriteriaUri,
        imageUri: assertion.badgeImageUri,
        trustedCredentialMetadataJson: null,
      },
      recipientIdentity: assertion.recipientIdentity,
      recipientIdentityType: assertion.recipientIdentityType,
      vcR2Key: assertion.vcR2Key,
      statusListIndex: assertion.statusListIndex,
      idempotencyKey: assertion.idempotencyKey,
      issuedAt: assertion.issuedAt,
      issuedByUserId: assertion.issuedByUserId,
      revokedAt: assertion.revokedAt,
      createdAt: assertion.createdAt,
      updatedAt: assertion.updatedAt,
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/issue",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          badgeTemplateId: assertion.badgeTemplateId,
          recipientIdentity: assertion.recipientIdentity,
        }).toString(),
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/tenants/tenant_123/admin/operations/issue");

    const setCookieHeaders =
      typeof response.headers.getSetCookie === "function"
        ? response.headers.getSetCookie()
        : [response.headers.get("set-cookie") ?? ""];
    const flashCookie = setCookieHeaders
      .map((entry) => entry.split(";")[0] ?? "")
      .find((entry) => entry.startsWith("ct_admin_flash_list_message_tenant_123="));

    expect(flashCookie).toBeDefined();

    const issuePageResponse = await app.request(
      "/tenants/tenant_123/admin/operations/issue",
      {
        headers: {
          Cookie: `better-auth.session_token=session-token; ${flashCookie ?? ""}`,
        },
      },
      env,
    );
    const body = await issuePageResponse.text();

    expect(issuePageResponse.status).toBe(200);
    expect(body).toContain("Badge issued for learner@example.edu.");
    expect(body).toContain('href="/badges/public_assertion_456"');
    expect(body).toContain('href="/badges/public_assertion_456/verification"');
    expect(body).toContain('href="/badges/public_assertion_456/jsonld"');
    expect(mockedIssueBadgeForTenant).toHaveBeenCalledWith(
      expect.anything(),
      "tenant_123",
      expect.objectContaining({
        achievementSource: expect.objectContaining({
          kind: "template_snapshot",
          snapshot: expect.objectContaining({
            badgeTemplateId: assertion.badgeTemplateId,
          }),
        }),
        recipientIdentity: assertion.recipientIdentity,
        recipientIdentityType: assertion.recipientIdentityType,
      }),
      "usr_admin",
    );
    expect(mockedIssueBadgeForTenant.mock.calls[0]?.[2]).not.toHaveProperty("badgeTemplateId");
  });
});

describe("removed operations route aliases", () => {
  it("does not register the old manual-issue admin post path", async () => {
    const response = await app.request(
      "/tenants/tenant_123/admin/operations/manual-issue",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams().toString(),
      },
      createEnv(),
    );

    expect(response.status).toBe(404);
  });
});

describe("GET /tenants/:tenantId/admin/operations/learner-records", () => {
  it("renders a bounded learner-record review page with truthful idle state", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/learner-records",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Learner Records");
    expect(body).toMatch(/class="[^"]*ct-action-group/);
    expect(body).toContain("Load learner record");
    expect(body).toContain('name="learner"');
    expect(body).toContain("LMS learner ID or email");
    expect(body).not.toContain("Choose one learner");
    expect(body).not.toContain("No learner record found");
  });

  it("renders one learner review with real export and standards-mapping links", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/learner-records?learner=learner-123",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Learner overview");
    expect(body).toContain("Learner One");
    expect(body).toContain("Institution-verified record");
    expect(body).toContain("Learner-supplemental record");
    expect(body).toContain("Historical record");
    expect(body).toContain("Applied Analytics Badge");
    expect(body).toContain("Clinical Placement Seminar");
    expect(body).toContain("Portfolio Reflection");
    expect(body).toContain("Membership Standing");
    expect(body).toContain(
      'href="/v1/tenants/tenant_123/learner-records/lpr_123/export?profile=native_portable_json"',
    );
    expect(body).toContain(
      'href="/v1/tenants/tenant_123/learner-records/lpr_123/standards-mapping?profile=clr_alignment_json"',
    );
    expect(mockedListLearnerProfilesForRecordLookupDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      lookupValue: "learner-123",
    });
  });

  it("opens a learner record by institution email", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/learner-records?learner=ottenhoff%40longsight.com",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Learner overview");
    expect(mockedListLearnerProfilesForRecordLookupDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      lookupValue: "ottenhoff@longsight.com",
    });
  });

  it("can verify a seeded-demo learner review on the normal admin operations route", async () => {
    const seededDemo = getSeededDemoLearnerRecordFixture();

    mockedListLearnerProfilesForRecordLookupDb.mockResolvedValueOnce([seededDemo.learnerProfile]);
    mockedListLearnerRecordAssertionExportsDb.mockResolvedValueOnce([
      ...seededDemo.assertionExports,
    ]);
    mockedListLearnerRecordEntriesDb.mockResolvedValueOnce([...seededDemo.recordEntries]);

    const response = await app.request(
      seededDemo.routeFamily.adminReview,
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      createEnv(),
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Learner overview");
    expect(body).toContain("Applied Analytics Badge");
    expect(body).toContain("Clinical Placement Seminar");
    expect(body).toContain("Portfolio Reflection");
    expect(body).toContain("Leadership Society Membership");
    expect(body).toContain(`href="${seededDemo.routeFamily.nativeExport}"`);
    expect(body).toContain(`href="${seededDemo.routeFamily.standardsMapping}"`);
  });

  it("renders a truthful unresolved state for missing learner lookups", async () => {
    const env = createEnv();
    mockedListLearnerProfilesForRecordLookupDb.mockResolvedValueOnce([]);

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/learner-records?learner=missing%40example.edu",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("No learner record found");
    expect(body).toContain("No learner record matched that LMS learner ID or email address");
  });

  it("does not choose silently when an LMS ID and email match different learners", async () => {
    mockedListLearnerProfilesForRecordLookupDb.mockResolvedValueOnce([
      {
        id: "lpr_lms",
        tenantId: "tenant_123",
        subjectId: "urn:credtrail:learner:tenant_123:lpr_lms",
        displayName: "LMS Learner",
        createdAt: "2026-08-04T10:00:00.000Z",
        updatedAt: "2026-08-04T10:00:00.000Z",
      },
      {
        id: "lpr_email",
        tenantId: "tenant_123",
        subjectId: "urn:credtrail:learner:tenant_123:lpr_email",
        displayName: "Email Learner",
        createdAt: "2026-08-04T10:00:00.000Z",
        updatedAt: "2026-08-04T10:00:00.000Z",
      },
    ]);

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/learner-records?learner=shared%40example.edu",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      createEnv(),
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("More than one learner matched");
    expect(body).not.toContain("Learner overview");
  });
});

describe("GET and POST /tenants/:tenantId/admin/operations/learner-record-imports", () => {
  it("renders a dedicated learner-record import page with template, upload, and progress affordances", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/learner-record-imports",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Learner Record Imports");
    expect(body).toMatch(/class="[^"]*ct-action-group/);
    expect(body).toContain("Download CSV template");
    expect(body).toContain(
      'action="/tenants/tenant_123/admin/operations/learner-record-imports/preview"',
    );
    expect(body).not.toContain(
      'formaction="/tenants/tenant_123/admin/operations/learner-record-imports/apply"',
    );
    expect(body).not.toContain("Queue import");
    expect(body).toContain("Current import progress");
    expect(body).toContain("No learner-record import batches have been queued");
  });

  it("renders preview results with trust and smart-default explanation on the admin page", async () => {
    const env = createEnv();
    const formData = new FormData();
    formData.set(
      "file",
      new File(
        [
          [
            "learnerEmail,title,recordType,issuedAt,badgeTemplateUrlKey,pathwayLabel",
            "learner@example.edu,Clinical Placement Seminar,course,2026-03-26T12:00:00.000Z,applied-analytics,Clinical readiness",
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
      "/tenants/tenant_123/admin/operations/learner-record-imports/preview",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
        },
        body: formData,
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Learner-record import preview ready");
    expect(body).toContain("Clinical Placement Seminar");
    expect(body).toContain("Pathway hint: Clinical readiness");
    expect(body).toContain(
      "Review trust classification, smart defaults, and warnings below before queueing the import.",
    );
    expect(body).toContain('data-learner-record-import-state="preview"');
    expect(body).toContain(
      'action="/tenants/tenant_123/admin/operations/learner-record-imports/apply"',
    );
    expect(body).toContain('name="batchId"');
    expect(body).not.toContain('name="csvPayloadBase64"');
    expect(body).toContain("Queue reviewed import");
    expect(mockedCreateLearnerRecordImportPreviewDb).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        fileName: "learner-records.csv",
        format: "csv",
        createdByUserId: "usr_admin",
      }),
    );
  });

  it("queues learner-record imports only from the reviewed preview payload", async () => {
    const env = createEnv();
    const batchId = "lrib_reviewed";
    const reports = [
      {
        rowNumber: 1,
        status: "valid",
        errors: [],
        warnings: [],
        preview: {
          learner: {
            email: "learner@example.edu",
            displayName: null,
          },
          record: {
            title: "Clinical Placement Seminar",
            recordType: "course",
            issuedAt: "2026-03-26T12:00:00.000Z",
            description: null,
            sourceRecordId: null,
            evidenceLinks: [],
          },
          trustLevel: "issuer_verified",
          issuerName: "Tenant 123",
          sourceSystem: "csv_import",
          smartContext: {
            orgUnitId: null,
            orgUnitLabel: null,
            badgeTemplateId: "badge_template_001",
            badgeTemplateLabel: "TypeScript Foundations",
            pathwayLabel: "Clinical readiness",
            inferredFrom: ["badge_template"],
          },
        },
      },
    ];
    const queuePayloads = [
      {
        batchId,
        rowNumber: 1,
        fileName: "learner-records.csv",
        format: "csv",
        requestedAt: "2026-03-26T12:00:00.000Z",
        requestedByUserId: "usr_admin",
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
          effectiveIssuerName: "Tenant 123",
          smartContext: {
            orgUnitId: null,
            badgeTemplateId: "badge_template_001",
            pathwayLabel: "Clinical readiness",
            inferredFrom: ["badge_template"],
          },
        },
      },
    ];
    const formData = new FormData();
    formData.set("batchId", batchId);
    mockedFindActiveLearnerRecordImportPreviewDb.mockResolvedValueOnce({
      tenantId: "tenant_123",
      batchId,
      fileName: "learner-records.csv",
      format: "csv",
      defaultsJson: JSON.stringify({
        defaultTrustLevel: "issuer_verified",
      }),
      reportsJson: JSON.stringify(reports),
      queuePayloadsJson: JSON.stringify(queuePayloads),
      createdByUserId: "usr_admin",
      createdAt: "2026-03-26T12:00:00.000Z",
      expiresAt: "2026-03-27T12:00:00.000Z",
      queuedAt: null,
    });
    const response = await app.request(
      "/tenants/tenant_123/admin/operations/learner-record-imports/apply",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
        },
        body: formData,
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Learner-record import batch queued");
    expect(body).toContain("Queued 1 valid rows from learner-records.csv");
    expect(body).toContain('data-learner-record-import-state="apply"');
    expect(body).not.toContain("Queue reviewed import");
    expect(mockedEnqueueJobQueueMessageOnce).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        jobType: "import_learner_record_batch",
        idempotencyKey: `learner-record-import:${batchId}:1`,
      }),
    );
    expect(mockedMarkLearnerRecordImportPreviewQueuedDb).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        batchId,
      }),
    );
    expect(
      mockedMarkLearnerRecordImportPreviewQueuedDb.mock.invocationCallOrder[0] ?? 0,
    ).toBeLessThan(mockedEnqueueJobQueueMessageOnce.mock.invocationCallOrder[0] ?? 0);
  });

  it("does not enqueue reviewed learner-record imports when the preview was already claimed", async () => {
    const env = createEnv();
    const batchId = "lrib_already_queued";
    const formData = new FormData();
    formData.set("batchId", batchId);
    mockedFindActiveLearnerRecordImportPreviewDb.mockResolvedValueOnce({
      tenantId: "tenant_123",
      batchId,
      fileName: "learner-records.csv",
      format: "csv",
      defaultsJson: JSON.stringify({
        defaultTrustLevel: "issuer_verified",
      }),
      reportsJson: JSON.stringify([
        {
          rowNumber: 1,
          status: "valid",
          errors: [],
          warnings: [],
          preview: {
            learner: { email: "learner@example.edu", displayName: null },
            record: {
              title: "Clinical Placement Seminar",
              recordType: "course",
              issuedAt: "2026-03-26T12:00:00.000Z",
              description: null,
              sourceRecordId: null,
              evidenceLinks: [],
            },
            trustLevel: "issuer_verified",
            issuerName: "Tenant 123",
            sourceSystem: "csv_import",
            smartContext: {
              orgUnitId: null,
              orgUnitLabel: null,
              badgeTemplateId: null,
              badgeTemplateLabel: null,
              pathwayLabel: null,
              inferredFrom: ["none"],
            },
          },
        },
      ]),
      queuePayloadsJson: JSON.stringify([
        {
          batchId,
          rowNumber: 1,
          fileName: "learner-records.csv",
          format: "csv",
          requestedAt: "2026-03-26T12:00:00.000Z",
          requestedByUserId: "usr_admin",
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
            effectiveIssuerName: "Tenant 123",
            smartContext: {
              orgUnitId: null,
              badgeTemplateId: null,
              pathwayLabel: null,
              inferredFrom: ["none"],
            },
          },
        },
      ]),
      createdByUserId: "usr_admin",
      createdAt: "2026-03-26T12:00:00.000Z",
      expiresAt: "2026-03-27T12:00:00.000Z",
      queuedAt: null,
    });
    mockedMarkLearnerRecordImportPreviewQueuedDb.mockResolvedValueOnce(false);

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/learner-record-imports/apply",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
        },
        body: formData,
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Reviewed preview was already queued");
    expect(mockedEnqueueJobQueueMessageOnce).not.toHaveBeenCalled();
  });

  it("reports queue insertion failures after the reviewed learner-record preview is claimed", async () => {
    const env = createEnv();
    const batchId = "lrib_retryable";
    const reports = [
      {
        rowNumber: 1,
        status: "valid",
        errors: [],
        warnings: [],
        preview: {
          learner: {
            email: "learner@example.edu",
            displayName: null,
          },
          record: {
            title: "Clinical Placement Seminar",
            recordType: "course",
            issuedAt: "2026-03-26T12:00:00.000Z",
            description: null,
            sourceRecordId: null,
            evidenceLinks: [],
          },
          trustLevel: "issuer_verified",
          issuerName: "Tenant 123",
          sourceSystem: "csv_import",
          smartContext: {
            orgUnitId: null,
            orgUnitLabel: null,
            badgeTemplateId: null,
            badgeTemplateLabel: null,
            pathwayLabel: null,
            inferredFrom: ["none"],
          },
        },
      },
    ];
    const queuePayloads = [
      {
        batchId,
        rowNumber: 1,
        fileName: "learner-records.csv",
        format: "csv",
        requestedAt: "2026-03-26T12:00:00.000Z",
        requestedByUserId: "usr_admin",
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
          effectiveIssuerName: "Tenant 123",
          smartContext: {
            orgUnitId: null,
            badgeTemplateId: null,
            pathwayLabel: null,
            inferredFrom: ["none"],
          },
        },
      },
    ];
    const formData = new FormData();
    formData.set("batchId", batchId);
    mockedFindActiveLearnerRecordImportPreviewDb.mockResolvedValueOnce({
      tenantId: "tenant_123",
      batchId,
      fileName: "learner-records.csv",
      format: "csv",
      defaultsJson: JSON.stringify({
        defaultTrustLevel: "issuer_verified",
      }),
      reportsJson: JSON.stringify(reports),
      queuePayloadsJson: JSON.stringify(queuePayloads),
      createdByUserId: "usr_admin",
      createdAt: "2026-03-26T12:00:00.000Z",
      expiresAt: "2026-03-27T12:00:00.000Z",
      queuedAt: null,
    });
    mockedEnqueueJobQueueMessageOnce.mockRejectedValueOnce(new Error("queue unavailable"));

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/learner-record-imports/apply",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
        },
        body: formData,
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Reviewed preview could not be queued");
    expect(body).toContain("Check import progress before trying again");
    expect(mockedMarkLearnerRecordImportPreviewQueuedDb).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        batchId,
      }),
    );
  });

  it("does not queue direct apply uploads before preview review", async () => {
    const env = createEnv();
    const formData = new FormData();
    formData.set(
      "file",
      new File(
        [
          [
            "learnerEmail,title,recordType,issuedAt,badgeTemplateUrlKey,pathwayLabel",
            "learner@example.edu,Clinical Placement Seminar,course,2026-03-26T12:00:00.000Z,applied-analytics,Clinical readiness",
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
      "/tenants/tenant_123/admin/operations/learner-record-imports/apply",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
        },
        body: formData,
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Preview is required before queueing");
    expect(fakeDbPrepare).not.toHaveBeenCalled();
  });
});

describe("GET /tenants/:tenantId/admin/operations/review-queue", () => {
  it("renders the rule review queue on its own page", async () => {
    const env = createEnv();
    mockedListBadgeIssuanceRuleEvaluations.mockResolvedValueOnce([
      {
        id: "bre_123",
        tenantId: "tenant_123",
        ruleId: "brl_123",
        versionId: "brv_123",
        learnerId: "learner_123",
        recipientIdentity: "learner@example.edu",
        recipientIdentityType: "email",
        matched: false,
        issuanceStatus: "review_required",
        assertionId: null,
        evaluationJson: JSON.stringify({
          evaluation: {
            matched: false,
            tree: {
              type: "grade_threshold",
              matched: false,
              resultKind: "missing_data",
              detail: "No grade facts were found for course_101",
            },
          },
        }),
        reviewStatus: "pending",
        reviewDecision: null,
        reviewComment: null,
        reviewedByUserId: null,
        reviewedAt: null,
        evaluatedAt: "2026-02-17T00:00:00.000Z",
        createdAt: "2026-02-17T00:00:00.000Z",
      },
    ]);
    mockedFindBadgeIssuanceRuleVersionByIdDb.mockResolvedValueOnce(
      buildBadgeRuleVersionRecord({
        id: "brv_123",
        ruleId: "brl_123",
        versionNumber: 1,
        status: "active",
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
        changeSummary: "Initial version",
        createdByUserId: "usr_admin",
        submittedByUserId: "usr_admin",
        submittedAt: "2026-02-18T12:05:00.000Z",
        approvedByUserId: "usr_approver",
        approvedAt: "2026-02-18T12:10:00.000Z",
        activatedByUserId: "usr_admin",
        activatedAt: "2026-02-18T12:15:00.000Z",
        snapshot: {
          name: "CS101 Rule",
        },
      }),
    );

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/review-queue",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Rule Review Queue");
    expect(body).toContain(
      "Review pending badge decisions without mixing them into the rest of operations.",
    );
    expect(body).not.toContain('id="rule-review-queue-refresh"');
    expect(body).not.toContain("No review queue entries loaded yet");
    expect(body).toContain('method="post"');
    expect(body).toContain("/tenants/tenant_123/admin/operations/review-queue/resolve");
    expect(body).toContain("learner@example.edu");
    expect(body).toContain("CS101 Rule");
    expect(body).not.toContain("No pending review queue entries.");
    expect(body).not.toContain('id="manual-issue-form"');
    expect(body).not.toContain('id="issued-badges-filter-form"');
    expect(body).not.toContain('id="assertion-lifecycle-view-form"');
    expect(body).toContain(pageAssetPath("institutionAdminShellJs"));
    expect(body).not.toContain(pageAssetPath("institutionAdminJs"));
  });
});

describe("GET /tenants/:tenantId/admin/operations/badge-status", () => {
  it("renders badge status on its own page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/badge-status",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Badge Status");
    expect(body).toContain('id="assertion-lifecycle-view-form"');
    expect(body).not.toContain("Credential Lifecycle");
    expect(body).not.toContain('id="manual-issue-form"');
    expect(body).not.toContain('id="rule-review-queue-refresh"');
    expect(body).not.toContain('id="issued-badges-filter-form"');
  });
});
