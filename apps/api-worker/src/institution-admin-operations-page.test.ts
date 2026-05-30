import { describe, expect, it } from "vitest";
import {
  createEnv,
  fakeDb,
  fakeDbPrepare,
  mockedCreateLearnerRecordImportPreviewDb,
  mockedEnqueueJobQueueMessageOnce,
  mockedFindActiveLearnerRecordImportPreviewDb,
  mockedFindAssertionById,
  mockedFindBadgeTemplateById,
  mockedFindLearnerProfileByIdDb,
  mockedFindLearnerProfileByIdentityDb,
  mockedListLearnerRecordAssertionExportsDb,
  mockedListLearnerRecordEntriesDb,
  mockedListTenantAssertions,
  mockedMarkLearnerRecordImportPreviewQueuedDb,
  mockedRecordAssertionLifecycleTransition,
  sampleLearnerRecordAssertionExport,
} from "./institution-admin-page-test-utils";
import { app } from "./index";
import { getSeededDemoLearnerRecordFixture } from "./learner-record/seeded-demo-learner-record-fixture";
import { INSTITUTION_ADMIN_ISSUED_BADGES_JS } from "./ui/page-assets/content/institution-admin-issued-badges-js";
import { INSTITUTION_ADMIN_JS } from "./ui/page-assets/content/institution-admin-js";
import { pageAssetPath } from "./ui/page-assets";

describe("GET /tenants/:tenantId/admin/operations", () => {
  it("renders the operations workspace", async () => {
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
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body).toContain(">Issue &amp; Inspect<");
    expect(body).toContain("Manual Issue Badge");
    expect(body).toContain("Learner Records");
    expect(body).toContain("Learner Record Imports");
    expect(body).toContain('id="manual-issue-form"');
    expect(body).toContain('href="/tenants/tenant_123/admin/operations/learner-records"');
    expect(body).toContain('href="/tenants/tenant_123/admin/operations/learner-record-imports"');
    expect(body).toContain("Review Queue");
    expect(body).toContain("Issued Badges");
    expect(body).toContain("Badge Status");
    expect(body).toContain('href="/tenants/tenant_123/admin/operations/review-queue"');
    expect(body).toContain('href="/tenants/tenant_123/admin/operations/issued-badges"');
    expect(body).toContain('href="/tenants/tenant_123/admin/operations/badge-status"');
    expect(body).not.toContain('id="assertion-lifecycle-view-form"');
    expect(body).not.toContain('id="rule-review-queue-refresh"');
    expect(body).not.toContain('id="issued-badges-filter-form"');
    expect(body).not.toContain("Create Tenant API Key");
    expect(body).not.toContain("Rule Value Lists");
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
    expect(body).toContain("Load learner record");
    expect(body).toContain('name="learnerProfileId"');
    expect(body).toContain('name="email"');
    expect(body).toContain("Choose one learner");
    expect(body).not.toContain("No learner record found");
  });

  it("renders one learner review with real export and standards-mapping links", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/learner-records?learnerProfileId=lpr_123",
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
    expect(mockedFindLearnerProfileByIdDb).toHaveBeenCalledWith(fakeDb, "tenant_123", "lpr_123");
  });

  it("can verify a seeded-demo learner review on the normal admin operations route", async () => {
    const seededDemo = getSeededDemoLearnerRecordFixture();

    mockedFindLearnerProfileByIdDb.mockResolvedValueOnce(seededDemo.learnerProfile);
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
    mockedFindLearnerProfileByIdentityDb.mockResolvedValueOnce(null);

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/learner-records?email=missing%40example.edu",
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
    expect(body).toContain("No learner profile matched this lookup");
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
    expect(body).toContain(">Operations<");
    expect(body).toContain("Rule Review Queue");
    expect(body).toContain('id="rule-review-queue-refresh"');
    expect(body).not.toContain('id="manual-issue-form"');
    expect(body).not.toContain('id="issued-badges-filter-form"');
    expect(body).not.toContain('id="assertion-lifecycle-view-form"');
  });
});

describe("GET /tenants/:tenantId/admin/operations/issued-badges", () => {
  it("renders the issued badges ledger on its own page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/issued-badges",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(mockedListTenantAssertions).not.toHaveBeenCalled();
    expect(response.status).toBe(200);
    expect(body).toContain("Issued Badges");
    expect(body).toContain('id="issued-badges-filter-form"');
    expect(body).toContain('id="issued-badge-lifecycle-panel"');
    expect(body).toContain('id="issued-badge-revoke-form"');
    expect(body).not.toContain("issuedBadgeRowsPath");
    expect(body).toContain('method="get"');
    expect(body).toContain("/tenants/tenant_123/admin/operations/issued-badges");
    expect(body).toContain('method="post"');
    expect(body).toContain("/tenants/tenant_123/admin/operations/issued-badges/revoke");
    expect(body).not.toContain('id="manual-issue-form"');
    expect(body).not.toContain('id="rule-review-queue-refresh"');
    expect(body).not.toContain('id="assertion-lifecycle-view-form"');
    expect(body).toContain(pageAssetPath("institutionAdminShellJs"));
    expect(body).not.toContain(pageAssetPath("institutionAdminJs"));
    expect(body).toContain(pageAssetPath("institutionAdminIssuedBadgesJs"));
    expect(INSTITUTION_ADMIN_JS).not.toContain("openIssuedBadgeLifecyclePanel");
    expect(INSTITUTION_ADMIN_ISSUED_BADGES_JS).not.toContain("loadIssuedBadges");
    expect(INSTITUTION_ADMIN_ISSUED_BADGES_JS).not.toContain("innerHTML");
    expect(INSTITUTION_ADMIN_ISSUED_BADGES_JS).toContain("loadAssertionLifecycle");
  });

  it("loads issued badges only after search filters are submitted", async () => {
    const env = createEnv();

    await app.request(
      "/tenants/tenant_123/admin/operations/issued-badges?recipientQuery=learner@example.edu",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    expect(mockedListTenantAssertions).toHaveBeenCalledTimes(1);
  });

  it("redirects with a list error when issued badge filters are invalid", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/issued-badges?state=not-a-state",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    const location = response.headers.get("location") ?? "";
    expect(location).toContain("listError=");
    expect(mockedListTenantAssertions).not.toHaveBeenCalled();
  });

  it("shows the revoke form only for revoke lifecycle deep links", async () => {
    const env = createEnv();

    const auditResponse = await app.request(
      "/tenants/tenant_123/admin/operations/issued-badges?lifecycle=tenant_123%3Aassertion_456&lifecycleMode=audit",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const auditBody = await auditResponse.text();

    const revokeResponse = await app.request(
      "/tenants/tenant_123/admin/operations/issued-badges?lifecycle=tenant_123%3Aassertion_456&lifecycleMode=revoke",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const revokeBody = await revokeResponse.text();

    expect(auditResponse.status).toBe(200);
    expect(revokeResponse.status).toBe(200);
    expect(auditBody).toMatch(/id="issued-badge-revoke-form"[^>]*hidden/);
    expect(revokeBody).toContain('id="issued-badge-revoke-form"');
    expect(revokeBody).toContain('name="reasonCode"');
    expect(revokeBody).not.toMatch(/id="issued-badge-revoke-form"[^>]*hidden/);
  });

  it("revokes an issued badge through the admin form and redirects with notice", async () => {
    const env = createEnv();
    const assertion = sampleLearnerRecordAssertionExport();

    mockedFindAssertionById.mockResolvedValueOnce({
      id: assertion.assertionId,
      tenantId: assertion.tenantId,
      publicId: assertion.assertionPublicId,
      learnerProfileId: assertion.learnerProfileId,
      badgeTemplateId: assertion.badgeTemplateId,
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

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/issued-badges/revoke",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          assertionId: assertion.assertionId,
          reasonCode: "issuer_requested",
          reason: "Issued in error",
        }).toString(),
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    const location = response.headers.get("location") ?? "";
    expect(location).toContain("listNotice=");
    expect(mockedRecordAssertionLifecycleTransition).toHaveBeenCalled();
  });

  it("renders a separate admin ledger export form with audit filters", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/issued-badges",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('id="issued-badges-export-form"');
    expect(body).toContain('action="/v1/tenants/tenant_123/assertions/ledger-export.csv"');
    expect(body).toContain('method="get"');
    expect(body).toContain('name="issuedFrom" type="date"');
    expect(body).toContain('name="issuedTo" type="date"');
    expect(body).toContain('name="badgeTemplateId"');
    expect(body).toContain('name="orgUnitId"');
    expect(body).toContain('name="state"');
    expect(body).toContain('name="recipientQuery"');
    expect(body).toContain('type="text"');
    expect(body).toContain("Synchronous CSV export is capped at 5000 rows");
    expect(body).toContain("Ancestor lineage columns reflect the current org tree only");
    expect(body).toContain("stable leaf attribution remains the historical contract");
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
