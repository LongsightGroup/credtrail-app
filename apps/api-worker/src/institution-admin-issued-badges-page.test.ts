import { describe, expect, it } from "vitest";
import {
  createEnv,
  fakeDb,
  mockedFindAssertionById,
  mockedFindBadgeTemplateById,
  mockedListTenantAssertions,
  mockedRecordAssertionLifecycleTransition,
  sampleLearnerRecordAssertionExport,
  sampleTenantAssertionSummary,
} from "./institution-admin-page-test-utils";
import { app } from "./index";
import { INSTITUTION_ADMIN_ISSUED_BADGES_JS } from "./ui/page-assets/content/institution-admin-issued-badges-js";
import { INSTITUTION_ADMIN_JS } from "./ui/page-assets/content/institution-admin-js";
import { pageAssetPath } from "./ui/page-assets";

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
    expect(body).toContain("Badge Records");
    expect(body).toContain('id="issued-badges-filter-form"');
    expect(body).toContain('name="issuedFrom" type="date"');
    expect(body).toContain('name="issuedTo" type="date"');
    expect(body).toContain('name="orgUnitId"');
    expect(body).toContain('id="issued-badge-lifecycle-panel"');
    expect(body).toContain('id="issued-badge-revoke-form"');
    expect(body).not.toContain("issuedBadgeRowsPath");
    expect(body).not.toContain('id="issued-badges-export-form"');
    expect(body).not.toContain("Ledger export");
    expect(body).not.toContain("Export matching CSV");
    expect(body).not.toContain("pending_review");
    expect(body).toContain("Use the search form above to load issued badges.");
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

  it("loads all issued badges when the default search form is submitted", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/issued-badges?issuedFrom=&issuedTo=&recipientQuery=&badgeTemplateId=&orgUnitId=&state=&limit=100",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    expect(response.status).toBe(200);
    expect(mockedListTenantAssertions).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      limit: 100,
    });
  });

  it("applies shared badge record filters and exports matching rows from the same query", async () => {
    const env = createEnv();

    mockedListTenantAssertions.mockResolvedValueOnce([sampleTenantAssertionSummary()]);

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/issued-badges?issuedFrom=2026-03-01&issuedTo=2026-03-31&recipientQuery=learner&badgeTemplateId=badge_template_001&orgUnitId=tenant_123%3Aorg%3Adepartment-cs&state=active&limit=25",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(mockedListTenantAssertions).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      issuedFrom: "2026-03-01",
      issuedTo: "2026-03-31",
      badgeTemplateId: "badge_template_001",
      orgUnitId: "tenant_123:org:department-cs",
      recipientQuery: "learner",
      state: "active",
      limit: 25,
    });
    expect(body).toContain("Export matching CSV");
    expect(body).toContain(
      'href="/v1/tenants/tenant_123/assertions/ledger-export.csv?issuedFrom=2026-03-01&amp;issuedTo=2026-03-31&amp;badgeTemplateId=badge_template_001&amp;orgUnitId=tenant_123%3Aorg%3Adepartment-cs&amp;state=active&amp;recipientQuery=learner"',
    );
    expect(body).not.toContain(
      'href="/v1/tenants/tenant_123/assertions/ledger-export.csv?issuedFrom=2026-03-01&amp;issuedTo=2026-03-31&amp;badgeTemplateId=badge_template_001&amp;orgUnitId=tenant_123%3Aorg%3Adepartment-cs&amp;state=active&amp;recipientQuery=learner&amp;limit=25"',
    );
    expect(body).toContain("Direct CSV export is capped at 5000 rows");
    expect(body).not.toContain('id="issued-badges-export-form"');
    expect(body).not.toContain("Ledger export");
  });

  it("does not show the matching export action when search returns no rows", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/issued-badges?recipientQuery=missing@example.edu",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(mockedListTenantAssertions).toHaveBeenCalledTimes(1);
    expect(body).toContain("No assertions matched the selected filters.");
    expect(body).not.toContain("Export matching CSV");
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
    expect(location).toBe("/tenants/tenant_123/admin/operations/issued-badges");
    expect(location).not.toContain("listError=");

    const setCookieHeaders =
      typeof response.headers.getSetCookie === "function"
        ? response.headers.getSetCookie()
        : [response.headers.get("set-cookie") ?? ""];
    const flashCookies = setCookieHeaders.map((entry) => entry.split(";")[0]).join("; ");
    expect(flashCookies).toContain("ct_admin_flash_list_message_tenant_123");
    expect(mockedListTenantAssertions).not.toHaveBeenCalled();

    const pageResponse = await app.request(
      location,
      {
        headers: {
          Cookie: `better-auth.session_token=session-token; ${flashCookies}`,
        },
      },
      env,
    );
    const body = await pageResponse.text();

    expect(pageResponse.status).toBe(200);
    expect(body).toContain("Invalid search filters");
  });

  it("redirects with a list error when issued badge date filters are invalid", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/issued-badges?issuedFrom=2026-03-31&issuedTo=2026-03-01&limit=100",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe(
      "/tenants/tenant_123/admin/operations/issued-badges",
    );
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
    expect(location).toContain("/tenants/tenant_123/admin/operations/issued-badges");
    expect(location).not.toContain("listNotice=");

    const setCookieHeaders =
      typeof response.headers.getSetCookie === "function"
        ? response.headers.getSetCookie()
        : [response.headers.get("set-cookie") ?? ""];
    const flashCookies = setCookieHeaders.map((entry) => entry.split(";")[0]).join("; ");
    expect(flashCookies).toContain("ct_admin_flash_list_message_tenant_123");
    expect(mockedRecordAssertionLifecycleTransition).toHaveBeenCalled();
  });

  it("keeps ledger export controls unified with the badge records search", async () => {
    const env = createEnv();

    mockedListTenantAssertions.mockResolvedValueOnce([sampleTenantAssertionSummary()]);

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/issued-badges?recipientQuery=learner@example.edu",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).not.toContain('id="issued-badges-export-form"');
    expect(body).not.toContain("Export ledger CSV");
    expect(body).not.toContain("Ancestor lineage columns reflect the current org tree only");
    expect(body).toContain("Export matching CSV");
  });
});
