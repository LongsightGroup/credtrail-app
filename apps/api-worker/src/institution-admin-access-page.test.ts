import { describe, expect, it } from "vitest";
import { createEnv, mockedFindTenantById } from "./institution-admin-page-test-utils";
import { app } from "./index";
import { INSTITUTION_ADMIN_ACCESS_JS } from "./ui/page-assets/content/institution-admin-access-js";
import { INSTITUTION_ADMIN_JS } from "./ui/page-assets/content/institution-admin-js";
import { pageAssetPath } from "./ui/page-assets";

const adminFlashCookieHeader = (response: Response): string => {
  const setCookieHeaders =
    typeof response.headers.getSetCookie === "function"
      ? response.headers.getSetCookie()
      : [response.headers.get("set-cookie") ?? ""];

  return setCookieHeaders.map((entry) => entry.split(";")[0]).join("; ");
};

describe("GET /tenants/:tenantId/admin/access", () => {
  it("does not keep the removed access overview route alive", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    expect(response.status).toBe(404);
  });

  it("renders enterprise auth settings on the authentication page for enterprise tenants", async () => {
    const env = createEnv();
    mockedFindTenantById.mockResolvedValue({
      id: "tenant_123",
      slug: "tenant-123",
      displayName: "Tenant 123",
      planTier: "enterprise",
      issuerDomain: "tenant-123.credtrail.test",
      didWeb: "did:web:credtrail.test:tenant_123",
      isActive: true,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/access/authentication",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Enterprise Auth");
    expect(body).toContain("Login mode");
    expect(body).toContain("Campus OIDC");
    expect(body).toContain("Configure hosted OIDC providers for institution sign-in.");
    expect(body).toContain("Members");
    expect(body).toContain("Governance");
    expect(body).not.toContain('name="enforceForRoles"');
    expect(body).toContain('id="enterprise-auth-policy-form"');
    expect(body).toContain('id="enterprise-auth-provider-form"');
    expect(body).toContain("Break-glass local accounts");
    expect(body).toContain("admin@tenant-123.edu");
    expect(body).toContain('action="/tenants/tenant_123/admin/access/authentication/policy"');
    expect(body).toContain('action="/tenants/tenant_123/admin/access/authentication/providers"');
    expect(body).toContain(
      'action="/tenants/tenant_123/admin/access/authentication/break-glass-accounts"',
    );
    expect(body).toContain('href="/tenants/tenant_123/admin/access/authentication"');
    expect(body).not.toContain("Back to governance");
    expect(body).toContain(pageAssetPath("institutionAdminShellJs"));
    expect(body).toContain(pageAssetPath("institutionAdminAccessJs"));
    expect(body).not.toContain(pageAssetPath("institutionAdminJs"));
  });

  it("shows upgrade guidance without enterprise auth controls for non-enterprise tenants", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/authentication",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Upgrade to the enterprise plan");
    expect(body).not.toContain("Back to members");
    expect(body).not.toContain('id="enterprise-auth-policy-form"');
    expect(body).toContain(pageAssetPath("institutionAdminShellJs"));
    expect(body).not.toContain(pageAssetPath("institutionAdminJs"));
  });
});

describe("GET /tenants/:tenantId/admin/access/governance", () => {
  it("renders governance delegation on its own page with current assignments", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/governance",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Governance Delegation");
    expect(body).toContain("must already exist in this tenant");
    expect(body).toContain('id="membership-scope-form"');
    expect(body).toContain('id="membership-scope-panel"');
    expect(body).toContain('name="userId"');
    expect(body).toContain("issuer@tenant-123.edu (issuer)");
    expect(body).toContain("Scoped Roles");
    expect(body).toContain("Current Scoped Roles (1)");
    expect(body).toContain('action="/tenants/tenant_123/admin/access/governance/scopes/remove"');
    expect(body).toContain('name="userId" value="usr_issuer"');
    expect(body).toContain("Current Delegations (1)");
    expect(body).not.toContain('id="delegated-grant-panel"');
    expect(body).toContain('href="/tenants/tenant_123/admin/access/governance/delegations/new"');
    expect(body).toContain(
      'action="/tenants/tenant_123/admin/access/governance/delegations/revoke"',
    );
    expect(body).toContain('name="grantId" value="dag_123"');
    expect(body.indexOf('id="membership-scope-body"')).toBeLessThan(
      body.indexOf('id="membership-scope-panel"'),
    );
    expect(body.indexOf('id="governance-actions"')).toBeLessThan(
      body.indexOf('id="delegated-grant-body"'),
    );
    expect(body).toMatch(/id="governance-actions"[\s\S]*?class="ct-admin__actions"/);
    expect(body).not.toContain("Tenant member user ID");
    expect(body).not.toContain("Delegate user ID");
    expect(body).not.toContain("Limit to badge template IDs");
    expect(body).not.toContain('id="api-key-form"');
    expect(body).not.toContain('id="org-unit-form"');
    expect(body).not.toContain('id="enterprise-auth-policy-form"');
    expect(body).not.toContain('id="enterprise-auth-provider-form"');
  });

  it("does not keep the legacy enterprise auth page path alive", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/governance/enterprise-auth",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(404);
  });

  it("ignores removed editProvider compatibility query params on governance", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/governance?editProvider=auth_prov_123",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
        redirect: "manual",
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Governance Delegation");
  });
});

describe("GET /tenants/:tenantId/admin/access/members", () => {
  it("renders tenant members on a dedicated page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/members",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Members");
    expect(body).toContain("Add colleagues");
    expect(body).toContain('<details class="ct-admin__panel ct-admin__add-disclosure">');
    expect(body).toContain("Open form");
    expect(body).toContain('id="tenant-member-form"');
    expect(body).toContain('name="email"');
    expect(body).toContain('name="role"');
    expect(body).toContain('name="sendInvite"');
    expect(body).toContain("Hide form");
    expect(body).toContain('action="/tenants/tenant_123/admin/access/members/usr_issuer/role"');
    expect(body).toContain("Resend invite");
    expect(body).toContain(
      'class="ct-admin__panel ct-admin__panel--table ct-admin__members-table ct-stack"',
    );
    expect(body).toContain('action="/tenants/tenant_123/admin/access/members/create"');
    expect(body).toContain("admin@tenant-123.edu");
    expect(body).toContain("issuer@tenant-123.edu");
    expect(body).toContain('action="/tenants/tenant_123/admin/access/members/usr_issuer/invite"');
    expect(body).toContain('action="/tenants/tenant_123/admin/access/members/usr_issuer/remove"');
    expect(body).toContain("Current user");
    expect(body).not.toContain('id="membership-scope-form"');
    expect(body).not.toContain('id="api-key-form"');
    expect(body).not.toContain('id="org-unit-form"');
  });
});

describe("GET /tenants/:tenantId/admin/access/api-keys", () => {
  it("renders API keys on a dedicated page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/api-keys",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("API Keys");
    expect(body).toContain(
      '<details id="api-key-panel" class="ct-admin__panel ct-admin__add-disclosure">',
    );
    expect(body).toContain("Open form");
    expect(body).toContain("Hide form");
    expect(body).toContain('id="api-key-form"');
    expect(body).toContain("Create API key");
    expect(body).toContain('id="api-key-active-count"');
    expect(body).toContain("Active API Keys (1)");
    expect(body).toContain('id="api-key-body"');
    expect(body).toContain(pageAssetPath("institutionAdminShellJs"));
    expect(body).not.toContain(pageAssetPath("institutionAdminJs"));
    expect(body).toContain(pageAssetPath("institutionAdminAccessJs"));
    expect(INSTITUTION_ADMIN_JS).not.toContain("insertApiKeyRow");
    expect(INSTITUTION_ADMIN_ACCESS_JS).toContain("data-confirm-message");
    expect(body).toContain('method="post"');
    expect(body).toContain("/tenants/tenant_123/admin/access/api-keys");
    expect(body).toContain("data-confirm-message");
    expect(body).toContain(
      'class="ct-admin__panel ct-admin__panel--table ct-admin__api-keys-table ct-stack"',
    );
    expect(body).not.toContain('id="org-unit-form"');
    expect(body).not.toContain('id="membership-scope-form"');
  });

  it("creates an API key through the admin form and reveals the secret from a flash cookie", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/api-keys",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          label: "Integration key",
          scopes: "queue.issue, queue.revoke",
        }).toString(),
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    const location = response.headers.get("location") ?? "";
    expect(location).toContain("/tenants/tenant_123/admin/access/api-keys");
    expect(location).not.toContain("apiKeySecret=");
    expect(location).not.toContain("listNotice=");

    const flashCookies = adminFlashCookieHeader(response);
    expect(flashCookies).toContain("ct_admin_flash_api_key_secret_tenant_123");
    expect(flashCookies).toContain("ct_admin_flash_list_message_tenant_123");

    const pageResponse = await app.request(
      location,
      {
        headers: {
          Cookie: `better-auth.session_token=session-token; ${flashCookies}`,
        },
        redirect: "manual",
      },
      env,
    );
    const body = await pageResponse.text();

    expect(pageResponse.status).toBe(200);
    expect(body).toContain('id="api-key-secret"');
    expect(body).toContain("Store this now");
    expect(body).toContain("ctak_");
  });

  it("saves an LMS connection through the admin form and redirects with notice", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/lms-connections",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          displayName: "Sakai QA",
          providerKind: "sakai",
          apiBaseUrl: "https://sakai.example.edu",
          sakaiUsername: "sakai-admin",
          sakaiPassword: "sakai-password",
        }).toString(),
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    const location = response.headers.get("location") ?? "";
    expect(location).toBe("/tenants/tenant_123/admin/access/lms-connections");
    expect(location).not.toContain("listNotice=");

    const flashCookies = adminFlashCookieHeader(response);
    expect(flashCookies).toContain("ct_admin_flash_list_message_tenant_123");
  });

  it("revokes an API key through the admin form and redirects with notice", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/api-keys/tak_123/revoke",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    expect(response.status).toBe(303);
    const location = response.headers.get("location") ?? "";
    expect(location).toBe("/tenants/tenant_123/admin/access/api-keys");
    expect(location).not.toContain("listNotice=");

    const flashCookies = adminFlashCookieHeader(response);
    expect(flashCookies).toContain("ct_admin_flash_list_message_tenant_123");
  });
});

describe("GET /tenants/:tenantId/admin/access/lms-connections", () => {
  it("renders LMS connections with server forms instead of client row patching", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/lms-connections",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("LMS Connections");
    expect(body).not.toContain('id="lms-connection-form"');
    expect(body).toContain('href="/tenants/tenant_123/admin/access/lms-connections/new"');
    expect(body).toContain(
      'class="ct-admin__button ct-admin__button--secondary" href="/tenants/tenant_123/admin/access/lms-connections/new"',
    );
    expect(body).toMatch(/id="lms-connection-actions"[\s\S]*?class="ct-admin__actions"/);
    expect(body).not.toContain("institution-admin-lms-connections.js");
    expect(body).toContain("/tenants/tenant_123/admin/access/lms-connections/lms_canvas/edit");
  });

  it("redirects legacy edit query params to the dedicated edit page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/lms-connections?edit=lms_canvas",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(
      "/tenants/tenant_123/admin/access/lms-connections/lms_canvas/edit",
    );
  });
});

describe("GET /tenants/:tenantId/admin/access/lms-connections/:connectionId/edit", () => {
  it("renders the LMS connection edit form for an existing connection", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/lms-connections/lms_canvas/edit",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Edit LMS Connection");
    expect(body).toContain('id="lms-connection-form"');
    expect(body).toContain('name="connectionId"');
    expect(body).toContain('value="lms_canvas"');
  });

  it("redirects unknown LMS connections back to the list", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/lms-connections/lms_missing/edit",
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
      "/tenants/tenant_123/admin/access/lms-connections",
    );
  });
});

describe("GET /tenants/:tenantId/admin/access/governance/delegations/new", () => {
  it("renders the delegated authority setup form on a dedicated page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/governance/delegations/new",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Add Delegated Authority");
    expect(body).toContain('id="delegated-grant-form"');
    expect(body).toContain('action="/tenants/tenant_123/admin/access/governance/delegations"');
    expect(body).not.toContain("Back to governance");
    expect(body).not.toContain('id="membership-scope-form"');
    expect(body).toContain(pageAssetPath("institutionAdminShellJs"));
    expect(body).not.toContain(pageAssetPath("institutionAdminJs"));
  });
});

describe("POST /tenants/:tenantId/admin/access/governance/enterprise-auth/policy", () => {
  it("does not keep the legacy enterprise auth policy post route alive", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/governance/enterprise-auth/policy",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          loginMode: "oidc_only",
        }).toString(),
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(404);
  });
});

describe("GET /tenants/:tenantId/admin/access/lms-connections/new", () => {
  it("renders the LMS connection setup form on a dedicated page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/lms-connections/new",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Connect LMS");
    expect(body).toContain('id="lms-connection-form"');
    expect(body).toContain('method="post"');
    expect(body).toContain('action="/tenants/tenant_123/admin/access/lms-connections"');
    expect(body).toContain('name="sakaiUsername"');
    expect(body).toContain('name="sakaiPassword"');
    expect(body).toContain("CredTrail creates and refreshes");
  });
});

describe("GET /tenants/:tenantId/admin/access/org-units", () => {
  it("renders org units on a dedicated page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/org-units",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Org Units");
    expect(body).toContain(
      '<details id="org-unit-panel" class="ct-admin__panel ct-admin__add-disclosure">',
    );
    expect(body).toContain("Open form");
    expect(body).toContain("Hide form");
    expect(body).toContain('id="org-unit-form"');
    expect(body).toContain("Create org unit");
    expect(body).not.toContain('name="slug" type="hidden"');
    expect(body).toContain("CredTrail creates the internal org key from the display name.");
    expect(body).not.toContain("<label>ID");
    expect(body).toContain(pageAssetPath("institutionAdminShellJs"));
    expect(body).not.toContain(pageAssetPath("institutionAdminJs"));
    expect(INSTITUTION_ADMIN_JS).not.toContain("deriveUrlKey");
    expect(body).toContain('action="/tenants/tenant_123/admin/access/org-units/create"');
    expect(body).toContain("Org Units (");
    expect(body).toContain(
      'class="ct-admin__panel ct-admin__panel--table ct-admin__org-units-table ct-stack"',
    );
    expect(body).not.toContain('id="api-key-form"');
    expect(body).not.toContain('id="membership-scope-form"');
  });
});
