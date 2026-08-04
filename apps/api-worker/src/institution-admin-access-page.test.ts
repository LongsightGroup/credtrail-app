import { describe, expect, it } from "vitest";
import {
  createEnv,
  fakeDb,
  mockedAddBadgeRuleApproverGroupMemberDb,
  mockedCreateDelegatedIssuingAuthorityGrantDb,
  mockedCreateAuditLogDb,
  mockedFindDelegatedIssuingAuthorityGrantByIdDb,
  mockedCreateBadgeRuleApproverGroupDb,
  mockedFindTenantById,
  mockedListDelegatedIssuingAuthorityGrants,
  mockedListTenantMembershipOrgUnitScopes,
  mockedRemoveBadgeRuleApproverGroupMemberDb,
  mockedRemoveTenantMembershipOrgUnitScopeDb,
  mockedRevokeDelegatedIssuingAuthorityGrantDb,
  mockedResolveBadgeRuleApprovalPolicyDb,
  mockedResolveTenantDefaultBadgeRuleApprovalPolicyDb,
  mockedUpsertTenantMembershipOrgUnitScopeDb,
  mockedUpsertBadgeRuleApprovalPolicyDb,
} from "./institution-admin-page-test-utils";
import { app } from "./index";
import { readScriptAssetSource } from "./page-asset-test-utils";
import { pageAssetPath } from "./ui/page-assets";

const INSTITUTION_ADMIN_ACCESS_JS = readScriptAssetSource("institutionAdminAccessJs");
const INSTITUTION_ADMIN_JS = readScriptAssetSource("institutionAdminJs");

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
    expect(body).toContain("Rule Approval");
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
    expect(body).toContain("Org-unit Access");
    expect(body).toContain("Rule Approval");
    expect(body).toContain("Delegated Authority");
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
  it("renders Rule Approval with approval policy and approver groups only", async () => {
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
    expect(mockedResolveTenantDefaultBadgeRuleApprovalPolicyDb).toHaveBeenCalledWith(
      fakeDb,
      "tenant_123",
    );
    expect(mockedResolveBadgeRuleApprovalPolicyDb).not.toHaveBeenCalled();
    expect(mockedListTenantMembershipOrgUnitScopes).not.toHaveBeenCalled();
    expect(mockedListDelegatedIssuingAuthorityGrants).not.toHaveBeenCalled();
    expect(body).toContain("Rule Approval");
    expect(body).toContain("Set who reviews submitted badge rule versions before activation.");
    expect(body).toContain("Institution policy decides who reviews submitted badge rules");
    expect(body).toContain("Approval governance");
    expect(body).toContain("Approval Policy");
    expect(body).toContain('id="rule-approval-policy-body"');
    expect(body).toContain("Tenant default");
    expect(body).toContain("Approval required");
    expect(body).toContain("Admin role");
    expect(body).toContain("Change policy");
    expect(body).toContain('id="rule-approval-policy-form"');
    expect(body).toContain(
      'action="/tenants/tenant_123/admin/access/governance/rule-approval-policy"',
    );
    expect(body).toContain("Set badge rule approval policy");
    expect(body).toContain("Require approval before activation");
    expect(body).toContain("If one person manages this institution, choose automatic approval");
    expect(body).toContain("Policy scope");
    expect(body).toContain("Reviewer type");
    expect(body).toContain("Named person");
    expect(body).toContain("Approver group");
    expect(body).toContain("Registrar office");
    expect(body).toContain('id="approver-group-form"');
    expect(body).toContain('id="approver-group-member-form"');
    expect(body).toContain('id="approver-group-body"');
    expect(body).toContain('action="/tenants/tenant_123/admin/access/governance/approver-groups"');
    expect(body).toContain(
      'action="/tenants/tenant_123/admin/access/governance/approver-groups/members"',
    );
    expect(body).toContain(
      'action="/tenants/tenant_123/admin/access/governance/approver-groups/members/remove"',
    );
    expect(body).toContain("Submitted badge rule versions require admin approval.");
    expect(body.indexOf('id="rule-approval-policy-body"')).toBeLessThan(
      body.indexOf('id="approver-group-body"'),
    );
    expect(body.indexOf('id="rule-approval-policy-panel"')).toBeLessThan(
      body.indexOf('id="rule-approval-policy-body"'),
    );
    expect(body.indexOf('id="approver-group-panel"')).toBeLessThan(
      body.indexOf('id="approver-group-body"'),
    );
    expect(body).not.toContain('id="membership-scope-form"');
    expect(body).not.toContain('id="membership-scope-panel"');
    expect(body).not.toContain("Current Scoped Roles");
    expect(body).not.toContain(
      'action="/tenants/tenant_123/admin/access/org-unit-access/scopes/remove"',
    );
    expect(body).not.toContain("Current Delegations");
    expect(body).not.toContain('id="delegated-grant-panel"');
    expect(body).not.toContain('href="/tenants/tenant_123/admin/access/delegations/new"');
    expect(body).not.toContain('action="/tenants/tenant_123/admin/access/delegations/revoke"');
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
    expect(body).toContain("Rule Approval");
  });
});

describe("GET /tenants/:tenantId/admin/access/org-unit-access", () => {
  it("renders scoped roles list-first on a dedicated page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/org-unit-access",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Org-unit Access");
    expect(body).toContain("Review standing access grants by org unit");
    expect(body).toContain(
      'href="/tenants/tenant_123/admin/access/org-unit-access" aria-current="page"',
    );
    expect(body).toContain("Current Scoped Roles (1)");
    expect(body).toContain("Add scoped role");
    expect(body).toContain('id="membership-scope-body"');
    expect(body).toContain('id="membership-scope-panel"');
    expect(body).toContain('aria-controls="membership-scope-panel"');
    expect(body).toContain('data-admin-inline-panel-trigger="membership-scope-panel"');
    expect(body).toContain('id="membership-scope-form"');
    expect(body).toContain('action="/tenants/tenant_123/admin/access/org-unit-access/scopes"');
    expect(body).toContain(
      'action="/tenants/tenant_123/admin/access/org-unit-access/scopes/remove"',
    );
    expect(body).toContain("issuer@tenant-123.edu (issuer)");
    expect(body).toContain('name="userId" type="hidden" value="usr_issuer"');
    expect(body.indexOf('id="membership-scope-panel"')).toBeLessThan(
      body.indexOf('id="membership-scope-body"'),
    );
    expect(body).not.toContain("Approval Policy");
    expect(body).not.toContain("Approver Groups");
    expect(body).not.toContain("Current Delegations");
    expect(body).not.toContain('id="delegated-grant-body"');
  });
});

describe("GET /tenants/:tenantId/admin/access/delegations", () => {
  it("renders delegated authority list-first on a dedicated page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/delegations",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Delegated Authority");
    expect(body).toContain("Review temporary badge authority grants");
    expect(body).toContain(
      'href="/tenants/tenant_123/admin/access/delegations" aria-current="page"',
    );
    expect(body).toContain("Current Delegations (1)");
    expect(body).toContain('id="delegated-grant-body"');
    expect(body).toContain('name="grantId" type="hidden" value="dag_123"');
    expect(body).toContain('action="/tenants/tenant_123/admin/access/delegations/revoke"');
    expect(body).toContain('href="/tenants/tenant_123/admin/access/delegations/new"');
    expect(body.indexOf('id="delegated-grant-body"')).toBeLessThan(
      body.indexOf('href="/tenants/tenant_123/admin/access/delegations/new"'),
    );
    expect(body).not.toContain("Approval Policy");
    expect(body).not.toContain("Approver Groups");
    expect(body).not.toContain("Current Scoped Roles");
    expect(body).not.toContain('id="membership-scope-form"');
  });
});

describe("POST /tenants/:tenantId/admin/access/governance/rule-approval-policy", () => {
  it("saves the tenant badge rule approval policy and audits the change", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/governance/rule-approval-policy",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          approvalRequirement: "always",
          requiredRole: "owner",
        }).toString(),
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/tenants/tenant_123/admin/access/governance");
    expect(mockedUpsertBadgeRuleApprovalPolicyDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      orgUnitId: null,
      approvalRequirement: "always",
      allowSelfCertification: false,
      recertificationIntervalMonths: null,
      approvalSteps: [
        {
          requiredRole: "owner",
          label: "Badge rule approval",
        },
      ],
      createdByUserId: "usr_admin",
    });
    expect(mockedCreateAuditLogDb).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        actorUserId: "usr_admin",
        action: "badge_rule.approval_policy_upserted",
        targetType: "badge_rule_approval_policy",
        targetId: "brap_123",
      }),
    );
  });

  it("saves an org-unit approver group badge rule approval policy", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/governance/rule-approval-policy",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          approvalRequirement: "always",
          orgUnitId: "tenant_123:org:institution",
          stepTargetType: "approver_group",
          targetApproverGroupId: "brag_registrar",
          requiredRole: "approver",
        }).toString(),
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(mockedUpsertBadgeRuleApprovalPolicyDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      orgUnitId: "tenant_123:org:institution",
      approvalRequirement: "always",
      allowSelfCertification: false,
      recertificationIntervalMonths: null,
      approvalSteps: [
        {
          targetType: "approver_group",
          targetApproverGroupId: "brag_registrar",
          requiredRole: "approver",
          label: "Approver group review",
        },
      ],
      createdByUserId: "usr_admin",
    });
  });

  it("saves a named-user badge rule approval policy", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/governance/rule-approval-policy",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          approvalRequirement: "always",
          stepTargetType: "user",
          targetUserId: "usr_issuer",
        }).toString(),
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(mockedUpsertBadgeRuleApprovalPolicyDb).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        orgUnitId: null,
        approvalSteps: [
          {
            targetType: "user",
            targetUserId: "usr_issuer",
            requiredRole: null,
            label: "Named approver review",
          },
        ],
      }),
    );
  });

  it("allows institutions to choose automatic approval", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/governance/rule-approval-policy",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          approvalRequirement: "never",
          requiredRole: "admin",
        }).toString(),
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(mockedUpsertBadgeRuleApprovalPolicyDb).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        approvalRequirement: "never",
        approvalSteps: [],
      }),
    );
  });

  it("rejects invalid policy form values without writing policy", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/governance/rule-approval-policy",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          approvalRequirement: "sometimes",
          requiredRole: "admin",
        }).toString(),
        redirect: "manual",
      },
      env,
    );

    const flashCookie = adminFlashCookieHeader(response);
    const followup = await app.request(
      "/tenants/tenant_123/admin/access/governance",
      {
        headers: {
          Cookie: `better-auth.session_token=session-token; ${flashCookie}`,
        },
      },
      env,
    );
    const body = await followup.text();

    expect(response.status).toBe(303);
    expect(mockedUpsertBadgeRuleApprovalPolicyDb).not.toHaveBeenCalled();
    expect(body).toContain("Choose an approval requirement and reviewer before saving.");
  });
});

describe("POST /tenants/:tenantId/admin/access/governance/approver-groups", () => {
  it("creates an approver group", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/governance/approver-groups",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          name: "Registrar office",
          orgUnitId: "tenant_123:org:institution",
        }).toString(),
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(mockedCreateBadgeRuleApproverGroupDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      orgUnitId: "tenant_123:org:institution",
      name: "Registrar office",
      createdByUserId: "usr_admin",
    });
  });

  it("adds and removes approver group members", async () => {
    const env = createEnv();

    const addResponse = await app.request(
      "/tenants/tenant_123/admin/access/governance/approver-groups/members",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          groupId: "brag_registrar",
          userId: "usr_issuer",
        }).toString(),
        redirect: "manual",
      },
      env,
    );
    const removeResponse = await app.request(
      "/tenants/tenant_123/admin/access/governance/approver-groups/members/remove",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          groupId: "brag_registrar",
          userId: "usr_issuer",
        }).toString(),
        redirect: "manual",
      },
      env,
    );

    expect(addResponse.status).toBe(303);
    expect(removeResponse.status).toBe(303);
    expect(mockedAddBadgeRuleApproverGroupMemberDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      groupId: "brag_registrar",
      userId: "usr_issuer",
      createdByUserId: "usr_admin",
    });
    expect(mockedRemoveBadgeRuleApproverGroupMemberDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      groupId: "brag_registrar",
      userId: "usr_issuer",
    });
  });

  it("shows precise approver group member validation failures", async () => {
    const env = createEnv();
    mockedAddBadgeRuleApproverGroupMemberDb.mockResolvedValueOnce({
      status: "membership_not_found",
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/access/governance/approver-groups/members",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          groupId: "brag_registrar",
          userId: "usr_unknown",
        }).toString(),
        redirect: "manual",
      },
      env,
    );
    const flashCookie = adminFlashCookieHeader(response);
    const followup = await app.request(
      "/tenants/tenant_123/admin/access/governance",
      {
        headers: {
          Cookie: `better-auth.session_token=session-token; ${flashCookie}`,
        },
      },
      env,
    );
    const body = await followup.text();

    expect(response.status).toBe(303);
    expect(body).toContain("Choose a tenant member who already belongs to this organization.");
  });
});

describe("POST /tenants/:tenantId/admin/access/org-unit-access/scopes", () => {
  it("saves scoped roles and redirects to Org-unit Access", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/org-unit-access/scopes",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          userId: "usr_issuer",
          orgUnitId: "tenant_123:org:institution",
          role: "issuer",
        }).toString(),
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe(
      "/tenants/tenant_123/admin/access/org-unit-access",
    );
    expect(mockedUpsertTenantMembershipOrgUnitScopeDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      userId: "usr_issuer",
      orgUnitId: "tenant_123:org:institution",
      role: "issuer",
      createdByUserId: "usr_admin",
    });
  });
});

describe("POST /tenants/:tenantId/admin/access/org-unit-access/scopes/remove", () => {
  it("removes scoped roles and redirects to Org-unit Access", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/org-unit-access/scopes/remove",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          userId: "usr_issuer",
          orgUnitId: "tenant_123:org:institution",
        }).toString(),
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe(
      "/tenants/tenant_123/admin/access/org-unit-access",
    );
    expect(mockedRemoveTenantMembershipOrgUnitScopeDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      userId: "usr_issuer",
      orgUnitId: "tenant_123:org:institution",
    });
  });
});

describe("POST /tenants/:tenantId/admin/access/delegations", () => {
  it("creates delegations and redirects to Delegated Authority", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/delegations",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          delegateUserId: "usr_delegate",
          orgUnitId: "tenant_123:org:institution",
          allowedAction: "issue_badge",
          endsAt: "2026-05-18T12:00:00.000Z",
        }).toString(),
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/tenants/tenant_123/admin/access/delegations");
    expect(mockedCreateDelegatedIssuingAuthorityGrantDb).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        delegateUserId: "usr_delegate",
        delegatedByUserId: "usr_admin",
        orgUnitId: "tenant_123:org:institution",
        allowedActions: ["issue_badge"],
      }),
    );
  });
});

describe("POST /tenants/:tenantId/admin/access/delegations/revoke", () => {
  it("revokes delegations and redirects to Delegated Authority", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/delegations/revoke",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          delegateUserId: "usr_delegate",
          grantId: "dag_123",
        }).toString(),
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/tenants/tenant_123/admin/access/delegations");
    expect(mockedFindDelegatedIssuingAuthorityGrantByIdDb).toHaveBeenCalledWith(
      fakeDb,
      "tenant_123",
      "dag_123",
    );
    expect(mockedRevokeDelegatedIssuingAuthorityGrantDb).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        grantId: "dag_123",
        revokedByUserId: "usr_admin",
      }),
    );
  });
});

describe("removed governance mutation routes", () => {
  it("does not keep org-unit scope posts under governance", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/governance/scopes",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          userId: "usr_issuer",
          orgUnitId: "tenant_123:org:institution",
          role: "issuer",
        }).toString(),
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(404);
  });

  it("does not keep delegation posts under governance", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/governance/delegations",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          delegateUserId: "usr_delegate",
          orgUnitId: "tenant_123:org:institution",
          allowedAction: "issue_badge",
          endsAt: "2026-05-18T12:00:00.000Z",
        }).toString(),
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(404);
  });

  it("does not keep the delegated authority setup page under governance", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/governance/delegations/new",
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
    expect(body).toContain('id="tenant-member-panel"');
    expect(body).toContain('class="ct-admin__inline-action-panel"');
    expect(body).toContain('aria-controls="tenant-member-panel"');
    expect(body).toContain('data-admin-inline-panel-trigger="tenant-member-panel"');
    expect(body).toContain("Add member");
    expect(body).not.toContain("Open form");
    expect(body).toContain('id="tenant-member-form"');
    expect(body).toContain('name="email"');
    expect(body).toContain('name="role"');
    expect(body).toContain('name="sendInvite"');
    expect(body).toContain('data-admin-inline-panel-close="tenant-member-panel"');
    expect(body).not.toContain("Hide form");
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
    expect(body).toContain('id="api-key-panel"');
    expect(body).toContain('class="ct-admin__inline-action-panel"');
    expect(body).toContain("New API key");
    expect(body).toContain('aria-controls="api-key-panel"');
    expect(body).toContain('data-admin-inline-panel-trigger="api-key-panel"');
    expect(body).not.toContain("Open form");
    expect(body).not.toContain("Hide form");
    expect(body).toContain('id="api-key-form"');
    expect(body).toContain("Create API key");
    expect(body).toContain('data-admin-inline-panel-close="api-key-panel"');
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
    expect(body).toMatch(
      /class="[^"]*ct-admin__button[^"]*ct-action--secondary[^"]*" href="\/tenants\/tenant_123\/admin\/access\/lms-connections\/new"/,
    );
    expect(body).toMatch(/id="lms-connection-actions"[\s\S]*?class="[^"]*ct-action-group/);
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

describe("GET /tenants/:tenantId/admin/access/delegations/new", () => {
  it("renders the delegated authority setup form on a dedicated page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/delegations/new",
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
    expect(body).toContain(
      'href="/tenants/tenant_123/admin/access/delegations" aria-current="page"',
    );
    expect(body).toContain('href="/tenants/tenant_123/admin/access/governance"');
    expect(body).toContain('id="delegated-grant-form"');
    expect(body).toContain('action="/tenants/tenant_123/admin/access/delegations"');
    expect(body).toContain("admin@tenant-123.edu (admin)");
    expect(body).toContain("issuer@tenant-123.edu (issuer)");
    expect(body).toContain("College of Engineering (college)");
    expect(body).toContain("TypeScript Foundations");
    expect(body).not.toContain("No tenant members available");
    expect(body).not.toContain("No active org units available");
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
    expect(body).toContain('id="org-unit-panel"');
    expect(body).toContain('class="ct-admin__inline-action-panel"');
    expect(body).toContain("New org unit");
    expect(body).toContain('aria-controls="org-unit-panel"');
    expect(body).toContain('data-admin-inline-panel-trigger="org-unit-panel"');
    expect(body).not.toContain("Open form");
    expect(body).not.toContain("Hide form");
    expect(body).toContain('id="org-unit-form"');
    expect(body).toContain("Create org unit");
    expect(body).toContain('data-admin-inline-panel-close="org-unit-panel"');
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
