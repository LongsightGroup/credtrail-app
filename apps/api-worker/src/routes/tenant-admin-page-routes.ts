import type { SqlDatabase, TenantMembershipRole } from "@credtrail/db";
import {
  findTenantById,
  findUserById,
  listAccessibleTenantContextsForUser,
  listBadgeIssuanceRules,
  listBadgeIssuanceRuleVersions,
  listBadgeTemplates,
  listTenantLmsConnections,
} from "@credtrail/db";
import {
  parseBadgeTemplatePathParams,
  parseTenantLmsConnectionPathParams,
  parseTenantPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import { accessAuthenticationPageUrl } from "../admin/access-admin-helpers";
import { buildLmsConnectionEditPath } from "../admin/lms-connection-admin-helpers";
import { institutionAdminRuleBuilderPage } from "../admin/institution-admin-rule-builder-page";
import {
  institutionAdminBadgeStatusPage,
  institutionAdminDashboardPage,
} from "../admin/institution-admin-page";
import {
  loadTenantBadgeRuleValueLists,
  toRuleValueListBuilderContextEntries,
} from "../admin/rule-value-lists-presentation";
import { buildOrganizationsPath } from "../auth/tenant-context-selection";
import { buildLocalTwoFactorPath } from "../auth/break-glass-policy";
import type { AppBindings, AppContext, AppEnv } from "../app";
import type { AppPage } from "../ui/render-page";
import { renderAppPage } from "../ui/render-page";

type InstitutionAdminPageData = Parameters<typeof institutionAdminDashboardPage>[0];

interface RegisterTenantAdminPageRoutesInput {
  app: Hono<AppEnv>;
  ADMIN_ROLES: readonly TenantMembershipRole[];
  adminRoleRequiredPage: (tenantId: string) => AppPage;
  requireTenantRole: (
    c: AppContext,
    tenantId: string,
    allowedRoles: readonly TenantMembershipRole[],
  ) => Promise<
    | {
        session: { userId: string };
        membershipRole: TenantMembershipRole;
      }
    | Response
  >;
  redirectToTenantLogin: (c: AppContext, tenantId: string, nextPath: string) => Response;
  renderInstitutionAdminWorkspace: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
    renderPage: (pageData: InstitutionAdminPageData) => AppPage,
  ) => Promise<Response>;
  renderInstitutionAdminMembersWorkspace: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<Response>;
  renderInstitutionAdminGovernanceWorkspace: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<Response>;
  renderInstitutionAdminGovernanceDelegationNewWorkspace: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<Response>;
  renderInstitutionAdminAuthenticationWorkspace: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<Response>;
  renderInstitutionAdminOrgUnitsWorkspace: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<Response>;
  renderInstitutionAdminApiKeysWorkspace: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<Response>;
  renderInstitutionAdminIssuedBadgesWorkspace: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<Response>;
  renderInstitutionAdminReviewQueueWorkspace: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<Response>;
  renderInstitutionAdminRulesWorkspace: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<Response>;
  renderInstitutionAdminLmsConnectionsWorkspace: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<Response>;
  renderInstitutionAdminLmsConnectionNewWorkspace: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<Response>;
  renderInstitutionAdminLmsConnectionEditWorkspace: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<Response>;
  renderInstitutionAdminManualIssueWorkspace: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<Response>;
  renderInstitutionAdminTemplatesWorkspace: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<Response>;
  renderInstitutionAdminTemplateEditorWorkspace: (
    c: AppContext,
    tenantId: string,
    badgeTemplateId: string,
    nextPath: string,
  ) => Promise<Response>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  resolveInstitutionAdminAdminRole: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<
    | Response
    | {
        session: { userId: string };
        membershipRole: TenantMembershipRole;
      }
  >;
}

export const registerTenantAdminPageRoutes = (input: RegisterTenantAdminPageRoutesInput): void => {
  const {
    app,
    ADMIN_ROLES,
    adminRoleRequiredPage,
    requireTenantRole,
    redirectToTenantLogin,
    renderInstitutionAdminWorkspace,
    renderInstitutionAdminMembersWorkspace,
    renderInstitutionAdminGovernanceWorkspace,
    renderInstitutionAdminGovernanceDelegationNewWorkspace,
    renderInstitutionAdminAuthenticationWorkspace,
    renderInstitutionAdminOrgUnitsWorkspace,
    renderInstitutionAdminApiKeysWorkspace,
    renderInstitutionAdminIssuedBadgesWorkspace,
    renderInstitutionAdminReviewQueueWorkspace,
    renderInstitutionAdminRulesWorkspace,
    renderInstitutionAdminLmsConnectionsWorkspace,
    renderInstitutionAdminLmsConnectionNewWorkspace,
    renderInstitutionAdminLmsConnectionEditWorkspace,
    renderInstitutionAdminManualIssueWorkspace,
    renderInstitutionAdminTemplatesWorkspace,
    renderInstitutionAdminTemplateEditorWorkspace,
    resolveDatabase,
  } = input;

  app.get("/tenants/:tenantId/admin", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin`,
      institutionAdminDashboardPage,
    );
  });

  app.get("/tenants/:tenantId/admin/operations", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return c.redirect(`/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/operations/issue`);
  });

  app.get("/tenants/:tenantId/admin/operations/issue", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminManualIssueWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/operations/issue`,
    );
  });

  app.get("/tenants/:tenantId/admin/operations/review-queue", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminReviewQueueWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/operations/review-queue`,
    );
  });

  app.get("/tenants/:tenantId/admin/operations/issued-badges", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminIssuedBadgesWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/operations/issued-badges`,
    );
  });

  app.get("/tenants/:tenantId/admin/operations/badge-status", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/operations/badge-status`,
      institutionAdminBadgeStatusPage,
    );
  });

  app.get("/tenants/:tenantId/admin/rules", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminRulesWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/rules`,
    );
  });

  app.get("/tenants/:tenantId/admin/rules/templates", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminTemplatesWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/rules/templates`,
    );
  });

  app.get("/tenants/:tenantId/admin/rules/templates/:badgeTemplateId", async (c) => {
    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    return renderInstitutionAdminTemplateEditorWorkspace(
      c,
      pathParams.tenantId,
      pathParams.badgeTemplateId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/rules/templates/${encodeURIComponent(
        pathParams.badgeTemplateId,
      )}`,
    );
  });

  app.get("/tenants/:tenantId/admin/access", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return c.redirect(`/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/members`);
  });

  app.get("/tenants/:tenantId/admin/access/members", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminMembersWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/members`,
    );
  });

  app.get("/tenants/:tenantId/admin/access/governance/enterprise-auth", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return c.redirect(accessAuthenticationPageUrl(pathParams.tenantId), 302);
  });

  app.get("/tenants/:tenantId/admin/access/governance", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const editProviderId = (c.req.query("editProvider") ?? "").trim();

    if (editProviderId.length > 0) {
      return c.redirect(
        accessAuthenticationPageUrl(pathParams.tenantId, {
          editProvider: editProviderId,
        }),
        302,
      );
    }

    return renderInstitutionAdminGovernanceWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/governance`,
    );
  });

  app.get("/tenants/:tenantId/admin/access/governance/delegations/new", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminGovernanceDelegationNewWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/governance/delegations/new`,
    );
  });

  app.get("/tenants/:tenantId/admin/access/authentication", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminAuthenticationWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/authentication`,
    );
  });

  app.get("/tenants/:tenantId/admin/access/api-keys", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminApiKeysWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/api-keys`,
    );
  });

  app.get("/tenants/:tenantId/admin/access/lms-connections/new", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminLmsConnectionNewWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/lms-connections/new`,
    );
  });

  app.get("/tenants/:tenantId/admin/access/lms-connections/:connectionId/edit", async (c) => {
    const pathParams = parseTenantLmsConnectionPathParams(c.req.param());
    return renderInstitutionAdminLmsConnectionEditWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/lms-connections/${encodeURIComponent(pathParams.connectionId)}/edit`,
    );
  });

  app.get("/tenants/:tenantId/admin/access/lms-connections", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const editConnectionId = (c.req.query("edit") ?? "").trim();

    if (editConnectionId.length > 0) {
      return c.redirect(buildLmsConnectionEditPath(pathParams.tenantId, editConnectionId), 302);
    }

    return renderInstitutionAdminLmsConnectionsWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/lms-connections`,
    );
  });

  app.get("/tenants/:tenantId/admin/access/org-units", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminOrgUnitsWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/org-units`,
    );
  });

  app.get("/tenants/:tenantId/admin/rules/new", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      if (roleCheck.status === 401) {
        return redirectToTenantLogin(
          c,
          pathParams.tenantId,
          `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/rules/new`,
        );
      }

      if (roleCheck.status === 423) {
        return c.redirect(
          buildLocalTwoFactorPath({
            tenantId: pathParams.tenantId,
            nextPath: `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/rules/new`,
            setup: true,
            reason: "break_glass_mfa_setup_pending",
          }),
          302,
        );
      }

      if (roleCheck.status === 403) {
        c.header("Cache-Control", "no-store");
        return renderAppPage(c, adminRoleRequiredPage(pathParams.tenantId), 403);
      }

      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const tenant = await findTenantById(db, pathParams.tenantId);

    if (tenant === null) {
      return c.json(
        {
          error: "Tenant not found",
        },
        404,
      );
    }

    const [
      currentUser,
      badgeTemplates,
      badgeRules,
      lmsConnections,
      accessibleTenantContexts,
      valueLists,
    ] = await Promise.all([
      findUserById(db, session.userId),
      listBadgeTemplates(db, {
        tenantId: pathParams.tenantId,
        includeArchived: false,
      }),
      listBadgeIssuanceRules(db, {
        tenantId: pathParams.tenantId,
      }),
      listTenantLmsConnections(db, pathParams.tenantId),
      listAccessibleTenantContextsForUser(db, session.userId),
      loadTenantBadgeRuleValueLists(db, pathParams.tenantId),
    ]);
    const badgeRuleVersionLists = await Promise.all(
      badgeRules.map(async (rule) =>
        listBadgeIssuanceRuleVersions(db, {
          tenantId: pathParams.tenantId,
          ruleId: rule.id,
        }),
      ),
    );
    const badgeRuleVersions = badgeRuleVersionLists.flat();
    const requestUrl = new URL(c.req.url);
    const requestedBadgeTemplateId = (c.req.query("badgeTemplateId") ?? "").trim();
    const selectedBadgeTemplateId = badgeTemplates.some(
      (template) => template.id === requestedBadgeTemplateId,
    )
      ? requestedBadgeTemplateId
      : undefined;
    const switchOrganizationPath =
      accessibleTenantContexts.length > 1
        ? buildOrganizationsPath(`${requestUrl.pathname}${requestUrl.search}`)
        : null;

    c.header("Cache-Control", "no-store");

    return renderAppPage(
      c,
      institutionAdminRuleBuilderPage({
        tenant,
        userId: session.userId,
        ...(currentUser?.email === undefined ? {} : { userEmail: currentUser.email }),
        membershipRole,
        badgeTemplates,
        badgeRules,
        badgeRuleVersions,
        lmsConnections,
        valueLists: toRuleValueListBuilderContextEntries(valueLists),
        ...(selectedBadgeTemplateId === undefined ? {} : { selectedBadgeTemplateId }),
        switchOrganizationPath,
      }),
    );
  });
};
