import type { SqlDatabase, TenantMembershipRole } from "@credtrail/db";
import {
  findBadgeTemplateById,
  findTenantById,
  findUserById,
  listAccessibleTenantContextsForUser,
  listBadgeIssuanceRules,
  listBadgeIssuanceRuleVersions,
  listBadgeTemplates,
  listTenantLmsConnections,
} from "@credtrail/db";
import { parseBadgeTemplatePathParams, parseTenantPathParams } from "@credtrail/validation";
import type { Hono } from "hono";
import { renderBadgeTemplateAdminTableRowToString } from "../admin/badge-template-table-row-fragment";
import {
  badgeTemplateHistoryHref,
  parseBadgeTemplateListPageQuery,
} from "../admin/badge-template-admin-helpers";
import { institutionAdminRuleBuilderPage } from "../admin/institution-admin-rule-builder-page";
import {
  institutionAdminAccessPage,
  institutionAdminApiKeysPage,
  institutionAdminBadgeStatusPage,
  institutionAdminDashboardPage,
  institutionAdminGovernancePage,
  institutionAdminIssuedBadgesPage,
  institutionAdminLmsConnectionsPage,
  institutionAdminMembersPage,
  institutionAdminOperationsPage,
  institutionAdminOperationsReviewQueuePage,
  institutionAdminOrgUnitsPage,
  institutionAdminRulesPage,
} from "../admin/institution-admin-page";
import { buildOrganizationsPath } from "../auth/tenant-context-selection";
import { buildLocalTwoFactorPath } from "../auth/break-glass-policy";
import type { AppBindings, AppContext, AppEnv } from "../app";
import type { AppPage } from "../ui/render-page";
import { renderAppPage } from "../ui/render-page";
import { listOptionalBadgeTemplateImageRevisionCountsByTenant } from "./badge-template-image-revision-counts";

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
    renderInstitutionAdminTemplatesWorkspace,
    renderInstitutionAdminTemplateEditorWorkspace,
    resolveDatabase,
    resolveInstitutionAdminAdminRole,
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
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/operations`,
      institutionAdminOperationsPage,
    );
  });

  app.get("/tenants/:tenantId/admin/operations/review-queue", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/operations/review-queue`,
      institutionAdminOperationsReviewQueuePage,
    );
  });

  app.get("/tenants/:tenantId/admin/operations/issued-badges", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/operations/issued-badges`,
      institutionAdminIssuedBadgesPage,
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
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/rules`,
      institutionAdminRulesPage,
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

  app.get("/tenants/:tenantId/admin/rules/templates/:badgeTemplateId/table-row", async (c) => {
    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    const rulesTemplatesPath = `/tenants/${encodeURIComponent(
      pathParams.tenantId,
    )}/admin/rules/templates`;
    const listPageQuery = parseBadgeTemplateListPageQuery(c.req.query());
    const roleCheck = await resolveInstitutionAdminAdminRole(
      c,
      pathParams.tenantId,
      rulesTemplatesPath,
    );

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const [template, imageRevisionCounts] = await Promise.all([
      findBadgeTemplateById(db, pathParams.tenantId, pathParams.badgeTemplateId),
      listOptionalBadgeTemplateImageRevisionCountsByTenant(db, pathParams.tenantId),
    ]);

    if (template === null) {
      return c.text("Badge template not found", 404);
    }

    c.header("Cache-Control", "no-store");
    c.header("Content-Type", "text/html; charset=utf-8");

    return c.body(
      renderBadgeTemplateAdminTableRowToString({
        tenantId: pathParams.tenantId,
        template,
        imageRevisionCount:
          imageRevisionCounts.find((entry) => entry.badgeTemplateId === template.id)
            ?.revisionCount ?? 0,
        historyHref: badgeTemplateHistoryHref(rulesTemplatesPath, template.id, listPageQuery),
      }),
    );
  });

  app.get("/tenants/:tenantId/admin/access", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access`,
      institutionAdminAccessPage,
    );
  });

  app.get("/tenants/:tenantId/admin/access/members", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/members`,
      institutionAdminMembersPage,
    );
  });

  app.get("/tenants/:tenantId/admin/access/governance", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/governance`,
      institutionAdminGovernancePage,
    );
  });

  app.get("/tenants/:tenantId/admin/access/api-keys", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/api-keys`,
      institutionAdminApiKeysPage,
    );
  });

  app.get("/tenants/:tenantId/admin/access/lms-connections", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/lms-connections`,
      institutionAdminLmsConnectionsPage,
    );
  });

  app.get("/tenants/:tenantId/admin/access/org-units", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/org-units`,
      institutionAdminOrgUnitsPage,
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

    const [currentUser, badgeTemplates, badgeRules, lmsConnections, accessibleTenantContexts] =
      await Promise.all([
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
        ...(selectedBadgeTemplateId === undefined ? {} : { selectedBadgeTemplateId }),
        switchOrganizationPath,
      }),
    );
  });
};
