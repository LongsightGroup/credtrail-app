import type { SqlDatabase, TenantMembershipRole } from "@credtrail/db";
import {
  BADGE_ISSUANCE_RULE_BUILDER_EDIT_DENIED_MESSAGE,
  canEditBadgeIssuanceRuleDraft,
  findBadgeIssuanceRuleById,
  findBadgeIssuanceRuleBuilderDraftById,
  findBadgeIssuanceRuleBuilderDraftForRule,
  findTenantById,
  findUserById,
  latestBadgeIssuanceRuleVersion,
  listAccessibleTenantContextsForUser,
  listBadgeIssuanceRules,
  listBadgeIssuanceRuleVersionsForRules,
  listBadgeTemplateRuleUsages,
  resolveListBadgeIssuanceRulesInput,
  listBadgeIssuanceRuleVersions,
  listBadgeTemplates,
  listTenantLmsConnections,
} from "@credtrail/db";
import {
  parseBadgeIssuanceRulePathParams,
  parseBadgeIssuanceRuleBuilderDraftPathParams,
  parseBadgeTemplatePathParams,
  parseTenantLmsConnectionPathParams,
  parseTenantPathParams,
  parseAssertionPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import { setAdminListMessageFlash } from "../admin/admin-list-message-flash";
import {
  badgeTemplateAdminEditorHref,
  buildBadgeTemplateListPath,
} from "../admin/badge-template-admin-helpers";
import {
  institutionAdminBadgeStatusPage,
  institutionAdminDashboardPage,
} from "../admin/institution-admin/page";
import { institutionAdminRuleBuilderPage } from "../admin/institution-admin-rule-builder-page";
import type { InstitutionAdminView } from "../admin/institution-admin/page-types";
import { buildLmsConnectionEditPath } from "../admin/lms-connection-admin-helpers";
import {
  loadTenantBadgeRuleValueLists,
  toRuleValueListBuilderContextEntries,
} from "../admin/rule-value-lists-presentation";
import type { AppContext, AppEnv } from "../app";
import type { RequireTenantRole, ResolveDatabase } from "../app/route-deps";
import { buildLocalTwoFactorPath } from "../auth/break-glass-policy";
import { buildOrganizationsPath } from "../auth/tenant-context-selection";
import { classifyRuleBuilderBadgeTemplateAvailability } from "../badges/badge-template-rule-availability";
import type { AppPage } from "../ui/render-page";
import { renderAppPage } from "../ui/render-page";

type InstitutionAdminPageData = Parameters<typeof institutionAdminDashboardPage>[0];

const createBadgeRuleBuilderDraftId = (): string => `brd_${crypto.randomUUID()}`;

const loadInstitutionAdminRuleBuilderSharedData = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    userId: string;
    draftId?: string | undefined;
    ruleId?: string | undefined;
  },
) => {
  const [currentUser, badgeTemplates, lmsConnections, accessibleTenantContexts, valueLists] =
    await Promise.all([
      findUserById(db, input.userId),
      listBadgeTemplates(db, {
        tenantId: input.tenantId,
        includeArchived: false,
      }),
      listTenantLmsConnections(db, input.tenantId),
      listAccessibleTenantContextsForUser(db, input.userId),
      loadTenantBadgeRuleValueLists(db, input.tenantId),
    ]);
  const builderDraft =
    input.draftId !== undefined
      ? await findBadgeIssuanceRuleBuilderDraftById(db, {
          tenantId: input.tenantId,
          userId: input.userId,
          draftId: input.draftId,
        })
      : input.ruleId !== undefined
        ? await findBadgeIssuanceRuleBuilderDraftForRule(db, {
            tenantId: input.tenantId,
            userId: input.userId,
            ruleId: input.ruleId,
          })
        : null;

  return {
    currentUser,
    badgeTemplates,
    lmsConnections,
    accessibleTenantContexts,
    valueLists: toRuleValueListBuilderContextEntries(valueLists),
    builderDraft,
  };
};

interface RegisterTenantAdminPageRoutesInput {
  app: Hono<AppEnv>;
  ADMIN_ROLES: readonly TenantMembershipRole[];
  adminRoleRequiredPage: (tenantId: string) => AppPage;
  requireTenantRole: RequireTenantRole;
  redirectToTenantLogin: (c: AppContext, tenantId: string, nextPath: string) => Response;
  renderInstitutionAdminWorkspace: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
    view: InstitutionAdminView,
    renderPage: (pageData: InstitutionAdminPageData) => AppPage,
  ) => Promise<Response>;
  renderInstitutionAdminMembersWorkspace: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<Response>;
  renderInstitutionAdminOrgUnitAccessWorkspace: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<Response>;
  renderInstitutionAdminGovernanceWorkspace: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<Response>;
  renderInstitutionAdminDelegationsWorkspace: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<Response>;
  renderInstitutionAdminDelegationsNewWorkspace: (
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
  renderInstitutionAdminAssertionEvidenceWorkspace: (
    c: AppContext,
    tenantId: string,
    assertionId: string,
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
  resolveDatabase: ResolveDatabase;
  resolveInstitutionAdminAdminRole: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<
    | Response
    | {
        principal: { userId: string };
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
    renderInstitutionAdminOrgUnitAccessWorkspace,
    renderInstitutionAdminGovernanceWorkspace,
    renderInstitutionAdminDelegationsWorkspace,
    renderInstitutionAdminDelegationsNewWorkspace,
    renderInstitutionAdminAuthenticationWorkspace,
    renderInstitutionAdminOrgUnitsWorkspace,
    renderInstitutionAdminApiKeysWorkspace,
    renderInstitutionAdminIssuedBadgesWorkspace,
    renderInstitutionAdminAssertionEvidenceWorkspace,
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
      "home",
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

  app.get("/tenants/:tenantId/admin/operations/issued-badges/:assertionId/evidence", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const assertionParams = parseAssertionPathParams(c.req.param());

    return renderInstitutionAdminAssertionEvidenceWorkspace(
      c,
      pathParams.tenantId,
      assertionParams.assertionId,
      c.req.path,
    );
  });

  app.get("/tenants/:tenantId/admin/operations/badge-status", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/operations/badge-status`,
      "operationsBadgeStatus",
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
      buildBadgeTemplateListPath(pathParams.tenantId),
    );
  });

  app.get("/tenants/:tenantId/admin/rules/templates/:badgeTemplateId", async (c) => {
    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    return renderInstitutionAdminTemplateEditorWorkspace(
      c,
      pathParams.tenantId,
      pathParams.badgeTemplateId,
      badgeTemplateAdminEditorHref(pathParams.tenantId, pathParams.badgeTemplateId),
    );
  });

  app.get("/tenants/:tenantId/admin/access/members", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminMembersWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/members`,
    );
  });

  app.get("/tenants/:tenantId/admin/access/governance", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminGovernanceWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/governance`,
    );
  });

  app.get("/tenants/:tenantId/admin/access/org-unit-access", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminOrgUnitAccessWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/org-unit-access`,
    );
  });

  app.get("/tenants/:tenantId/admin/access/delegations", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminDelegationsWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/delegations`,
    );
  });

  app.get("/tenants/:tenantId/admin/access/delegations/new", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminDelegationsNewWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/delegations/new`,
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

  const renderUnfinishedRuleBuilder = async (
    c: AppContext,
    route: {
      tenantId: string;
      draftId?: string | undefined;
    },
  ): Promise<Response> => {
    const encodedTenantId = encodeURIComponent(route.tenantId);
    const nextPath =
      route.draftId === undefined
        ? `/tenants/${encodedTenantId}/admin/rules/new`
        : `/tenants/${encodedTenantId}/admin/rules/drafts/${encodeURIComponent(route.draftId)}/edit`;
    const rulesPath = `/tenants/${encodedTenantId}/admin/rules`;
    const roleCheck = await requireTenantRole(c, route.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      if (roleCheck.status === 401) {
        return redirectToTenantLogin(c, route.tenantId, nextPath);
      }

      if (roleCheck.status === 423) {
        return c.redirect(
          buildLocalTwoFactorPath({
            tenantId: route.tenantId,
            nextPath,
            setup: true,
            reason: "break_glass_mfa_setup_pending",
          }),
          302,
        );
      }

      if (roleCheck.status === 403) {
        c.header("Cache-Control", "no-store");
        return renderAppPage(c, adminRoleRequiredPage(route.tenantId), 403);
      }

      return roleCheck;
    }

    const { principal, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const [tenant, sharedData, badgeRules] = await Promise.all([
      findTenantById(db, route.tenantId),
      loadInstitutionAdminRuleBuilderSharedData(db, {
        tenantId: route.tenantId,
        userId: principal.userId,
        ...(route.draftId === undefined ? {} : { draftId: route.draftId }),
      }),
      resolveListBadgeIssuanceRulesInput(db, {
        tenantId: route.tenantId,
        userId: principal.userId,
        membershipRole,
      }).then((listInput) => listBadgeIssuanceRules(db, listInput)),
    ]);

    if (tenant === null) {
      return c.json({ error: "Tenant not found" }, 404);
    }

    if (
      route.draftId !== undefined &&
      (sharedData.builderDraft === null || sharedData.builderDraft.ruleId !== null)
    ) {
      await setAdminListMessageFlash(c, {
        tenantId: route.tenantId,
        userId: principal.userId,
        workspace: "rules",
        tone: "error",
        message: "That unfinished draft was not found.",
      });
      return c.redirect(rulesPath, 303);
    }

    const [badgeRuleVersions, badgeTemplateRuleUsages] = await Promise.all([
      listBadgeIssuanceRuleVersionsForRules(db, {
        tenantId: route.tenantId,
        ruleIds: badgeRules.map((rule) => rule.id),
      }),
      listBadgeTemplateRuleUsages(db, {
        tenantId: route.tenantId,
        badgeTemplateIds: sharedData.badgeTemplates.map((template) => template.id),
      }),
    ]);
    const badgeTemplateAvailability = classifyRuleBuilderBadgeTemplateAvailability({
      publicAppOrigin: c.env.PUBLIC_APP_ORIGIN,
      badgeTemplates: sharedData.badgeTemplates,
    });
    const requestUrl = new URL(c.req.url);
    const requestedBadgeTemplateId = (c.req.query("badgeTemplateId") ?? "").trim();
    const selectedBadgeTemplateId = sharedData.badgeTemplates.some(
      (template) => template.id === requestedBadgeTemplateId,
    )
      ? requestedBadgeTemplateId
      : undefined;
    const switchOrganizationPath =
      sharedData.accessibleTenantContexts.length > 1
        ? buildOrganizationsPath(`${requestUrl.pathname}${requestUrl.search}`)
        : null;
    const builderDraftId = sharedData.builderDraft?.id ?? createBadgeRuleBuilderDraftId();

    c.header("Cache-Control", "no-store");

    return renderAppPage(
      c,
      institutionAdminRuleBuilderPage({
        tenant,
        userId: principal.userId,
        ...(sharedData.currentUser?.email === undefined
          ? {}
          : { userEmail: sharedData.currentUser.email }),
        membershipRole,
        badgeTemplateAvailability,
        badgeRules,
        badgeRuleVersions,
        badgeTemplateRuleUsages,
        lmsConnections: sharedData.lmsConnections,
        valueLists: sharedData.valueLists,
        builderDraftId,
        builderDraft: sharedData.builderDraft,
        ...(selectedBadgeTemplateId === undefined ? {} : { selectedBadgeTemplateId }),
        switchOrganizationPath,
      }),
    );
  };

  // These builder pages live in the institution-admin shell, so they require
  // owner/admin access even though badge-rule authoring APIs also allow issuers.
  app.get("/tenants/:tenantId/admin/rules/new", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderUnfinishedRuleBuilder(c, {
      tenantId: pathParams.tenantId,
    });
  });

  app.get("/tenants/:tenantId/admin/rules/drafts/:draftId/edit", (c) => {
    const pathParams = parseBadgeIssuanceRuleBuilderDraftPathParams(c.req.param());
    return renderUnfinishedRuleBuilder(c, pathParams);
  });

  app.get("/tenants/:tenantId/admin/rules/:ruleId/edit", async (c) => {
    const pathParams = parseBadgeIssuanceRulePathParams(c.req.param());
    const nextPath = `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/rules/${encodeURIComponent(
      pathParams.ruleId,
    )}/edit`;
    const rulesPath = `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/rules`;
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      if (roleCheck.status === 401) {
        return redirectToTenantLogin(c, pathParams.tenantId, nextPath);
      }

      if (roleCheck.status === 423) {
        return c.redirect(
          buildLocalTwoFactorPath({
            tenantId: pathParams.tenantId,
            nextPath,
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

    const { principal, membershipRole } = roleCheck;
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

    const editRule = await findBadgeIssuanceRuleById(db, pathParams.tenantId, pathParams.ruleId);

    if (editRule === null) {
      await setAdminListMessageFlash(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        workspace: "rules",
        tone: "error",
        message: "That rule was not found.",
      });

      return c.redirect(rulesPath, 303);
    }

    const editRuleVersions = await listBadgeIssuanceRuleVersions(db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
    });
    const latestVersion = latestBadgeIssuanceRuleVersion(editRuleVersions);

    if (!canEditBadgeIssuanceRuleDraft(editRule, editRuleVersions) || latestVersion === null) {
      await setAdminListMessageFlash(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        workspace: "rules",
        tone: "error",
        message: BADGE_ISSUANCE_RULE_BUILDER_EDIT_DENIED_MESSAGE,
      });

      return c.redirect(rulesPath, 303);
    }

    const [sharedData, badgeRules] = await Promise.all([
      loadInstitutionAdminRuleBuilderSharedData(db, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        ruleId: pathParams.ruleId,
      }),
      resolveListBadgeIssuanceRulesInput(db, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        membershipRole,
      }).then((listInput) => listBadgeIssuanceRules(db, listInput)),
    ]);
    const [badgeRuleVersions, badgeTemplateRuleUsages] = await Promise.all([
      listBadgeIssuanceRuleVersionsForRules(db, {
        tenantId: pathParams.tenantId,
        ruleIds: badgeRules.map((rule) => rule.id),
      }),
      listBadgeTemplateRuleUsages(db, {
        tenantId: pathParams.tenantId,
        badgeTemplateIds: sharedData.badgeTemplates.map((template) => template.id),
        excludingRuleId: pathParams.ruleId,
      }),
    ]);
    const badgeTemplateAvailability = classifyRuleBuilderBadgeTemplateAvailability({
      publicAppOrigin: c.env.PUBLIC_APP_ORIGIN,
      badgeTemplates: sharedData.badgeTemplates,
    });
    const requestUrl = new URL(c.req.url);
    const switchOrganizationPath =
      sharedData.accessibleTenantContexts.length > 1
        ? buildOrganizationsPath(`${requestUrl.pathname}${requestUrl.search}`)
        : null;

    c.header("Cache-Control", "no-store");

    return renderAppPage(
      c,
      institutionAdminRuleBuilderPage({
        tenant,
        userId: principal.userId,
        ...(sharedData.currentUser?.email === undefined
          ? {}
          : { userEmail: sharedData.currentUser.email }),
        membershipRole,
        badgeTemplateAvailability,
        badgeRules,
        badgeRuleVersions,
        badgeTemplateRuleUsages,
        lmsConnections: sharedData.lmsConnections,
        valueLists: sharedData.valueLists,
        builderDraftId: sharedData.builderDraft?.id ?? createBadgeRuleBuilderDraftId(),
        builderDraft: sharedData.builderDraft,
        editRule: {
          rule: editRule,
          latestVersion,
        },
        switchOrganizationPath,
      }),
    );
  });
};
