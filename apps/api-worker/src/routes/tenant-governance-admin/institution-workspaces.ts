import { listTenantAssertions, type SqlDatabase, type TenantMembershipRole } from "@credtrail/db";
import { renderAppPage, type AppPage } from "../../ui/render-page";
import type { AppContext, AppBindings } from "../../app";
import { consumeAdminFlashCookie } from "../../admin/admin-flash";
import {
  consumeAdminListMessageFlash,
  setAdminListMessageFlash,
} from "../../admin/admin-list-message-flash";
import {
  buildIssuedBadgesPagePath,
  issuedBadgesInvalidFiltersError,
  safeParseIssuedBadgesPageQuery,
  shouldLoadIssuedBadgesList,
} from "../../admin/issued-badges-admin-helpers";
import {
  loadInstitutionAdminWorkspacePageData,
  renderInstitutionAdminWorkspacePage,
} from "../../admin/institution-admin-workspace";
import {
  institutionAdminApiKeysPage,
  institutionAdminDashboardPage,
  institutionAdminIssuedBadgesPage,
} from "../../admin/institution-admin-page";
import {
  renderInstitutionAdminAuthenticationWorkspace,
  renderInstitutionAdminGovernanceDelegationNewWorkspace,
  renderInstitutionAdminGovernanceWorkspace,
  renderInstitutionAdminLmsConnectionEditWorkspace,
  renderInstitutionAdminLmsConnectionNewWorkspace,
  renderInstitutionAdminLmsConnectionsWorkspace,
  renderInstitutionAdminManualIssueWorkspace,
  renderInstitutionAdminMembersWorkspace,
  renderInstitutionAdminOrgUnitsWorkspace,
  renderInstitutionAdminReviewQueueWorkspace,
  renderInstitutionAdminRulesWorkspace,
} from "../../admin/institution-admin-workspace-renderers";
import type { InstitutionAdminView } from "../../admin/institution-admin/page-types";
import type { TenantGovernanceAdminAuth } from "./auth";
import type { TenantGovernanceAdminPageDataLoaders } from "./page-data";

export type TenantGovernanceInstitutionAdminWorkspaces = ReturnType<
  typeof createTenantGovernanceInstitutionAdminWorkspaces
>;

export const createTenantGovernanceInstitutionAdminWorkspaces = (input: {
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  resolveInstitutionAdminAdminRole: TenantGovernanceAdminAuth["resolveInstitutionAdminAdminRole"];
  loadInstitutionAdminPageData: TenantGovernanceAdminPageDataLoaders["loadInstitutionAdminPageData"];
}) => {
  const { resolveDatabase, resolveInstitutionAdminAdminRole, loadInstitutionAdminPageData } = input;

  const renderInstitutionAdminWorkspace = async (
    c: AppContext,
    tenantId: string,
    nextPath: string,
    renderPage: (pageData: Parameters<typeof institutionAdminDashboardPage>[0]) => AppPage,
  ): Promise<Response> => {
    const roleCheck = await resolveInstitutionAdminAdminRole(c, tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const pageData = await loadInstitutionAdminPageData(
      c,
      tenantId,
      session.userId,
      membershipRole,
    );

    if (pageData instanceof Response) {
      return pageData;
    }

    c.header("Cache-Control", "no-store");

    return renderAppPage(c, renderPage(pageData));
  };

  const renderInstitutionAdminApiKeysWorkspace = async (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ): Promise<Response> => {
    const loaded = await loadInstitutionAdminWorkspacePageData({
      c,
      tenantId,
      nextPath,
      resolveInstitutionAdminAdminRole,
      loadInstitutionAdminPageData,
    });

    if (loaded instanceof Response) {
      return loaded;
    }

    const { pageData, session } = loaded;
    const flash = await consumeAdminListMessageFlash(c, {
      tenantId,
      userId: session.userId,
      workspace: "access_api_keys",
    });
    const revealedSecret = await consumeAdminFlashCookie(c, {
      kind: "api_key_secret",
      tenantId,
      userId: session.userId,
    });

    return await renderInstitutionAdminWorkspacePage(
      c,
      renderAppPage,
      institutionAdminApiKeysPage({
        ...pageData,
        apiKeysWorkspace: {
          listNotice: flash?.tone === "success" ? flash.message : null,
          listError: flash?.tone === "error" ? flash.message : null,
          revealedSecret,
          openCreatePanel:
            revealedSecret !== null || flash?.tone === "error" || flash?.tone === "success",
        },
      }),
    );
  };

  const renderInstitutionAdminIssuedBadgesWorkspace = async (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ): Promise<Response> => {
    const loaded = await loadInstitutionAdminWorkspacePageData({
      c,
      tenantId,
      nextPath,
      resolveInstitutionAdminAdminRole,
      loadInstitutionAdminPageData,
    });

    if (loaded instanceof Response) {
      return loaded;
    }

    const { pageData, session } = loaded;
    const parsedQuery = safeParseIssuedBadgesPageQuery(c.req.query());

    if (!parsedQuery.ok) {
      await setAdminListMessageFlash(c, {
        tenantId,
        userId: session.userId,
        workspace: "issued_badges",
        tone: "error",
        message: issuedBadgesInvalidFiltersError,
      });

      return c.redirect(buildIssuedBadgesPagePath(tenantId), 303);
    }

    const issuedBadgesQuery = parsedQuery.value;
    const flash = await consumeAdminListMessageFlash(c, {
      tenantId,
      userId: session.userId,
      workspace: "issued_badges",
    });
    const assertions = shouldLoadIssuedBadgesList(c.req.query())
      ? await listTenantAssertions(resolveDatabase(c.env), {
          tenantId,
          ...(issuedBadgesQuery.listQuery.badgeTemplateId === undefined
            ? {}
            : { badgeTemplateId: issuedBadgesQuery.listQuery.badgeTemplateId }),
          ...(issuedBadgesQuery.listQuery.recipientQuery === undefined
            ? {}
            : { recipientQuery: issuedBadgesQuery.listQuery.recipientQuery }),
          ...(issuedBadgesQuery.listQuery.state === undefined
            ? {}
            : { state: issuedBadgesQuery.listQuery.state }),
          ...(issuedBadgesQuery.listQuery.limit === undefined
            ? {}
            : { limit: issuedBadgesQuery.listQuery.limit }),
        })
      : [];

    return await renderInstitutionAdminWorkspacePage(
      c,
      renderAppPage,
      institutionAdminIssuedBadgesPage({
        ...pageData,
        issuedBadgesWorkspace: {
          filters: issuedBadgesQuery.filters,
          assertions,
          listNotice: flash?.tone === "success" ? flash.message : null,
          listError: flash?.tone === "error" ? flash.message : null,
          lifecycleAssertionId: issuedBadgesQuery.lifecycleAssertionId,
          lifecycleMode: issuedBadgesQuery.lifecycleMode,
        },
      }),
    );
  };

  const workspaceRendererDeps = (view: InstitutionAdminView) => ({
    resolveDatabase,
    resolveInstitutionAdminAdminRole,
    loadInstitutionAdminPageData: (
      c: AppContext,
      tenantId: string,
      sessionUserId: string,
      membershipRole: TenantMembershipRole,
    ) => loadInstitutionAdminPageData(c, tenantId, sessionUserId, membershipRole, { view }),
  });

  const renderRulesWorkspace = async (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ): Promise<Response> => {
    return renderInstitutionAdminRulesWorkspace(
      c,
      renderAppPage,
      tenantId,
      nextPath,
      workspaceRendererDeps("rules"),
    );
  };

  const renderReviewQueueWorkspace = async (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ): Promise<Response> => {
    return renderInstitutionAdminReviewQueueWorkspace(
      c,
      renderAppPage,
      tenantId,
      nextPath,
      workspaceRendererDeps("operationsReviewQueue"),
    );
  };

  const renderLmsConnectionsWorkspace = (c: AppContext, tenantId: string, nextPath: string) =>
    renderInstitutionAdminLmsConnectionsWorkspace(
      c,
      renderAppPage,
      tenantId,
      nextPath,
      workspaceRendererDeps("accessLmsConnections"),
    );

  const renderLmsConnectionNewWorkspace = (c: AppContext, tenantId: string, nextPath: string) =>
    renderInstitutionAdminLmsConnectionNewWorkspace(
      c,
      renderAppPage,
      tenantId,
      nextPath,
      workspaceRendererDeps("accessLmsConnectionNew"),
    );

  const renderLmsConnectionEditWorkspace = (c: AppContext, tenantId: string, nextPath: string) =>
    renderInstitutionAdminLmsConnectionEditWorkspace(
      c,
      renderAppPage,
      tenantId,
      nextPath,
      workspaceRendererDeps("accessLmsConnectionEdit"),
    );

  const renderAuthenticationWorkspace = (c: AppContext, tenantId: string, nextPath: string) =>
    renderInstitutionAdminAuthenticationWorkspace(
      c,
      renderAppPage,
      tenantId,
      nextPath,
      workspaceRendererDeps("accessAuthentication"),
    );

  const renderGovernanceDelegationNewWorkspace = (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) =>
    renderInstitutionAdminGovernanceDelegationNewWorkspace(
      c,
      renderAppPage,
      tenantId,
      nextPath,
      workspaceRendererDeps("accessGovernanceDelegationNew"),
    );

  const renderManualIssueWorkspace = (c: AppContext, tenantId: string, nextPath: string) =>
    renderInstitutionAdminManualIssueWorkspace(
      c,
      renderAppPage,
      tenantId,
      nextPath,
      workspaceRendererDeps("operationsManualIssue"),
    );

  const renderMembersWorkspace = (c: AppContext, tenantId: string, nextPath: string) =>
    renderInstitutionAdminMembersWorkspace(
      c,
      renderAppPage,
      tenantId,
      nextPath,
      workspaceRendererDeps("accessMembers"),
    );

  const renderGovernanceWorkspace = (c: AppContext, tenantId: string, nextPath: string) =>
    renderInstitutionAdminGovernanceWorkspace(
      c,
      renderAppPage,
      tenantId,
      nextPath,
      workspaceRendererDeps("accessGovernance"),
    );

  const renderOrgUnitsWorkspace = (c: AppContext, tenantId: string, nextPath: string) =>
    renderInstitutionAdminOrgUnitsWorkspace(
      c,
      renderAppPage,
      tenantId,
      nextPath,
      workspaceRendererDeps("accessOrgUnits"),
    );

  return {
    renderInstitutionAdminWorkspace,
    renderInstitutionAdminApiKeysWorkspace,
    renderInstitutionAdminIssuedBadgesWorkspace,
    renderRulesWorkspace,
    renderReviewQueueWorkspace,
    renderLmsConnectionsWorkspace,
    renderLmsConnectionNewWorkspace,
    renderLmsConnectionEditWorkspace,
    renderAuthenticationWorkspace,
    renderGovernanceDelegationNewWorkspace,
    renderManualIssueWorkspace,
    renderMembersWorkspace,
    renderGovernanceWorkspace,
    renderOrgUnitsWorkspace,
  };
};
