import {
  findTenantLmsConnectionById,
  listBadgeIssuanceRuleBuilderDraftsForUser,
  type ListBadgeIssuanceRuleRegistryPageInput,
  type TenantMembershipRole,
} from "@credtrail/db";
import { parseTenantLmsConnectionPathParams } from "@credtrail/validation";
import type { AppContext } from "../app";
import type { ResolveDatabase } from "../app/route-deps";
import { loadBadgeRuleReviewQueueEntries } from "../badge-rule-review-queue-workspace";
import { buildTenantLtiDynamicRegistrationInviteUrl } from "../lti/dynamic-registration-service";
import type { AppPage, renderAppPage } from "../ui/render-page";
import {
  consumeAdminListMessageFlash,
  setAdminListMessageFlash,
  type AdminListMessageWorkspace,
} from "./admin-list-message-flash";
import {
  institutionAdminAuthenticationPage,
  institutionAdminDelegationsNewPage,
  institutionAdminDelegationsPage,
  institutionAdminGovernancePage,
  institutionAdminLmsConnectionEditPage,
  institutionAdminLmsConnectionNewPage,
  institutionAdminLmsConnectionsPage,
  institutionAdminManualIssuePage,
  institutionAdminMembersPage,
  institutionAdminOperationsReviewQueuePage,
  institutionAdminOrgUnitAccessPage,
  institutionAdminOrgUnitsPage,
  institutionAdminRulesPage,
} from "./institution-admin-page";
import {
  loadInstitutionAdminWorkspacePageData,
  renderInstitutionAdminWorkspacePage,
} from "./institution-admin-workspace";
import {
  emptyLmsConnectionFormValues,
  lmsConnectionFormValuesFromRecord,
} from "./institution-admin/lms-connection-setup-section";
import type { InstitutionAdminListFlashWorkspace } from "./institution-admin/list-flash-workspace";
import type { InstitutionAdminPageInput } from "./institution-admin/page-types";
import { lmsConnectionsPageUrl } from "./lms-connection-admin-helpers";
import { consumeAdminManualIssueFlash } from "./manual-issue-flash";
import { loadTenantBadgeRuleValueLists } from "./rule-value-lists-presentation";
import {
  badgeRuleRegistryPageUrl,
  buildBadgeRuleRegistryPath,
  safeParseBadgeRuleRegistryPageQuery,
} from "./badge-rule-registry-admin-helpers";

interface InstitutionAdminWorkspaceRendererDeps<TPageData extends InstitutionAdminPageInput> {
  resolveDatabase: ResolveDatabase;
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
  loadInstitutionAdminPageData: (
    c: AppContext,
    tenantId: string,
    sessionUserId: string,
    membershipRole: TenantMembershipRole,
    options?: {
      view?: import("./institution-admin/page-types").InstitutionAdminView;
      badgeTemplatesIncludeArchived?: boolean;
      badgeRuleRegistryQuery?: Omit<ListBadgeIssuanceRuleRegistryPageInput, "tenantId" | "scope">;
    },
  ) => Promise<TPageData | Response>;
}

const readListWorkspaceFlash = async (
  c: AppContext,
  input: {
    tenantId: string;
    userId: string;
    workspace: AdminListMessageWorkspace;
  },
): Promise<InstitutionAdminListFlashWorkspace> => {
  const flash = await consumeAdminListMessageFlash(c, {
    tenantId: input.tenantId,
    userId: input.userId,
    workspace: input.workspace,
  });

  if (flash === null) {
    return {
      listNotice: null,
      listError: null,
    };
  }

  if (flash.tone === "error") {
    return {
      listNotice: null,
      listError: flash.message,
    };
  }

  return {
    listNotice: flash.message,
    listError: null,
  };
};

const renderInstitutionAdminListFlashWorkspace = async <
  TPageData extends InstitutionAdminPageInput,
>(
  c: AppContext,
  renderAppPageFn: typeof renderAppPage,
  tenantId: string,
  nextPath: string,
  deps: InstitutionAdminWorkspaceRendererDeps<TPageData>,
  config: {
    workspace: AdminListMessageWorkspace;
    buildPage: (pageData: TPageData, flash: InstitutionAdminListFlashWorkspace) => AppPage;
  },
): Promise<Response> => {
  const loaded = await loadInstitutionAdminWorkspacePageData({
    c,
    tenantId,
    nextPath,
    resolveInstitutionAdminAdminRole: deps.resolveInstitutionAdminAdminRole,
    loadInstitutionAdminPageData: deps.loadInstitutionAdminPageData,
  });

  if (loaded instanceof Response) {
    return loaded;
  }

  const { pageData, session } = loaded;
  const flash = await readListWorkspaceFlash(c, {
    tenantId,
    userId: session.userId,
    workspace: config.workspace,
  });

  return await renderInstitutionAdminWorkspacePage(
    c,
    renderAppPageFn,
    config.buildPage(pageData, flash),
  );
};

export const renderInstitutionAdminRulesWorkspace = async <
  TPageData extends InstitutionAdminPageInput,
>(
  c: AppContext,
  renderAppPageFn: typeof renderAppPage,
  tenantId: string,
  nextPath: string,
  deps: InstitutionAdminWorkspaceRendererDeps<TPageData>,
): Promise<Response> => {
  const roleCheck = await deps.resolveInstitutionAdminAdminRole(c, tenantId, nextPath);

  if (roleCheck instanceof Response) {
    return roleCheck;
  }

  const parsedQuery = safeParseBadgeRuleRegistryPageQuery(c.req.query());
  if (!parsedQuery.ok) {
    await setAdminListMessageFlash(c, {
      tenantId,
      userId: roleCheck.session.userId,
      workspace: "rules",
      tone: "error",
      message: "Those rule filters or page controls were invalid. Review the list and try again.",
    });
    return c.redirect(buildBadgeRuleRegistryPath(tenantId), 303);
  }

  const query = parsedQuery.value;
  const pageData = await deps.loadInstitutionAdminPageData(
    c,
    tenantId,
    roleCheck.session.userId,
    roleCheck.membershipRole,
    {
      badgeRuleRegistryQuery: {
        searchQuery: query.searchQuery,
        ...(query.latestStatus === null ? {} : { latestStatus: query.latestStatus }),
        sort: query.sort,
        direction: query.direction,
        limit: query.limit,
        ...(query.cursor === undefined ? {} : { cursor: query.cursor }),
      },
    },
  );

  if (pageData instanceof Response) {
    return pageData;
  }

  const registryPage = pageData.badgeRuleRegistryPage;
  if (registryPage === undefined) {
    throw new Error("Badge rule registry page data was not loaded");
  }

  const session = roleCheck.session;
  const flash = await readListWorkspaceFlash(c, {
    tenantId,
    userId: session.userId,
    workspace: "rules",
  });
  const db = deps.resolveDatabase(c.env);
  const [valueLists, builderDrafts] = await Promise.all([
    loadTenantBadgeRuleValueLists(db, tenantId),
    listBadgeIssuanceRuleBuilderDraftsForUser(db, {
      tenantId,
      userId: session.userId,
    }),
  ]);

  return await renderInstitutionAdminWorkspacePage(
    c,
    renderAppPageFn,
    institutionAdminRulesPage({
      ...pageData,
      rulesWorkspace: {
        listNotice: flash.listNotice,
        listError: flash.listError,
        builderDrafts,
        registry: {
          searchQuery: query.searchQuery,
          latestStatus: query.latestStatus,
          sort: query.sort,
          direction: query.direction,
          limit: query.limit,
          totalCount: registryPage.totalCount,
          previousPageHref:
            registryPage.previousCursor === null
              ? null
              : badgeRuleRegistryPageUrl(tenantId, query, {
                  position: "before",
                  boundary: registryPage.previousCursor,
                }),
          nextPageHref:
            registryPage.nextCursor === null
              ? null
              : badgeRuleRegistryPageUrl(tenantId, query, {
                  position: "after",
                  boundary: registryPage.nextCursor,
                }),
        },
      },
      ruleValueListsWorkspace: {
        valueLists,
        listNotice: null,
        listError: null,
      },
    }),
  );
};

export const renderInstitutionAdminReviewQueueWorkspace = async <
  TPageData extends InstitutionAdminPageInput,
>(
  c: AppContext,
  renderAppPageFn: typeof renderAppPage,
  tenantId: string,
  nextPath: string,
  deps: InstitutionAdminWorkspaceRendererDeps<TPageData>,
): Promise<Response> => {
  const loaded = await loadInstitutionAdminWorkspacePageData({
    c,
    tenantId,
    nextPath,
    resolveInstitutionAdminAdminRole: deps.resolveInstitutionAdminAdminRole,
    loadInstitutionAdminPageData: deps.loadInstitutionAdminPageData,
  });

  if (loaded instanceof Response) {
    return loaded;
  }

  const { pageData, session } = loaded;
  const flash = await readListWorkspaceFlash(c, {
    tenantId,
    userId: session.userId,
    workspace: "operations_review_queue",
  });
  const entries = await loadBadgeRuleReviewQueueEntries(deps.resolveDatabase(c.env), tenantId, {
    reviewStatus: "pending",
    limit: 50,
  });

  return await renderInstitutionAdminWorkspacePage(
    c,
    renderAppPageFn,
    institutionAdminOperationsReviewQueuePage({
      ...pageData,
      reviewQueueWorkspace: {
        entries,
        listNotice: flash.listNotice,
        listError: flash.listError,
      },
    }),
  );
};

export const renderInstitutionAdminMembersWorkspace = async <
  TPageData extends InstitutionAdminPageInput,
>(
  c: AppContext,
  renderAppPageFn: typeof renderAppPage,
  tenantId: string,
  nextPath: string,
  deps: InstitutionAdminWorkspaceRendererDeps<TPageData>,
): Promise<Response> => {
  return renderInstitutionAdminListFlashWorkspace(c, renderAppPageFn, tenantId, nextPath, deps, {
    workspace: "access_members",
    buildPage: (pageData, flash) =>
      institutionAdminMembersPage({
        ...pageData,
        accessMembersWorkspace: flash,
      }),
  });
};

export const renderInstitutionAdminOrgUnitAccessWorkspace = async <
  TPageData extends InstitutionAdminPageInput,
>(
  c: AppContext,
  renderAppPageFn: typeof renderAppPage,
  tenantId: string,
  nextPath: string,
  deps: InstitutionAdminWorkspaceRendererDeps<TPageData>,
): Promise<Response> => {
  return renderInstitutionAdminListFlashWorkspace(c, renderAppPageFn, tenantId, nextPath, deps, {
    workspace: "access_org_unit_access",
    buildPage: (pageData, flash) =>
      institutionAdminOrgUnitAccessPage({
        ...pageData,
        accessOrgUnitAccessWorkspace: flash,
      }),
  });
};

export const renderInstitutionAdminGovernanceWorkspace = async <
  TPageData extends InstitutionAdminPageInput,
>(
  c: AppContext,
  renderAppPageFn: typeof renderAppPage,
  tenantId: string,
  nextPath: string,
  deps: InstitutionAdminWorkspaceRendererDeps<TPageData>,
): Promise<Response> => {
  return renderInstitutionAdminListFlashWorkspace(c, renderAppPageFn, tenantId, nextPath, deps, {
    workspace: "access_governance",
    buildPage: (pageData, flash) =>
      institutionAdminGovernancePage({
        ...pageData,
        accessGovernanceWorkspace: flash,
      }),
  });
};

export const renderInstitutionAdminDelegationsWorkspace = async <
  TPageData extends InstitutionAdminPageInput,
>(
  c: AppContext,
  renderAppPageFn: typeof renderAppPage,
  tenantId: string,
  nextPath: string,
  deps: InstitutionAdminWorkspaceRendererDeps<TPageData>,
): Promise<Response> => {
  return renderInstitutionAdminListFlashWorkspace(c, renderAppPageFn, tenantId, nextPath, deps, {
    workspace: "access_delegations",
    buildPage: (pageData, flash) =>
      institutionAdminDelegationsPage({
        ...pageData,
        accessDelegationsWorkspace: flash,
      }),
  });
};

export const renderInstitutionAdminAuthenticationWorkspace = async <
  TPageData extends InstitutionAdminPageInput,
>(
  c: AppContext,
  renderAppPageFn: typeof renderAppPage,
  tenantId: string,
  nextPath: string,
  deps: InstitutionAdminWorkspaceRendererDeps<TPageData>,
): Promise<Response> => {
  const loaded = await loadInstitutionAdminWorkspacePageData({
    c,
    tenantId,
    nextPath,
    resolveInstitutionAdminAdminRole: deps.resolveInstitutionAdminAdminRole,
    loadInstitutionAdminPageData: deps.loadInstitutionAdminPageData,
  });

  if (loaded instanceof Response) {
    return loaded;
  }

  const { pageData, session } = loaded;
  const flash = await readListWorkspaceFlash(c, {
    tenantId,
    userId: session.userId,
    workspace: "access_authentication",
  });
  const editProviderId = (c.req.query("editProvider") ?? "").trim();

  return await renderInstitutionAdminWorkspacePage(
    c,
    renderAppPageFn,
    institutionAdminAuthenticationPage({
      ...pageData,
      accessAuthenticationWorkspace: {
        listNotice: flash.listNotice,
        listError: flash.listError,
        editProviderId: editProviderId.length > 0 ? editProviderId : null,
      },
    }),
  );
};

export const renderInstitutionAdminDelegationsNewWorkspace = async <
  TPageData extends InstitutionAdminPageInput,
>(
  c: AppContext,
  renderAppPageFn: typeof renderAppPage,
  tenantId: string,
  nextPath: string,
  deps: InstitutionAdminWorkspaceRendererDeps<TPageData>,
): Promise<Response> => {
  return renderInstitutionAdminListFlashWorkspace(c, renderAppPageFn, tenantId, nextPath, deps, {
    workspace: "access_delegations_new",
    buildPage: (pageData, flash) =>
      institutionAdminDelegationsNewPage({
        ...pageData,
        accessDelegationsNewWorkspace: flash,
      }),
  });
};

export const renderInstitutionAdminLmsConnectionsWorkspace = async <
  TPageData extends InstitutionAdminPageInput,
>(
  c: AppContext,
  renderAppPageFn: typeof renderAppPage,
  tenantId: string,
  nextPath: string,
  deps: InstitutionAdminWorkspaceRendererDeps<TPageData>,
): Promise<Response> => {
  const loaded = await loadInstitutionAdminWorkspacePageData({
    c,
    tenantId,
    nextPath,
    resolveInstitutionAdminAdminRole: deps.resolveInstitutionAdminAdminRole,
    loadInstitutionAdminPageData: deps.loadInstitutionAdminPageData,
  });

  if (loaded instanceof Response) {
    return loaded;
  }

  const { pageData, session } = loaded;
  const flash = await readListWorkspaceFlash(c, {
    tenantId,
    userId: session.userId,
    workspace: "access_lms_connections",
  });
  const dynamicRegistrationUrl = await buildTenantLtiDynamicRegistrationInviteUrl(c.env, tenantId);

  return await renderInstitutionAdminWorkspacePage(
    c,
    renderAppPageFn,
    institutionAdminLmsConnectionsPage({
      ...pageData,
      lmsConnectionsWorkspace: {
        listNotice: flash.listNotice,
        listError: flash.listError,
        ltiDynamicRegistrationUrl: dynamicRegistrationUrl,
      },
    }),
  );
};

export const renderInstitutionAdminLmsConnectionNewWorkspace = async <
  TPageData extends InstitutionAdminPageInput,
>(
  c: AppContext,
  renderAppPageFn: typeof renderAppPage,
  tenantId: string,
  nextPath: string,
  deps: InstitutionAdminWorkspaceRendererDeps<TPageData>,
): Promise<Response> => {
  const loaded = await loadInstitutionAdminWorkspacePageData({
    c,
    tenantId,
    nextPath,
    resolveInstitutionAdminAdminRole: deps.resolveInstitutionAdminAdminRole,
    loadInstitutionAdminPageData: deps.loadInstitutionAdminPageData,
  });

  if (loaded instanceof Response) {
    return loaded;
  }

  const { pageData, session } = loaded;
  const flash = await readListWorkspaceFlash(c, {
    tenantId,
    userId: session.userId,
    workspace: "access_lms_connections",
  });

  return await renderInstitutionAdminWorkspacePage(
    c,
    renderAppPageFn,
    institutionAdminLmsConnectionNewPage({
      ...pageData,
      lmsConnectionSetupFormValues: emptyLmsConnectionFormValues(),
      lmsConnectionSetupWorkspace: {
        listNotice: flash.listNotice,
        listError: flash.listError,
      },
    }),
  );
};

export const renderInstitutionAdminLmsConnectionEditWorkspace = async <
  TPageData extends InstitutionAdminPageInput,
>(
  c: AppContext,
  renderAppPageFn: typeof renderAppPage,
  tenantId: string,
  nextPath: string,
  deps: InstitutionAdminWorkspaceRendererDeps<TPageData>,
): Promise<Response> => {
  const loaded = await loadInstitutionAdminWorkspacePageData({
    c,
    tenantId,
    nextPath,
    resolveInstitutionAdminAdminRole: deps.resolveInstitutionAdminAdminRole,
    loadInstitutionAdminPageData: deps.loadInstitutionAdminPageData,
  });

  if (loaded instanceof Response) {
    return loaded;
  }

  const { pageData, session } = loaded;
  const flash = await readListWorkspaceFlash(c, {
    tenantId,
    userId: session.userId,
    workspace: "access_lms_connections",
  });

  let pathParams: ReturnType<typeof parseTenantLmsConnectionPathParams>;

  try {
    pathParams = parseTenantLmsConnectionPathParams(c.req.param());
  } catch {
    await setAdminListMessageFlash(c, {
      tenantId,
      userId: session.userId,
      workspace: "access_lms_connections",
      tone: "error",
      message: "LMS connection not found.",
    });

    return c.redirect(lmsConnectionsPageUrl(tenantId), 303);
  }

  const db = deps.resolveDatabase(c.env);
  const connection = await findTenantLmsConnectionById(db, {
    tenantId,
    connectionId: pathParams.connectionId,
  });

  if (connection === null) {
    await setAdminListMessageFlash(c, {
      tenantId,
      userId: session.userId,
      workspace: "access_lms_connections",
      tone: "error",
      message: "LMS connection not found.",
    });

    return c.redirect(lmsConnectionsPageUrl(tenantId), 303);
  }

  return await renderInstitutionAdminWorkspacePage(
    c,
    renderAppPageFn,
    institutionAdminLmsConnectionEditPage({
      ...pageData,
      lmsConnectionSetupFormValues: lmsConnectionFormValuesFromRecord(connection),
      lmsConnectionSetupWorkspace: {
        listNotice: flash.listNotice,
        listError: flash.listError,
      },
    }),
  );
};

export const renderInstitutionAdminManualIssueWorkspace = async <
  TPageData extends InstitutionAdminPageInput,
>(
  c: AppContext,
  renderAppPageFn: typeof renderAppPage,
  tenantId: string,
  nextPath: string,
  deps: InstitutionAdminWorkspaceRendererDeps<TPageData>,
): Promise<Response> => {
  const loaded = await loadInstitutionAdminWorkspacePageData({
    c,
    tenantId,
    nextPath,
    resolveInstitutionAdminAdminRole: deps.resolveInstitutionAdminAdminRole,
    loadInstitutionAdminPageData: deps.loadInstitutionAdminPageData,
  });

  if (loaded instanceof Response) {
    return loaded;
  }

  const { pageData, session } = loaded;
  const flash = await consumeAdminManualIssueFlash(c, {
    tenantId,
    userId: session.userId,
  });
  const manualIssueWorkspace =
    flash === null
      ? {
          listNotice: null,
          listError: null,
          successLinks: null,
        }
      : flash.tone === "error"
        ? {
            listNotice: null,
            listError: flash.message,
            successLinks: null,
          }
        : {
            listNotice: flash.message,
            listError: null,
            successLinks: flash.successLinks ?? null,
          };

  return await renderInstitutionAdminWorkspacePage(
    c,
    renderAppPageFn,
    institutionAdminManualIssuePage({
      ...pageData,
      manualIssueWorkspace,
    }),
  );
};

export const renderInstitutionAdminOrgUnitsWorkspace = async <
  TPageData extends InstitutionAdminPageInput,
>(
  c: AppContext,
  renderAppPageFn: typeof renderAppPage,
  tenantId: string,
  nextPath: string,
  deps: InstitutionAdminWorkspaceRendererDeps<TPageData>,
): Promise<Response> => {
  return renderInstitutionAdminListFlashWorkspace(c, renderAppPageFn, tenantId, nextPath, deps, {
    workspace: "access_org_units",
    buildPage: (pageData, flash) =>
      institutionAdminOrgUnitsPage({
        ...pageData,
        accessOrgUnitsWorkspace: flash,
      }),
  });
};
