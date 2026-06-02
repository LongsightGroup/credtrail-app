import {
  findTenantLmsConnectionById,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { renderAppPage } from "../ui/render-page";
import type { AppBindings, AppContext } from "../app";
import {
  consumeAdminListMessageFlash,
  setAdminListMessageFlash,
  type AdminListMessageWorkspace,
} from "./admin-list-message-flash";
import { parseTenantLmsConnectionPathParams } from "@credtrail/validation";
import {
  institutionAdminAuthenticationPage,
  institutionAdminGovernanceDelegationNewPage,
  institutionAdminGovernancePage,
  institutionAdminLmsConnectionEditPage,
  institutionAdminLmsConnectionNewPage,
  institutionAdminLmsConnectionsPage,
  institutionAdminManualIssuePage,
  institutionAdminMembersPage,
  institutionAdminOperationsReviewQueuePage,
  institutionAdminOrgUnitsPage,
  institutionAdminRulesPage,
} from "./institution-admin-page";
import { lmsConnectionsPageUrl } from "./lms-connection-admin-helpers";
import {
  emptyLmsConnectionFormValues,
  lmsConnectionFormValuesFromRecord,
} from "./institution-admin/lms-connection-setup-section";
import type { InstitutionAdminPageInput } from "./institution-admin/page-types";
import {
  loadInstitutionAdminWorkspacePageData,
  renderInstitutionAdminWorkspacePage,
} from "./institution-admin-workspace";
import { loadTenantBadgeRuleValueLists } from "./rule-value-lists-presentation";
import { loadBadgeRuleReviewQueueEntries } from "../badge-rule-review-queue-workspace";

interface InstitutionAdminWorkspaceRendererDeps<TPageData extends InstitutionAdminPageInput> {
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
  loadInstitutionAdminPageData: (
    c: AppContext,
    tenantId: string,
    sessionUserId: string,
    membershipRole: TenantMembershipRole,
  ) => Promise<TPageData | Response>;
}

const readListWorkspaceFlash = async (
  c: AppContext,
  input: {
    tenantId: string;
    userId: string;
    workspace: AdminListMessageWorkspace;
  },
): Promise<{ listNotice: string | null; listError: string | null }> => {
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

export const renderInstitutionAdminRulesWorkspace = async <
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
    workspace: "rules",
  });
  const valueLists = await loadTenantBadgeRuleValueLists(deps.resolveDatabase(c.env), tenantId);

  return await renderInstitutionAdminWorkspacePage(
    c,
    renderAppPageFn,
    institutionAdminRulesPage({
      ...pageData,
      rulesWorkspace: {
        listNotice: flash.listNotice,
        listError: flash.listError,
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
    workspace: "access_members",
  });

  return await renderInstitutionAdminWorkspacePage(
    c,
    renderAppPageFn,
    institutionAdminMembersPage({
      ...pageData,
      accessMembersWorkspace: {
        listNotice: flash.listNotice,
        listError: flash.listError,
      },
    }),
  );
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
    workspace: "access_governance",
  });

  return await renderInstitutionAdminWorkspacePage(
    c,
    renderAppPageFn,
    institutionAdminGovernancePage({
      ...pageData,
      accessGovernanceWorkspace: {
        listNotice: flash.listNotice,
        listError: flash.listError,
      },
    }),
  );
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

export const renderInstitutionAdminGovernanceDelegationNewWorkspace = async <
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
    workspace: "access_governance_delegation",
  });

  return await renderInstitutionAdminWorkspacePage(
    c,
    renderAppPageFn,
    institutionAdminGovernanceDelegationNewPage({
      ...pageData,
      accessGovernanceDelegationWorkspace: {
        listNotice: flash.listNotice,
        listError: flash.listError,
      },
    }),
  );
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

  return await renderInstitutionAdminWorkspacePage(
    c,
    renderAppPageFn,
    institutionAdminLmsConnectionsPage({
      ...pageData,
      lmsConnectionsWorkspace: {
        listNotice: flash.listNotice,
        listError: flash.listError,
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
  const flash = await readListWorkspaceFlash(c, {
    tenantId,
    userId: session.userId,
    workspace: "operations_manual_issue",
  });

  return await renderInstitutionAdminWorkspacePage(
    c,
    renderAppPageFn,
    institutionAdminManualIssuePage({
      ...pageData,
      manualIssueWorkspace: {
        listNotice: flash.listNotice,
        listError: flash.listError,
      },
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
    workspace: "access_org_units",
  });

  return await renderInstitutionAdminWorkspacePage(
    c,
    renderAppPageFn,
    institutionAdminOrgUnitsPage({
      ...pageData,
      accessOrgUnitsWorkspace: {
        listNotice: flash.listNotice,
        listError: flash.listError,
      },
    }),
  );
};
