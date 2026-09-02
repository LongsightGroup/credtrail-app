import {
  findAutomatedBadgeRuleEvaluationStatus,
  listLtiResourceLinkPlacementsForRule,
  resolveBadgeIssuanceRuleVersionSelection,
} from "@credtrail/db";
import {
  parseBadgeIssuanceRulePathParams,
  parseBadgeIssuanceRuleVersionPathParams,
  parseBadgeIssuanceRuleVersionSelectionQuery,
} from "@credtrail/validation";
import type { Hono } from "hono";
import {
  buildBadgeRuleDetailPath,
  buildBadgeRuleVersionDetailPath,
} from "../admin/access-admin-helpers";
import { badgeRuleVersionPage } from "../admin/badge-rule-version-page";
import { consumeAdminListMessageFlash } from "../admin/admin-list-message-flash";
import type { AppContext, AppEnv } from "../app/types";
import type { ResolveDatabase } from "../app/route-deps";
import { renderAppPage } from "../ui/render-page";
import {
  loadBadgeRuleVersionPageContext,
  loadBadgeRuleVersionsPageContext,
  type BadgeRuleVersionPageContext,
  type ResolveBadgeRuleVersionPageActor,
} from "./badge-rule-version-page-context";
import type { InstitutionAdminShellData } from "./institution-admin-page-data-loader";
import type { TenantGovernanceAdminPageDataLoaders } from "./tenant-governance-admin/page-data";

interface RegisterTenantBadgeRuleVersionPageRoutesInput {
  readonly app: Hono<AppEnv>;
  readonly resolveDatabase: ResolveDatabase;
  readonly loadInstitutionAdminShellData: TenantGovernanceAdminPageDataLoaders["loadInstitutionAdminShellData"];
  readonly resolveInstitutionAdminAdminRole: ResolveBadgeRuleVersionPageActor;
}

interface AuthorizedRuleVersionPageData extends BadgeRuleVersionPageContext {
  readonly shell: InstitutionAdminShellData;
}

interface RuleVersionRenderData extends AuthorizedRuleVersionPageData {
  readonly automaticEvaluationStatus: Awaited<
    ReturnType<typeof findAutomatedBadgeRuleEvaluationStatus>
  >;
  readonly evaluationFlash: Awaited<ReturnType<typeof consumeAdminListMessageFlash>>;
  readonly placements: Awaited<ReturnType<typeof listLtiResourceLinkPlacementsForRule>>;
  readonly evaluationRequestId: string;
}

interface LoadAuthorizedRuleVersionPageDataInput {
  readonly tenantId: string;
  readonly ruleId: string;
  readonly versionId: string;
  readonly nextPath: string;
  readonly resolveDatabase: ResolveDatabase;
  readonly resolveInstitutionAdminAdminRole: RegisterTenantBadgeRuleVersionPageRoutesInput["resolveInstitutionAdminAdminRole"];
  readonly loadInstitutionAdminShellData: TenantGovernanceAdminPageDataLoaders["loadInstitutionAdminShellData"];
}

const loadAuthorizedRuleVersionPageData = async (
  c: AppContext,
  input: LoadAuthorizedRuleVersionPageDataInput,
): Promise<Response | AuthorizedRuleVersionPageData> => {
  const authorized = await loadBadgeRuleVersionPageContext(c, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
    nextPath: input.nextPath,
    resolveDatabase: input.resolveDatabase,
    resolveActor: input.resolveInstitutionAdminAdminRole,
  });

  if (authorized instanceof Response) {
    return authorized;
  }

  const shell = await input.loadInstitutionAdminShellData(
    c,
    input.tenantId,
    authorized.principal.userId,
    authorized.membershipRole,
  );

  if (shell instanceof Response) {
    return shell;
  }

  return {
    ...authorized,
    shell,
  };
};

const renderRuleVersion = async (
  c: AppContext,
  input: RuleVersionRenderData,
): Promise<Response> => {
  return await renderAppPage(
    c,
    badgeRuleVersionPage({
      tenant: input.shell.tenant,
      userId: input.shell.userId,
      ...(input.shell.userEmail === undefined ? {} : { userEmail: input.shell.userEmail }),
      membershipRole: input.shell.membershipRole,
      switchOrganizationPath: input.shell.switchOrganizationPath,
      rule: input.rule,
      version: input.version,
      versions: input.versions,
      definition: input.definition,
      orgUnit: input.orgUnit,
      automaticEvaluationStatus: input.automaticEvaluationStatus,
      placements: input.placements,
      actionFlash: input.evaluationFlash,
      evaluationRequestId: input.evaluationRequestId,
    }),
  );
};

/** Registers canonical, read-only institution-admin badge-rule version pages. */
export const registerTenantBadgeRuleVersionPageRoutes = (
  input: RegisterTenantBadgeRuleVersionPageRoutesInput,
): void => {
  const { app, resolveDatabase, loadInstitutionAdminShellData, resolveInstitutionAdminAdminRole } =
    input;

  app.get("/tenants/:tenantId/admin/rules/:ruleId", async (c) => {
    const pathParams = parseBadgeIssuanceRulePathParams(c.req.param());
    c.header("Cache-Control", "no-store");
    let query: ReturnType<typeof parseBadgeIssuanceRuleVersionSelectionQuery>;

    try {
      query = parseBadgeIssuanceRuleVersionSelectionQuery(c.req.query());
    } catch {
      return c.json({ error: "Choose a valid badge rule version" }, 400);
    }

    const detailPath = buildBadgeRuleDetailPath(pathParams.tenantId, pathParams.ruleId);
    const loaded = await loadBadgeRuleVersionsPageContext(c, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      nextPath:
        query.versionId === undefined
          ? detailPath
          : `${detailPath}?versionId=${encodeURIComponent(query.versionId)}`,
      resolveDatabase,
      resolveActor: resolveInstitutionAdminAdminRole,
    });

    if (loaded instanceof Response) {
      return loaded;
    }

    const versionSelection = resolveBadgeIssuanceRuleVersionSelection({
      rule: loaded.rule,
      versions: loaded.versions,
    });
    const selectedVersion =
      query.versionId === undefined
        ? versionSelection.defaultVersion
        : loaded.versions.find((version) => version.id === query.versionId);

    if (selectedVersion === undefined || selectedVersion === null) {
      return c.json({ error: "Badge rule version not found" }, 404);
    }

    return c.redirect(
      buildBadgeRuleVersionDetailPath(pathParams.tenantId, pathParams.ruleId, selectedVersion.id),
      302,
    );
  });

  app.get("/tenants/:tenantId/admin/rules/:ruleId/versions/:versionId", async (c) => {
    const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
    c.header("Cache-Control", "no-store");
    const nextPath = buildBadgeRuleVersionDetailPath(
      pathParams.tenantId,
      pathParams.ruleId,
      pathParams.versionId,
    );
    const loaded = await loadAuthorizedRuleVersionPageData(c, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      versionId: pathParams.versionId,
      nextPath,
      resolveDatabase,
      loadInstitutionAdminShellData,
      resolveInstitutionAdminAdminRole,
    });

    if (loaded instanceof Response) {
      return loaded;
    }

    const [automaticEvaluationStatus, placements, evaluationFlash] = await Promise.all([
      findAutomatedBadgeRuleEvaluationStatus(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        ruleId: pathParams.ruleId,
        versionId: pathParams.versionId,
      }),
      listLtiResourceLinkPlacementsForRule(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        ruleId: pathParams.ruleId,
      }),
      consumeAdminListMessageFlash(c, {
        tenantId: pathParams.tenantId,
        userId: loaded.principal.userId,
        workspace: "rule_version",
      }),
    ]);

    return renderRuleVersion(c, {
      ...loaded,
      automaticEvaluationStatus,
      placements,
      evaluationFlash,
      evaluationRequestId: crypto.randomUUID(),
    });
  });
};
