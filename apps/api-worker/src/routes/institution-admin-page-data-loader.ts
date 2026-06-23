import {
  findTenantAuthPolicy,
  findTenantById,
  findUserById,
  listAccessibleTenantContextsForUser,
  listBadgeIssuanceRules,
  listBadgeIssuanceRuleVersions,
  listBadgeTemplates,
  listDelegatedIssuingAuthorityGrants,
  listTenantApiKeys,
  listTenantAuthProviders,
  listTenantBreakGlassAccounts,
  listTenantLmsConnections,
  listTenantMembers,
  listTenantMembershipOrgUnitScopes,
  listTenantOrgUnits,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import { institutionAdminDashboardPage } from "../admin/institution-admin/page";
import {
  institutionAdminViewNeedsApiKeyRows,
  institutionAdminViewNeedsDelegationSelectOptions,
  institutionAdminViewNeedsGovernanceTableRows,
  institutionAdminViewNeedsLmsConnectionRows,
  institutionAdminViewNeedsOrgUnitRows,
  institutionAdminViewNeedsRuleTableRows,
  institutionAdminViewNeedsRuleVersionIndexes,
  institutionAdminViewNeedsTemplateSelectOptions,
  institutionAdminViewNeedsTenantMemberRows,
  type InstitutionAdminView,
} from "../admin/institution-admin/page-types";
import type { AppBindings, AppContext } from "../app";
import { buildOrganizationsPath } from "../auth/tenant-context-selection";

export type InstitutionAdminPageData = Parameters<typeof institutionAdminDashboardPage>[0];

export interface LoadInstitutionAdminShellDataInput {
  c: AppContext;
  tenantId: string;
  sessionUserId: string;
  membershipRole: TenantMembershipRole;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
}

export type InstitutionAdminShellData = Pick<
  InstitutionAdminPageData,
  "membershipRole" | "switchOrganizationPath" | "tenant" | "userEmail" | "userId"
>;

export interface LoadInstitutionAdminPageDataInput extends LoadInstitutionAdminShellDataInput {
  view?: InstitutionAdminView;
  badgeTemplatesIncludeArchived?: boolean;
}

type InstitutionAdminDataset =
  | "badgeTemplates"
  | "orgUnits"
  | "membershipOrgUnitScopes"
  | "tenantMembers"
  | "delegatedGrants"
  | "apiKeys"
  | "lmsConnections"
  | "badgeRules"
  | "badgeRuleVersions"
  | "enterpriseAuth";

const institutionAdminDatasetsForView = (
  view: InstitutionAdminView,
): ReadonlySet<InstitutionAdminDataset> => {
  const datasets = new Set<InstitutionAdminDataset>();

  if (institutionAdminViewNeedsTemplateSelectOptions(view)) {
    datasets.add("badgeTemplates");
  }

  if (
    institutionAdminViewNeedsOrgUnitRows(view) ||
    institutionAdminViewNeedsDelegationSelectOptions(view) ||
    institutionAdminViewNeedsGovernanceTableRows(view) ||
    institutionAdminViewNeedsTenantMemberRows(view)
  ) {
    datasets.add("orgUnits");
  }

  if (institutionAdminViewNeedsGovernanceTableRows(view)) {
    datasets.add("tenantMembers");
    datasets.add("membershipOrgUnitScopes");
  }

  if (institutionAdminViewNeedsTenantMemberRows(view)) {
    datasets.add("tenantMembers");
    datasets.add("membershipOrgUnitScopes");
  }

  if (
    institutionAdminViewNeedsGovernanceTableRows(view) ||
    institutionAdminViewNeedsDelegationSelectOptions(view)
  ) {
    datasets.add("delegatedGrants");
  }

  if (institutionAdminViewNeedsApiKeyRows(view)) {
    datasets.add("apiKeys");
  }

  if (institutionAdminViewNeedsLmsConnectionRows(view)) {
    datasets.add("lmsConnections");
  }

  if (
    institutionAdminViewNeedsRuleTableRows(view) ||
    institutionAdminViewNeedsRuleVersionIndexes(view)
  ) {
    datasets.add("badgeRules");
    datasets.add("badgeRuleVersions");
  }

  if (view === "accessAuthentication") {
    datasets.add("enterpriseAuth");
  }

  return datasets;
};

const emptyInstitutionAdminPageData = (
  shell: InstitutionAdminShellData,
): InstitutionAdminPageData => {
  return {
    ...shell,
    badgeTemplates: [],
    orgUnits: [],
    membershipOrgUnitScopes: [],
    tenantMembers: [],
    delegatedIssuingAuthorityGrants: [],
    lmsConnections: [],
    activeApiKeys: [],
    revokedApiKeyCount: 0,
    badgeRules: [],
    badgeRuleVersions: [],
    enterpriseAuthPolicy: null,
    enterpriseAuthProviders: [],
    breakGlassAccounts: [],
  };
};

export const loadInstitutionAdminShellData = async (
  input: LoadInstitutionAdminShellDataInput,
): Promise<InstitutionAdminShellData | Response> => {
  const db = input.resolveDatabase(input.c.env);
  const [tenant, currentUser, accessibleTenantContexts] = await Promise.all([
    findTenantById(db, input.tenantId),
    findUserById(db, input.sessionUserId),
    listAccessibleTenantContextsForUser(db, input.sessionUserId),
  ]);

  if (tenant === null) {
    return input.c.json(
      {
        error: "Tenant not found",
      },
      404,
    );
  }

  const requestUrl = new URL(input.c.req.url);
  const switchOrganizationPath =
    accessibleTenantContexts.length > 1
      ? buildOrganizationsPath(`${requestUrl.pathname}${requestUrl.search}`)
      : null;

  return {
    tenant,
    userId: input.sessionUserId,
    ...(currentUser?.email === undefined ? {} : { userEmail: currentUser.email }),
    membershipRole: input.membershipRole,
    switchOrganizationPath,
  };
};

export const loadInstitutionAdminPageData = async (
  input: LoadInstitutionAdminPageDataInput,
): Promise<InstitutionAdminPageData | Response> => {
  const shellData = await loadInstitutionAdminShellData(input);

  if (shellData instanceof Response) {
    return shellData;
  }

  const datasets =
    input.view === undefined
      ? new Set<InstitutionAdminDataset>([
          "badgeTemplates",
          "orgUnits",
          "membershipOrgUnitScopes",
          "tenantMembers",
          "delegatedGrants",
          "apiKeys",
          "lmsConnections",
          "badgeRules",
          "badgeRuleVersions",
          "enterpriseAuth",
        ])
      : institutionAdminDatasetsForView(input.view);

  if (datasets.size === 0) {
    return emptyInstitutionAdminPageData(shellData);
  }

  const db = input.resolveDatabase(input.c.env);
  const tenant = shellData.tenant;
  const includeEnterpriseAuth = datasets.has("enterpriseAuth") && tenant.planTier === "enterprise";

  const [
    badgeTemplates,
    orgUnits,
    membershipOrgUnitScopes,
    tenantMembers,
    delegatedIssuingAuthorityGrants,
    apiKeys,
    lmsConnections,
    badgeRules,
    authPolicy,
    authProviders,
    breakGlassAccounts,
  ] = await Promise.all([
    datasets.has("badgeTemplates")
      ? listBadgeTemplates(db, {
          tenantId: input.tenantId,
          includeArchived: input.badgeTemplatesIncludeArchived ?? false,
        })
      : Promise.resolve([]),
    datasets.has("orgUnits")
      ? listTenantOrgUnits(db, {
          tenantId: input.tenantId,
          includeInactive: true,
        })
      : Promise.resolve([]),
    datasets.has("membershipOrgUnitScopes")
      ? listTenantMembershipOrgUnitScopes(db, {
          tenantId: input.tenantId,
        })
      : Promise.resolve([]),
    datasets.has("tenantMembers") ? listTenantMembers(db, input.tenantId) : Promise.resolve([]),
    datasets.has("delegatedGrants")
      ? listDelegatedIssuingAuthorityGrants(db, {
          tenantId: input.tenantId,
          includeRevoked: true,
          includeExpired: true,
        })
      : Promise.resolve([]),
    datasets.has("apiKeys")
      ? listTenantApiKeys(db, {
          tenantId: input.tenantId,
          includeRevoked: true,
        })
      : Promise.resolve([]),
    datasets.has("lmsConnections")
      ? listTenantLmsConnections(db, input.tenantId)
      : Promise.resolve([]),
    datasets.has("badgeRules")
      ? listBadgeIssuanceRules(db, {
          tenantId: input.tenantId,
        })
      : Promise.resolve([]),
    includeEnterpriseAuth ? findTenantAuthPolicy(db, input.tenantId) : Promise.resolve(null),
    includeEnterpriseAuth ? listTenantAuthProviders(db, input.tenantId) : Promise.resolve([]),
    includeEnterpriseAuth ? listTenantBreakGlassAccounts(db, input.tenantId) : Promise.resolve([]),
  ]);

  const badgeRuleVersionLists =
    datasets.has("badgeRuleVersions") && badgeRules.length > 0
      ? await Promise.all(
          badgeRules.map(async (rule) =>
            listBadgeIssuanceRuleVersions(db, {
              tenantId: input.tenantId,
              ruleId: rule.id,
            }),
          ),
        )
      : [];
  const badgeRuleVersions = badgeRuleVersionLists.flat();
  const activeApiKeys = apiKeys.filter((apiKey) => apiKey.revokedAt === null);
  const revokedApiKeyCount = apiKeys.length - activeApiKeys.length;

  return {
    ...shellData,
    badgeTemplates,
    orgUnits,
    membershipOrgUnitScopes,
    tenantMembers,
    delegatedIssuingAuthorityGrants,
    lmsConnections,
    activeApiKeys,
    revokedApiKeyCount,
    badgeRules,
    badgeRuleVersions,
    enterpriseAuthPolicy: authPolicy,
    enterpriseAuthProviders: authProviders,
    breakGlassAccounts,
  };
};
