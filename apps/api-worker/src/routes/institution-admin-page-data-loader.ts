import {
  findTenantAuthPolicy,
  findTenantById,
  findUserById,
  listAccessibleTenantContextsForUser,
  listBadgeRuleApproverGroupsWithMembers,
  listBadgeIssuanceRules,
  resolveListBadgeIssuanceRulesInput,
  listBadgeIssuanceRuleVersionsForRules,
  listBadgeTemplates,
  listDelegatedIssuingAuthorityGrants,
  listTenantApiKeys,
  listTenantAuthProviders,
  listTenantBreakGlassAccounts,
  listTenantLmsConnections,
  listTenantMembers,
  listTenantMembershipOrgUnitScopes,
  listTenantOrgUnits,
  resolveTenantDefaultBadgeRuleApprovalPolicy,
  type TenantMembershipRole,
} from "@credtrail/db";
import { institutionAdminDashboardPage } from "../admin/institution-admin/page";
import type { InstitutionAdminView } from "../admin/institution-admin/page-types";
import { INSTITUTION_ADMIN_VIEW_REGISTRY } from "../admin/institution-admin/view-content";
import type { AppContext } from "../app";
import type { ResolveDatabase } from "../app/route-deps";
import { buildOrganizationsPath } from "../auth/tenant-context-selection";

export type InstitutionAdminPageData = Parameters<typeof institutionAdminDashboardPage>[0];

export interface LoadInstitutionAdminShellDataInput {
  c: AppContext;
  tenantId: string;
  sessionUserId: string;
  membershipRole: TenantMembershipRole;
  resolveDatabase: ResolveDatabase;
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
  | "badgeRuleApprovalPolicy"
  | "enterpriseAuth";

const institutionAdminDatasetsForView = (
  view: InstitutionAdminView,
): ReadonlySet<InstitutionAdminDataset> => {
  const datasets = new Set<InstitutionAdminDataset>();
  const needs = INSTITUTION_ADMIN_VIEW_REGISTRY[view].dataNeeds;

  if (needs.templateSelectOptions || needs.issuedBadgeFilters || needs.delegationSelectOptions) {
    datasets.add("badgeTemplates");
  }

  if (
    needs.orgUnitRows ||
    needs.accessOrgUnitSelectOptions ||
    needs.delegatedGrantRows ||
    needs.tenantMemberRows ||
    needs.issuedBadgeFilters
  ) {
    datasets.add("orgUnits");
  }

  if (needs.governanceTableRows) {
    datasets.add("badgeRuleApprovalPolicy");
  }

  if (needs.accessMemberSelectOptions || needs.tenantMemberRows) {
    datasets.add("tenantMembers");
  }

  if (needs.scopedRoleRows || needs.tenantMemberRows) {
    datasets.add("membershipOrgUnitScopes");
  }

  if (needs.delegatedGrantRows) {
    datasets.add("delegatedGrants");
  }

  if (needs.apiKeyRows) {
    datasets.add("apiKeys");
  }

  if (needs.lmsConnectionRows) {
    datasets.add("lmsConnections");
  }

  if (needs.badgeRulesTable || needs.ruleSelectOptions) {
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
    badgeRuleApproverGroups: [],
    tenantMembers: [],
    delegatedIssuingAuthorityGrants: [],
    lmsConnections: [],
    activeApiKeys: [],
    revokedApiKeyCount: 0,
    badgeRules: [],
    badgeRuleVersions: [],
    badgeRuleApprovalPolicy: null,
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
    badgeRuleApproverGroups,
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
    datasets.has("badgeRuleApprovalPolicy")
      ? listBadgeRuleApproverGroupsWithMembers(db, input.tenantId)
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
      ? resolveListBadgeIssuanceRulesInput(db, {
          tenantId: input.tenantId,
          userId: input.sessionUserId,
          membershipRole: input.membershipRole,
        }).then((listInput) => listBadgeIssuanceRules(db, listInput))
      : Promise.resolve([]),
    includeEnterpriseAuth ? findTenantAuthPolicy(db, input.tenantId) : Promise.resolve(null),
    includeEnterpriseAuth ? listTenantAuthProviders(db, input.tenantId) : Promise.resolve([]),
    includeEnterpriseAuth ? listTenantBreakGlassAccounts(db, input.tenantId) : Promise.resolve([]),
  ]);

  const badgeRuleVersions = datasets.has("badgeRuleVersions")
    ? await listBadgeIssuanceRuleVersionsForRules(db, {
        tenantId: input.tenantId,
        ruleIds: badgeRules.map((rule) => rule.id),
      })
    : [];
  const badgeRuleApprovalPolicy = datasets.has("badgeRuleApprovalPolicy")
    ? await resolveTenantDefaultBadgeRuleApprovalPolicy(db, input.tenantId)
    : null;
  const activeApiKeys = apiKeys.filter((apiKey) => apiKey.revokedAt === null);
  const revokedApiKeyCount = apiKeys.length - activeApiKeys.length;

  return {
    ...shellData,
    badgeTemplates,
    orgUnits,
    membershipOrgUnitScopes,
    badgeRuleApproverGroups,
    tenantMembers,
    delegatedIssuingAuthorityGrants,
    lmsConnections,
    activeApiKeys,
    revokedApiKeyCount,
    badgeRules,
    badgeRuleVersions,
    badgeRuleApprovalPolicy,
    enterpriseAuthPolicy: authPolicy,
    enterpriseAuthProviders: authProviders,
    breakGlassAccounts,
  };
};
