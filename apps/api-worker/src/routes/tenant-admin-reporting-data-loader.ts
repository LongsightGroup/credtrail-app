import {
  findTenantById,
  findUserById,
  getTenantReportingEngagementCounts,
  getTenantReportingOverview,
  getTenantReportingTrends,
  listAccessibleTenantContextsForUser,
  listBadgeTemplates,
  listTenantMembershipOrgUnitScopes,
  listTenantOrgUnits,
  listTenantReportingComparisons,
  type SqlDatabase,
  type TenantMembershipRole,
  type TenantReportingLifecycleFilter,
} from "@credtrail/db";
import { renderAppPage, type AppPage } from "../ui/render-page";
import { institutionAdminDashboardPage } from "../admin/institution-admin-page";
import type { AppBindings, AppContext } from "../app";
import { resolveTenantReportingAccess } from "../auth/tenant-access";
import { buildOrganizationsPath } from "../auth/tenant-context-selection";
import { buildReportingMetricEntries } from "../reporting/metric-definitions";
import {
  toReportingComparisonFilters,
  toReportingEngagementFilters,
  toReportingOverviewFilters,
  toReportingTrendFilters,
} from "../reporting/reporting-page-filters";

type InstitutionAdminPageData = Parameters<typeof institutionAdminDashboardPage>[0];
type ReportingComparisonRow = Awaited<ReturnType<typeof listTenantReportingComparisons>>[number];
type BadgeTemplateRecord = InstitutionAdminPageData["badgeTemplates"][number];

interface LoadInstitutionAdminReportingPageDataInput {
  c: AppContext;
  tenantId: string;
  sessionUserId: string;
  membershipRole: TenantMembershipRole;
  issuedFrom?: string | undefined;
  issuedTo?: string | undefined;
  badgeTemplateId?: string | undefined;
  orgUnitId?: string | undefined;
  state?: TenantReportingLifecycleFilter | undefined;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  loadInstitutionAdminPageData: (
    c: AppContext,
    tenantId: string,
    sessionUserId: string,
    membershipRole: TenantMembershipRole,
  ) => Promise<InstitutionAdminPageData | Response>;
  reportingAccessRequiredPage: (tenantId: string) => AppPage;
}

const buildOrgUnitMap = (orgUnits: InstitutionAdminPageData["orgUnits"]) => {
  return new Map(orgUnits.map((orgUnit) => [orgUnit.id, orgUnit] as const));
};

const isOrgUnitWithinRoot = (
  orgUnitsById: ReadonlyMap<string, InstitutionAdminPageData["orgUnits"][number]>,
  orgUnitId: string,
  rootOrgUnitId: string,
): boolean => {
  const visited = new Set<string>();
  let currentOrgUnitId: string | null = orgUnitId;

  while (currentOrgUnitId !== null) {
    if (currentOrgUnitId === rootOrgUnitId) {
      return true;
    }

    if (visited.has(currentOrgUnitId)) {
      return false;
    }

    visited.add(currentOrgUnitId);
    currentOrgUnitId = orgUnitsById.get(currentOrgUnitId)?.parentOrgUnitId ?? null;
  }

  return false;
};

const isOrgUnitWithinRoots = (
  orgUnitsById: ReadonlyMap<string, InstitutionAdminPageData["orgUnits"][number]>,
  orgUnitId: string,
  rootOrgUnitIds: readonly string[],
): boolean => {
  return rootOrgUnitIds.some((rootOrgUnitId) =>
    isOrgUnitWithinRoot(orgUnitsById, orgUnitId, rootOrgUnitId),
  );
};

const filterOrgUnitsToScope = (
  orgUnits: InstitutionAdminPageData["orgUnits"],
  orgUnitsById: ReadonlyMap<string, InstitutionAdminPageData["orgUnits"][number]>,
  scopedRootOrgUnitIds: readonly string[],
) => {
  return orgUnits.filter((orgUnit) =>
    isOrgUnitWithinRoots(orgUnitsById, orgUnit.id, scopedRootOrgUnitIds),
  );
};

const filterComparisonRowsToScope = (
  comparisonRows: readonly ReportingComparisonRow[],
  orgUnitsById: ReadonlyMap<string, InstitutionAdminPageData["orgUnits"][number]>,
  scopedRootOrgUnitIds: readonly string[],
): ReportingComparisonRow[] => {
  return comparisonRows.filter((row) =>
    isOrgUnitWithinRoots(orgUnitsById, row.groupId, scopedRootOrgUnitIds),
  );
};

const filterBadgeTemplatesToIds = (
  badgeTemplates: readonly BadgeTemplateRecord[],
  allowedBadgeTemplateIds: ReadonlySet<string>,
): BadgeTemplateRecord[] => {
  return badgeTemplates.filter((badgeTemplate) => allowedBadgeTemplateIds.has(badgeTemplate.id));
};

export const loadInstitutionAdminReportingPageData = async (
  input: LoadInstitutionAdminReportingPageDataInput,
): Promise<InstitutionAdminPageData | Response> => {
  if (input.membershipRole === "owner" || input.membershipRole === "admin") {
    const pageData = await input.loadInstitutionAdminPageData(
      input.c,
      input.tenantId,
      input.sessionUserId,
      input.membershipRole,
    );

    if (pageData instanceof Response) {
      return pageData;
    }

    const db = input.resolveDatabase(input.c.env);
    const reportingPageFilters = {
      issuedFrom: input.issuedFrom,
      issuedTo: input.issuedTo,
      badgeTemplateId: input.badgeTemplateId,
      orgUnitId: input.orgUnitId,
      state: input.state,
    };
    const [
      reportingOverview,
      reportingEngagementCounts,
      reportingTrends,
      reportingTemplateComparisons,
      reportingOrgUnitComparisons,
    ] = await Promise.all([
      getTenantReportingOverview(db, {
        tenantId: input.tenantId,
        ...toReportingOverviewFilters(reportingPageFilters),
      }),
      getTenantReportingEngagementCounts(db, {
        tenantId: input.tenantId,
        ...toReportingEngagementFilters(reportingPageFilters),
      }),
      getTenantReportingTrends(db, {
        tenantId: input.tenantId,
        ...toReportingTrendFilters(reportingPageFilters),
      }),
      listTenantReportingComparisons(db, {
        tenantId: input.tenantId,
        ...toReportingComparisonFilters(reportingPageFilters, "badgeTemplate"),
      }),
      listTenantReportingComparisons(db, {
        tenantId: input.tenantId,
        ...toReportingComparisonFilters(reportingPageFilters, "orgUnit"),
      }),
    ]);

    return {
      ...pageData,
      reportingOverview,
      reportingEngagementCounts,
      reportingMetrics: buildReportingMetricEntries(reportingOverview.counts),
      reportingOrgUnitComparisons,
      reportingTemplateComparisons,
      reportingTrends,
    };
  }

  const db = input.resolveDatabase(input.c.env);
  const reportingAccess = await resolveTenantReportingAccess({
    db,
    tenantId: input.tenantId,
    userId: input.sessionUserId,
    membershipRole: input.membershipRole,
  });

  if (reportingAccess === null) {
    input.c.header("Cache-Control", "no-store");
    return renderAppPage(input.c, input.reportingAccessRequiredPage(input.tenantId), 403);
  }

  const [
    tenant,
    currentUser,
    badgeTemplates,
    orgUnits,
    membershipOrgUnitScopes,
    accessibleTenantContexts,
  ] = await Promise.all([
    findTenantById(db, input.tenantId),
    findUserById(db, input.sessionUserId),
    listBadgeTemplates(db, {
      tenantId: input.tenantId,
      includeArchived: false,
    }),
    listTenantOrgUnits(db, {
      tenantId: input.tenantId,
      includeInactive: true,
    }),
    listTenantMembershipOrgUnitScopes(db, {
      tenantId: input.tenantId,
      userId: input.sessionUserId,
    }),
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
  const orgUnitsById = buildOrgUnitMap(orgUnits);
  const scopedRootOrgUnitIds =
    reportingAccess.visibility === "scoped" ? reportingAccess.scopedOrgUnitIds : [];

  if (
    input.orgUnitId !== undefined &&
    scopedRootOrgUnitIds.length > 0 &&
    !isOrgUnitWithinRoots(orgUnitsById, input.orgUnitId, scopedRootOrgUnitIds)
  ) {
    input.c.header("Cache-Control", "no-store");
    return renderAppPage(input.c, input.reportingAccessRequiredPage(input.tenantId), 403);
  }

  const reportingOrgUnitComparisonsRaw = await listTenantReportingComparisons(db, {
    tenantId: input.tenantId,
    ...toReportingComparisonFilters(
      {
        issuedFrom: input.issuedFrom,
        issuedTo: input.issuedTo,
        badgeTemplateId: input.badgeTemplateId,
        state: input.state,
      },
      "orgUnit",
    ),
    groupBy: "orgUnit",
  });
  const reportingOrgUnitComparisons =
    scopedRootOrgUnitIds.length === 0
      ? reportingOrgUnitComparisonsRaw
      : filterComparisonRowsToScope(
          reportingOrgUnitComparisonsRaw,
          orgUnitsById,
          scopedRootOrgUnitIds,
        );
  const selectedOrgUnitId =
    input.orgUnitId ?? (scopedRootOrgUnitIds.length === 0 ? undefined : scopedRootOrgUnitIds[0]);
  const reportingPageFilters = {
    issuedFrom: input.issuedFrom,
    issuedTo: input.issuedTo,
    badgeTemplateId: input.badgeTemplateId,
    orgUnitId: selectedOrgUnitId,
    state: input.state,
  };
  const [
    reportingOverview,
    reportingEngagementCounts,
    reportingTrends,
    reportingTemplateComparisons,
  ] = await Promise.all([
    getTenantReportingOverview(db, {
      tenantId: input.tenantId,
      ...toReportingOverviewFilters(reportingPageFilters),
    }),
    getTenantReportingEngagementCounts(db, {
      tenantId: input.tenantId,
      ...toReportingEngagementFilters(reportingPageFilters),
    }),
    getTenantReportingTrends(db, {
      tenantId: input.tenantId,
      ...toReportingTrendFilters(reportingPageFilters),
    }),
    listTenantReportingComparisons(db, {
      tenantId: input.tenantId,
      ...toReportingComparisonFilters(reportingPageFilters, "badgeTemplate"),
    }),
  ]);
  const visibleBadgeTemplateIds = new Set(reportingTemplateComparisons.map((row) => row.groupId));

  if (input.badgeTemplateId !== undefined) {
    visibleBadgeTemplateIds.add(input.badgeTemplateId);
  }

  const visibleBadgeTemplates =
    scopedRootOrgUnitIds.length === 0
      ? badgeTemplates
      : filterBadgeTemplatesToIds(badgeTemplates, visibleBadgeTemplateIds);
  const visibleOrgUnits =
    scopedRootOrgUnitIds.length === 0
      ? orgUnits
      : filterOrgUnitsToScope(orgUnits, orgUnitsById, scopedRootOrgUnitIds);

  return {
    tenant,
    userId: input.sessionUserId,
    ...(currentUser?.email === undefined ? {} : { userEmail: currentUser.email }),
    membershipRole: input.membershipRole,
    badgeTemplates: visibleBadgeTemplates,
    orgUnits: visibleOrgUnits,
    membershipOrgUnitScopes,
    tenantMembers: [],
    delegatedIssuingAuthorityGrants: [],
    activeApiKeys: [],
    revokedApiKeyCount: 0,
    badgeRules: [],
    badgeRuleVersions: [],
    enterpriseAuthPolicy: null,
    enterpriseAuthProviders: [],
    breakGlassAccounts: [],
    switchOrganizationPath,
    reportingOverview,
    reportingEngagementCounts,
    reportingMetrics: buildReportingMetricEntries(reportingOverview.counts),
    reportingOrgUnitComparisons,
    reportingTemplateComparisons,
    reportingTrends,
  };
};
