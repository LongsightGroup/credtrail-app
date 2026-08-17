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
  type TenantMembershipRole,
  type TenantReportingLifecycleFilter,
} from "@credtrail/db";
import { institutionAdminDashboardPage } from "../admin/institution-admin/page";
import type {
  InstitutionAdminReportingView,
  InstitutionAdminView,
} from "../admin/institution-admin/page-types";
import type { AppContext } from "../app/types";
import type { ResolveDatabase } from "../app/route-deps";
import { resolveTenantReportingAccess } from "../auth/tenant-access";
import { buildOrganizationsPath } from "../auth/tenant-context-selection";
import { buildReportingMetricEntries } from "../reporting/metric-definitions";
import {
  type ReportingPageFilters,
  toReportingComparisonFilters,
  toReportingEngagementFilters,
  toReportingOverviewFilters,
  toReportingTrendFilters,
} from "../reporting/reporting-page-filters";
import { renderAppPage, type AppPage } from "../ui/render-page";

type InstitutionAdminPageData = Parameters<typeof institutionAdminDashboardPage>[0];
type ReportingComparisonRow = Awaited<ReturnType<typeof listTenantReportingComparisons>>[number];
type BadgeTemplateRecord = InstitutionAdminPageData["badgeTemplates"][number];
type ReportingFilterValues = NonNullable<InstitutionAdminPageData["reportingFilters"]>;

interface LoadInstitutionAdminReportingPageDataInput {
  c: AppContext;
  tenantId: string;
  sessionUserId: string;
  membershipRole: TenantMembershipRole;
  view: InstitutionAdminReportingView;
  issuedFrom?: string | undefined;
  issuedTo?: string | undefined;
  badgeTemplateId?: string | undefined;
  orgUnitId?: string | undefined;
  state?: TenantReportingLifecycleFilter | undefined;
  resolveDatabase: ResolveDatabase;
  loadInstitutionAdminPageData: (
    c: AppContext,
    tenantId: string,
    sessionUserId: string,
    membershipRole: TenantMembershipRole,
    options?: { view?: InstitutionAdminView },
  ) => Promise<InstitutionAdminPageData | Response>;
  reportingAccessRequiredPage: (tenantId: string) => AppPage;
}

interface ReportingDataRequirements {
  readonly overview: boolean;
  readonly engagement: boolean;
  readonly trends: boolean;
  readonly templateComparisons: boolean;
  readonly orgUnitComparisons: boolean;
}

interface ReportingDatasets {
  readonly overview: Awaited<ReturnType<typeof getTenantReportingOverview>> | null;
  readonly engagement: Awaited<ReturnType<typeof getTenantReportingEngagementCounts>> | null;
  readonly trends: Awaited<ReturnType<typeof getTenantReportingTrends>> | null;
  readonly templateComparisons: ReportingComparisonRow[];
  readonly orgUnitComparisons: ReportingComparisonRow[];
}

const reportingDataRequirements = (
  view: InstitutionAdminReportingView,
): ReportingDataRequirements => {
  switch (view) {
    case "reporting":
      return {
        overview: true,
        engagement: true,
        trends: false,
        templateComparisons: true,
        orgUnitComparisons: true,
      };
    case "reportingExplore":
      return {
        overview: true,
        engagement: true,
        trends: true,
        templateComparisons: true,
        orgUnitComparisons: true,
      };
    case "reportingTrends":
      return {
        overview: false,
        engagement: false,
        trends: true,
        templateComparisons: false,
        orgUnitComparisons: false,
      };
    case "reportingReports":
      return {
        overview: false,
        engagement: false,
        trends: false,
        templateComparisons: false,
        orgUnitComparisons: false,
      };
  }
};

const reportingFilterValues = (filters: ReportingPageFilters): ReportingFilterValues => ({
  issuedFrom: filters.issuedFrom ?? null,
  issuedTo: filters.issuedTo ?? null,
  badgeTemplateId: filters.badgeTemplateId ?? null,
  orgUnitId: filters.orgUnitId ?? null,
  state: filters.state ?? null,
});

const loadReportingDatasets = async (input: {
  readonly db: ReturnType<ResolveDatabase>;
  readonly tenantId: string;
  readonly filters: ReportingPageFilters;
  readonly orgUnitComparisonFilters: ReportingPageFilters;
  readonly requirements: ReportingDataRequirements;
  readonly loadTemplateComparisonsForVisibility: boolean;
}): Promise<ReportingDatasets> => {
  const [overview, engagement, trends, templateComparisons, orgUnitComparisons] = await Promise.all(
    [
      input.requirements.overview
        ? getTenantReportingOverview(input.db, {
            tenantId: input.tenantId,
            ...toReportingOverviewFilters(input.filters),
          })
        : Promise.resolve(null),
      input.requirements.engagement
        ? getTenantReportingEngagementCounts(input.db, {
            tenantId: input.tenantId,
            ...toReportingEngagementFilters(input.filters),
          })
        : Promise.resolve(null),
      input.requirements.trends
        ? getTenantReportingTrends(input.db, {
            tenantId: input.tenantId,
            ...toReportingTrendFilters(input.filters),
          })
        : Promise.resolve(null),
      input.requirements.templateComparisons || input.loadTemplateComparisonsForVisibility
        ? listTenantReportingComparisons(input.db, {
            tenantId: input.tenantId,
            ...toReportingComparisonFilters(input.filters, "badgeTemplate"),
          })
        : Promise.resolve([]),
      input.requirements.orgUnitComparisons
        ? listTenantReportingComparisons(input.db, {
            tenantId: input.tenantId,
            ...toReportingComparisonFilters(input.orgUnitComparisonFilters, "orgUnit"),
          })
        : Promise.resolve([]),
    ],
  );

  return { overview, engagement, trends, templateComparisons, orgUnitComparisons };
};

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
  const requirements = reportingDataRequirements(input.view);

  if (input.membershipRole === "owner" || input.membershipRole === "admin") {
    const pageData = await input.loadInstitutionAdminPageData(
      input.c,
      input.tenantId,
      input.sessionUserId,
      input.membershipRole,
      { view: input.view },
    );

    if (pageData instanceof Response) {
      return pageData;
    }

    const db = input.resolveDatabase(input.c.env);
    const reportingPageFilters: ReportingPageFilters = {
      issuedFrom: input.issuedFrom,
      issuedTo: input.issuedTo,
      badgeTemplateId: input.badgeTemplateId,
      orgUnitId: input.orgUnitId,
      state: input.state,
    };
    const reportingDatasets = await loadReportingDatasets({
      db,
      tenantId: input.tenantId,
      filters: reportingPageFilters,
      orgUnitComparisonFilters: reportingPageFilters,
      requirements,
      loadTemplateComparisonsForVisibility: false,
    });

    return {
      ...pageData,
      reportingOverview: reportingDatasets.overview,
      reportingEngagementCounts: reportingDatasets.engagement,
      reportingFilters: reportingFilterValues(reportingPageFilters),
      reportingMetrics:
        reportingDatasets.overview === null
          ? []
          : buildReportingMetricEntries(reportingDatasets.overview.counts),
      reportingOrgUnitComparisons: reportingDatasets.orgUnitComparisons,
      reportingTemplateComparisons: reportingDatasets.templateComparisons,
      reportingTrends: reportingDatasets.trends,
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

  const selectedOrgUnitId =
    input.orgUnitId ?? (scopedRootOrgUnitIds.length === 0 ? undefined : scopedRootOrgUnitIds[0]);
  const reportingPageFilters: ReportingPageFilters = {
    issuedFrom: input.issuedFrom,
    issuedTo: input.issuedTo,
    badgeTemplateId: input.badgeTemplateId,
    orgUnitId: selectedOrgUnitId,
    state: input.state,
  };
  const orgUnitComparisonFilters: ReportingPageFilters = {
    issuedFrom: input.issuedFrom,
    issuedTo: input.issuedTo,
    badgeTemplateId: input.badgeTemplateId,
    state: input.state,
  };
  const reportingDatasets = await loadReportingDatasets({
    db,
    tenantId: input.tenantId,
    filters: reportingPageFilters,
    orgUnitComparisonFilters,
    requirements,
    loadTemplateComparisonsForVisibility: scopedRootOrgUnitIds.length > 0,
  });
  const reportingOrgUnitComparisons =
    scopedRootOrgUnitIds.length === 0
      ? reportingDatasets.orgUnitComparisons
      : filterComparisonRowsToScope(
          reportingDatasets.orgUnitComparisons,
          orgUnitsById,
          scopedRootOrgUnitIds,
        );
  const visibleBadgeTemplateIds = new Set(
    reportingDatasets.templateComparisons.map((row) => row.groupId),
  );

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
    badgeRuleApproverGroups: [],
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
    switchOrganizationPath,
    reportingOverview: reportingDatasets.overview,
    reportingEngagementCounts: reportingDatasets.engagement,
    reportingFilters: reportingFilterValues(reportingPageFilters),
    reportingMetrics:
      reportingDatasets.overview === null
        ? []
        : buildReportingMetricEntries(reportingDatasets.overview.counts),
    reportingOrgUnitComparisons,
    reportingTemplateComparisons: reportingDatasets.templateComparisons,
    reportingTrends: reportingDatasets.trends,
  };
};
