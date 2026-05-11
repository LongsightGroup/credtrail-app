import type {
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  BadgeTemplateRecord,
  DelegatedIssuingAuthorityGrantRecord,
  LearnerRecordTrustLevel,
  TenantBreakGlassAccountRecord,
  TenantApiKeyRecord,
  TenantAuthPolicyRecord,
  TenantAuthProviderRecord,
  TenantMemberRecord,
  TenantMembershipOrgUnitScopeRecord,
  TenantMembershipRole,
  TenantOrgUnitRecord,
  TenantReportingComparisonRowRecord,
  TenantReportingEngagementCounts,
  TenantReportingOverviewRecord,
  TenantReportingTrendRecord,
  TenantRecord,
} from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { appPage, type AppPage } from "../ui/render-page";
import type { ReportingMetricEntry } from "../reporting/metric-definitions";
import { selectReportingHighlightRows } from "../reporting/reporting-highlights";
import {
  buildReportingHierarchyQueryEntries,
  buildReportingPageQueryEntries,
} from "../reporting/reporting-page-filters";
import { renderReporting, type ReportingVisualSeriesPoint } from "../reporting/reporting-visuals";
import type {
  LearnerRecordImportBatchProgressSummary,
  LearnerRecordImportRowReport,
} from "../learner-record/learner-record-import";
import type { LearnerRecordPresentationModel } from "../learner-record/learner-record-presentation";
import { formatIsoTimestamp } from "../utils/display-format";
import {
  AdminButton,
  AdminButtonLink,
  AdminActions,
  AdminCheckboxRow,
  AdminCtaLink,
  AdminEmptyTableRow,
  AdminField,
  AdminFieldset,
  AdminForm,
  AdminMeta,
  AdminMetricCard,
  AdminPageHeader,
  AdminPanel,
  AdminShell,
  AdminSidebar,
  AdminStatus,
  AdminStatusPill,
  AdminTable,
  AdminTopbar,
  AdminWorkspaceCard,
  type AdminSidebarFooterLink,
  type AdminSidebarSection,
} from "./components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

const formatScopesSummary = (scopesJson: string): string => {
  try {
    const parsed = JSON.parse(scopesJson) as unknown;

    if (!Array.isArray(parsed)) {
      return scopesJson;
    }

    return parsed
      .map((entry) => (typeof entry === "string" ? entry.trim() : ""))
      .filter((entry) => entry.length > 0)
      .join(", ");
  } catch {
    return scopesJson;
  }
};

const serializeJsonScriptContent = (value: unknown): string => {
  return JSON.stringify(value)
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029");
};

const formatJsonTextareaValue = (value: string): string => {
  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return value;
  }
};

const formatDelegatedIssuingActionLabel = (action: string): string => {
  switch (action) {
    case "issue_badge":
      return "Issue badges";
    case "revoke_badge":
      return "Revoke badges";
    case "manage_lifecycle":
      return "Change badge status";
    default:
      return action;
  }
};

const formatReportingCount = (value: number): string => {
  return new Intl.NumberFormat("en-US", {
    maximumFractionDigits: 0,
  }).format(value);
};

const formatReportingRate = (value: number): string => {
  return `${value.toFixed(1)}%`;
};

const formatReportingDateLabel = (value: string): string => {
  const date = value.includes("T") ? new Date(value) : new Date(`${value}T00:00:00.000Z`);

  if (!Number.isFinite(date.getTime())) {
    return value;
  }

  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  }).format(date);
};

const formatReportingStateLabel = (value: string | null | undefined): string => {
  if (value === null || value === undefined || value.trim().length === 0) {
    return "All current states";
  }

  switch (value) {
    case "pending_review":
      return "Pending review";
    case "active":
      return "active";
    case "suspended":
      return "suspended";
    case "revoked":
      return "revoked";
    case "expired":
      return "expired";
    default:
      return value;
  }
};

const REPORTING_HIERARCHY_LEVELS = ["institution", "college", "department", "program"] as const;
type ReportingHierarchyLevel = (typeof REPORTING_HIERARCHY_LEVELS)[number];

const REPORTING_HIERARCHY_DEPTH: Record<ReportingHierarchyLevel, number> = {
  institution: 0,
  college: 1,
  department: 2,
  program: 3,
};

const REPORTING_RATE_MIN_ISSUED = 5;
const REPORTING_PERFORMER_ROW_LIMIT = 3;

interface ReportingHierarchyRow {
  orgUnitId: string;
  level: ReportingHierarchyLevel;
  issuedCount: number;
  publicBadgeViewCount: number;
  verificationViewCount: number;
  shareClickCount: number;
  learnerClaimCount: number;
  walletAcceptCount: number;
  claimRate: number;
  shareRate: number;
}

type ReportingPanelState = "rich" | "sparse" | "empty";

interface ReportingActivityCounts {
  issuedCount: number;
  publicBadgeViewCount: number;
  verificationViewCount: number;
  shareClickCount: number;
  learnerClaimCount: number;
  walletAcceptCount: number;
}

const isReportingHierarchyLevel = (
  value: TenantOrgUnitRecord["unitType"],
): value is ReportingHierarchyLevel => {
  return REPORTING_HIERARCHY_LEVELS.includes(value as ReportingHierarchyLevel);
};

const getNextReportingHierarchyLevel = (
  level: ReportingHierarchyLevel,
): ReportingHierarchyLevel | null => {
  const index = REPORTING_HIERARCHY_LEVELS.indexOf(level);

  return index === REPORTING_HIERARCHY_LEVELS.length - 1
    ? null
    : (REPORTING_HIERARCHY_LEVELS[index + 1] ?? null);
};

const formatReportingHierarchyLevelLabel = (level: ReportingHierarchyLevel): string => {
  switch (level) {
    case "institution":
      return "Institution";
    case "college":
      return "College";
    case "department":
      return "Department";
    case "program":
      return "Program";
  }
};

const buildReportingHierarchyFocusId = (orgUnitId: string): string => {
  return `reporting-hierarchy-focus-${encodeURIComponent(orgUnitId)}`;
};

const appendQueryParam = (
  params: URLSearchParams,
  key: string,
  value: string | null | undefined,
): void => {
  const normalizedValue = value?.trim() ?? "";

  if (normalizedValue.length > 0) {
    params.set(key, normalizedValue);
  }
};

const buildPathWithQuery = (
  path: string,
  queryEntries: ReadonlyArray<readonly [string, string | null | undefined]>,
): string => {
  const params = new URLSearchParams();

  for (const [key, value] of queryEntries) {
    appendQueryParam(params, key, value);
  }

  const query = params.toString();

  return query.length === 0 ? path : `${path}?${query}`;
};

type InstitutionAdminView =
  | "home"
  | "operations"
  | "operationsLearnerRecords"
  | "operationsLearnerRecordImports"
  | "operationsReviewQueue"
  | "operationsIssuedBadges"
  | "operationsBadgeStatus"
  | "reporting"
  | "reportingExplore"
  | "reportingTrends"
  | "reportingReports"
  | "rules"
  | "access"
  | "accessMembers"
  | "accessGovernance"
  | "accessApiKeys"
  | "accessOrgUnits";

interface InstitutionAdminLearnerRecordReview {
  lookup: {
    learnerProfileId?: string;
    email?: string;
  };
  learnerProfile: {
    id: string;
    displayName: string | null;
    subjectId: string;
  } | null;
  presentation: LearnerRecordPresentationModel | null;
  exportPath: string | null;
  standardsMappingPath: string | null;
  lookupState: "idle" | "unresolved" | "loaded";
}

interface InstitutionAdminLearnerRecordImportWorkflow {
  templatePath: string;
  previewPath: string;
  applyPath: string;
  defaults: {
    defaultTrustLevel: LearnerRecordTrustLevel;
    defaultIssuerName: string;
  };
  submission: {
    mode: "preview" | "apply";
    batchId: string;
    fileName: string;
    totalRows: number;
    validRows: number;
    invalidRows: number;
    queuedRows: number;
    rows: readonly LearnerRecordImportRowReport[];
  } | null;
  feedback: {
    tone: "success" | "warning";
    title: string;
    detail: string;
  } | null;
  progress: {
    totals: {
      messages: number;
      batches: number;
      pendingRows: number;
      processingRows: number;
      completedRows: number;
      failedRows: number;
    };
    batches: readonly LearnerRecordImportBatchProgressSummary[];
  };
}

interface InstitutionAdminPageInput {
  tenant: TenantRecord;
  userId: string;
  userEmail?: string;
  membershipRole: TenantMembershipRole;
  badgeTemplates: readonly BadgeTemplateRecord[];
  orgUnits: readonly TenantOrgUnitRecord[];
  tenantMembers: readonly TenantMemberRecord[];
  membershipOrgUnitScopes: readonly TenantMembershipOrgUnitScopeRecord[];
  delegatedIssuingAuthorityGrants: readonly DelegatedIssuingAuthorityGrantRecord[];
  activeApiKeys: readonly TenantApiKeyRecord[];
  revokedApiKeyCount: number;
  badgeRules: readonly BadgeIssuanceRuleRecord[];
  badgeRuleVersions: readonly BadgeIssuanceRuleVersionRecord[];
  reportingEngagementCounts?: TenantReportingEngagementCounts | null;
  reportingOverview?: TenantReportingOverviewRecord | null;
  reportingMetrics?: readonly ReportingMetricEntry[];
  reportingOrgUnitComparisons?: readonly TenantReportingComparisonRowRecord[];
  reportingTemplateComparisons?: readonly TenantReportingComparisonRowRecord[];
  reportingTrends?: TenantReportingTrendRecord | null;
  enterpriseAuthPolicy?: TenantAuthPolicyRecord | null;
  enterpriseAuthProviders?: readonly TenantAuthProviderRecord[];
  breakGlassAccounts?: readonly TenantBreakGlassAccountRecord[];
  learnerRecordReview?: InstitutionAdminLearnerRecordReview;
  learnerRecordImportWorkflow?: InstitutionAdminLearnerRecordImportWorkflow;
  switchOrganizationPath?: string | null;
}

const renderInstitutionAdminPage = (
  input: InstitutionAdminPageInput,
  view: InstitutionAdminView,
): AppPage => {
  const templateById = new Map(input.badgeTemplates.map((template) => [template.id, template]));
  const orgUnitById = new Map(input.orgUnits.map((orgUnit) => [orgUnit.id, orgUnit]));
  const versionsByRuleId = new Map<string, BadgeIssuanceRuleVersionRecord[]>();
  const tenantAdminPath = `/tenants/${encodeURIComponent(input.tenant.id)}/admin`;
  const operationsPath = `${tenantAdminPath}/operations`;
  const operationsLearnerRecordsPath = `${operationsPath}/learner-records`;
  const operationsLearnerRecordImportsPath = `${operationsPath}/learner-record-imports`;
  const operationsReviewQueuePath = `${operationsPath}/review-queue`;
  const operationsIssuedBadgesPath = `${operationsPath}/issued-badges`;
  const operationsBadgeStatusPath = `${operationsPath}/badge-status`;
  const reportingPath = `${tenantAdminPath}/reporting`;
  const reportingExplorePath = `${reportingPath}/explore`;
  const reportingTrendsPath = `${reportingPath}/trends`;
  const reportingReportsPath = `${reportingPath}/reports`;
  const rulesWorkspacePath = `${tenantAdminPath}/rules`;
  const accessPath = `${tenantAdminPath}/access`;
  const accessMembersPath = `${accessPath}/members`;
  const accessGovernancePath = `${accessPath}/governance`;
  const accessApiKeysPath = `${accessPath}/api-keys`;
  const accessOrgUnitsPath = `${accessPath}/org-units`;
  const ruleBuilderPath = `${tenantAdminPath}/rules/new`;
  const badgeTemplateCount = String(input.badgeTemplates.length);
  const orgUnitCount = String(input.orgUnits.length);
  const activeApiKeyCount = String(input.activeApiKeys.length);
  const revokedApiKeyCount = String(input.revokedApiKeyCount);
  const ruleCount = String(input.badgeRules.length);
  const tenantMemberCount = String(input.tenantMembers.length);
  const scopedRoleCount = String(input.membershipOrgUnitScopes.length);
  const delegatedAuthorityGrantCount = String(input.delegatedIssuingAuthorityGrants.length);
  const userLabel = input.userEmail ?? input.userId;
  const switchOrganizationPath = input.switchOrganizationPath?.trim() ?? "";
  const learnerRecordReview = input.learnerRecordReview ?? {
    lookup: {},
    learnerProfile: null,
    presentation: null,
    exportPath: null,
    standardsMappingPath: null,
    lookupState: "idle" as const,
  };
  const learnerRecordImportWorkflow = input.learnerRecordImportWorkflow ?? {
    templatePath: `/v1/tenants/${encodeURIComponent(input.tenant.id)}/learner-record-imports/template.csv`,
    previewPath: operationsLearnerRecordImportsPath,
    applyPath: operationsLearnerRecordImportsPath,
    defaults: {
      defaultTrustLevel: "issuer_verified" as const,
      defaultIssuerName: "",
    },
    submission: null,
    feedback: null,
    progress: {
      totals: {
        messages: 0,
        batches: 0,
        pendingRows: 0,
        processingRows: 0,
        completedRows: 0,
        failedRows: 0,
      },
      batches: [],
    },
  };
  const reportingEngagementCounts = input.reportingEngagementCounts ?? null;
  const reportingOverview = input.reportingOverview ?? null;
  const reportingMetrics = input.reportingMetrics ?? [];
  const reportingOrgUnitComparisons = input.reportingOrgUnitComparisons ?? [];
  const reportingTemplateComparisons = input.reportingTemplateComparisons ?? [];
  const reportingTrends = input.reportingTrends ?? null;
  const renderOrgUnitSummary = (orgUnitId: string): HonoElement => {
    const orgUnit = orgUnitById.get(orgUnitId);

    if (orgUnit === undefined) {
      return <strong>{orgUnitId}</strong>;
    }

    return (
      <>
        <strong>{orgUnit.displayName}</strong>
        <div class="ct-admin__meta">{`${orgUnit.id} · ${orgUnit.unitType}`}</div>
      </>
    );
  };
  const renderBadgeTemplateScopeSummary = (badgeTemplateIds: readonly string[]): string => {
    if (badgeTemplateIds.length === 0) {
      return "All badge templates in scope";
    }

    return badgeTemplateIds
      .map((badgeTemplateId) => templateById.get(badgeTemplateId)?.title ?? badgeTemplateId)
      .join(", ");
  };
  const getReportingOrgUnitLabel = (orgUnitId: string): string => {
    return orgUnitById.get(orgUnitId)?.displayName ?? orgUnitId;
  };
  const getReportingComparisonLabel = (row: TenantReportingComparisonRowRecord): string => {
    if (row.groupBy === "badgeTemplate") {
      return templateById.get(row.groupId)?.title ?? row.groupId;
    }

    return getReportingOrgUnitLabel(row.groupId);
  };
  const renderReportingComparisonGroupLabel = (
    row: TenantReportingComparisonRowRecord,
  ): HonoElement => {
    if (row.groupBy === "badgeTemplate") {
      const template = templateById.get(row.groupId);

      if (template === undefined) {
        return <strong>{row.groupId}</strong>;
      }

      return (
        <>
          <strong>{template.title}</strong>
          <div class="ct-admin__meta">{template.id}</div>
        </>
      );
    }

    return renderOrgUnitSummary(row.groupId);
  };
  const buildReportingLegendDetail = (input: {
    publicBadgeViewCount: number;
    claimRate: number;
    shareRate: number;
  }): string => {
    return `${formatReportingCount(input.publicBadgeViewCount)} public views · ${formatReportingRate(
      input.claimRate,
    )} claim · ${formatReportingRate(input.shareRate)} share`;
  };
  const buildReportingComparisonSeries = (
    rows: readonly TenantReportingComparisonRowRecord[],
  ): ReportingVisualSeriesPoint[] => {
    return rows
      .map((row) => ({
        label: getReportingComparisonLabel(row),
        value: row.issuedCount,
        detail: buildReportingLegendDetail({
          publicBadgeViewCount: row.publicBadgeViewCount,
          claimRate: row.claimRate,
          shareRate: row.shareRate,
        }),
      }))
      .sort((left, right) => {
        if (right.value !== left.value) {
          return right.value - left.value;
        }

        return left.label.localeCompare(right.label);
      });
  };
  const hasReportingActivity = (input: ReportingActivityCounts): boolean => {
    return (
      input.issuedCount > 0 ||
      input.publicBadgeViewCount > 0 ||
      input.verificationViewCount > 0 ||
      input.shareClickCount > 0 ||
      input.learnerClaimCount > 0 ||
      input.walletAcceptCount > 0
    );
  };
  const classifyReportingPanelState = (activeRowCount: number): ReportingPanelState => {
    if (activeRowCount === 0) {
      return "empty";
    }

    return activeRowCount === 1 ? "sparse" : "rich";
  };
  const renderReportingStateShell = (input: {
    description: string;
    eyebrow: string;
    state: Exclude<ReportingPanelState, "rich">;
    title: string;
  }): HonoElement => {
    return (
      <section
        class="ct-admin__reporting-state-shell ct-stack"
        data-reporting-panel-state={input.state}
      >
        <p class="ct-admin__eyebrow">{input.eyebrow}</p>
        <h3>{input.title}</h3>
        <p class="ct-admin__hint">{input.description}</p>
      </section>
    );
  };
  const renderReportingVisualModule = (input: {
    description: string;
    density?: "regular" | "compact";
    emptyMessage?: string;
    headingLevel?: "h3" | "h4";
    id?: string;
    kind:
      | "comparison-bars"
      | "comparison-ranked"
      | "journey-funnel"
      | "stacked-summary"
      | "trend-area"
      | "trend-series";
    note?: string;
    series: readonly ReportingVisualSeriesPoint[];
    seriesOrder?: "input" | "value-desc";
    showLegend?: boolean;
    showTrendContext?: boolean;
    sparseMessage?: string;
    summaryOverride?: string;
    title: string;
  }): HonoElement => {
    return (
      <div class="ct-admin__reporting-visual-shell">
        {renderReporting(input)}
        {input.note === undefined || input.note.trim().length === 0 ? null : (
          <p class="ct-admin__reporting-visual-note">{input.note}</p>
        )}
      </div>
    );
  };
  const renderReportingTrendCallout = (input: {
    kind: "peak" | "latest";
    label: string;
    row: TenantReportingTrendRecord["series"][number];
  }): HonoElement => {
    return (
      <article class="ct-admin__reporting-trend-callout" data-reporting-trend-callout={input.kind}>
        <p class="ct-admin__eyebrow">{input.label}</p>
        <h3>{formatReportingDateLabel(input.row.bucketStart)}</h3>
        <p class="ct-admin__meta">{`${formatReportingCount(input.row.issuedCount)} issued badges`}</p>
        <p class="ct-admin__meta">
          {`${formatReportingCount(input.row.publicBadgeViewCount)} public views · ${formatReportingCount(input.row.shareClickCount)} share clicks · ${formatReportingCount(input.row.walletAcceptCount)} wallet accepts`}
        </p>
      </article>
    );
  };
  const renderReportingCountCell = (value: number): string => {
    return formatReportingCount(value);
  };
  const buildVisibleOrgUnitLineage = (orgUnitId: string): TenantOrgUnitRecord[] => {
    const lineage: TenantOrgUnitRecord[] = [];
    const visited = new Set<string>();
    let currentOrgUnitId: string | null = orgUnitId;

    while (currentOrgUnitId !== null) {
      if (visited.has(currentOrgUnitId)) {
        break;
      }

      visited.add(currentOrgUnitId);
      const orgUnit = orgUnitById.get(currentOrgUnitId);

      if (orgUnit === undefined) {
        break;
      }

      if (!isReportingHierarchyLevel(orgUnit.unitType)) {
        break;
      }

      lineage.push(orgUnit);
      currentOrgUnitId = orgUnit.parentOrgUnitId;
    }

    return lineage;
  };
  const aggregateReportingHierarchyRows = (input: {
    comparisonRows: readonly TenantReportingComparisonRowRecord[];
    focusOrgUnitId?: string | undefined;
    level: ReportingHierarchyLevel;
  }): ReportingHierarchyRow[] => {
    const focusOrgUnit =
      input.focusOrgUnitId === undefined ? null : (orgUnitById.get(input.focusOrgUnitId) ?? null);

    if (focusOrgUnit !== null && !isReportingHierarchyLevel(focusOrgUnit.unitType)) {
      return [];
    }

    const groups = new Map<
      string,
      {
        orgUnit: TenantOrgUnitRecord;
        issuedCount: number;
        publicBadgeViewCount: number;
        verificationViewCount: number;
        shareClickCount: number;
        learnerClaimCount: number;
        walletAcceptCount: number;
        weightedClaimRateTotal: number;
        weightedShareRateTotal: number;
      }
    >();

    for (const row of input.comparisonRows) {
      const lineage = buildVisibleOrgUnitLineage(row.groupId);

      if (lineage.length === 0) {
        continue;
      }

      if (focusOrgUnit !== null && !lineage.some((orgUnit) => orgUnit.id === focusOrgUnit.id)) {
        continue;
      }

      const targetOrgUnit = lineage.find((orgUnit) => orgUnit.unitType === input.level);

      if (targetOrgUnit === undefined) {
        continue;
      }

      const group =
        groups.get(targetOrgUnit.id) ??
        (() => {
          const created = {
            orgUnit: targetOrgUnit,
            issuedCount: 0,
            publicBadgeViewCount: 0,
            verificationViewCount: 0,
            shareClickCount: 0,
            learnerClaimCount: 0,
            walletAcceptCount: 0,
            weightedClaimRateTotal: 0,
            weightedShareRateTotal: 0,
          };
          groups.set(targetOrgUnit.id, created);
          return created;
        })();

      group.issuedCount += row.issuedCount;
      group.publicBadgeViewCount += row.publicBadgeViewCount;
      group.verificationViewCount += row.verificationViewCount;
      group.shareClickCount += row.shareClickCount;
      group.learnerClaimCount += row.learnerClaimCount;
      group.walletAcceptCount += row.walletAcceptCount;
      group.weightedClaimRateTotal += row.claimRate * row.issuedCount;
      group.weightedShareRateTotal += row.shareRate * row.issuedCount;
    }

    return Array.from(groups.values())
      .map((group) => {
        const issuedCount = group.issuedCount;

        return {
          orgUnitId: group.orgUnit.id,
          level: input.level,
          issuedCount,
          publicBadgeViewCount: group.publicBadgeViewCount,
          verificationViewCount: group.verificationViewCount,
          shareClickCount: group.shareClickCount,
          learnerClaimCount: group.learnerClaimCount,
          walletAcceptCount: group.walletAcceptCount,
          claimRate: issuedCount === 0 ? 0 : group.weightedClaimRateTotal / issuedCount,
          shareRate: issuedCount === 0 ? 0 : group.weightedShareRateTotal / issuedCount,
        };
      })
      .sort((left, right) => {
        if (right.issuedCount !== left.issuedCount) {
          return right.issuedCount - left.issuedCount;
        }

        return left.orgUnitId.localeCompare(right.orgUnitId);
      });
  };
  const buildReportingHierarchyDrillHref = (orgUnitId: string): string => {
    return `${reportingExplorePath}#${buildReportingHierarchyFocusId(orgUnitId)}`;
  };
  const renderReportingHierarchyRowLabel = (row: ReportingHierarchyRow): HonoElement => {
    const orgUnit = orgUnitById.get(row.orgUnitId);

    if (orgUnit === undefined || !isReportingHierarchyLevel(orgUnit.unitType)) {
      return renderOrgUnitSummary(row.orgUnitId);
    }

    const nextLevel = getNextReportingHierarchyLevel(orgUnit.unitType);

    if (nextLevel === null) {
      return (
        <>
          {renderOrgUnitSummary(row.orgUnitId)}
          <div class="ct-admin__meta">Deepest reporting level</div>
        </>
      );
    }

    return (
      <>
        {renderOrgUnitSummary(row.orgUnitId)}
        <div class="ct-admin__meta">
          <a data-reporting-drill-link href={buildReportingHierarchyDrillHref(row.orgUnitId)}>
            View {formatReportingHierarchyLevelLabel(nextLevel).toLowerCase()} drilldown
          </a>
        </div>
      </>
    );
  };
  const renderReportingHierarchyRows = (
    rows: readonly ReportingHierarchyRow[],
    emptyLabel: string,
  ): HonoElement => {
    if (rows.length === 0) {
      return <AdminEmptyTableRow colSpan={9}>{emptyLabel}</AdminEmptyTableRow>;
    }

    return (
      <>
        {rows.map((row) => (
          <tr>
            <td>{renderReportingHierarchyRowLabel(row)}</td>
            <td>
              <span class="ct-admin__reporting-table-number">
                {renderReportingCountCell(row.issuedCount)}
              </span>
            </td>
            <td>
              <span class="ct-admin__reporting-table-number">
                {renderReportingCountCell(row.publicBadgeViewCount)}
              </span>
            </td>
            <td>
              <span class="ct-admin__reporting-table-number">
                {renderReportingCountCell(row.verificationViewCount)}
              </span>
            </td>
            <td>
              <span class="ct-admin__reporting-table-number">
                {renderReportingCountCell(row.shareClickCount)}
              </span>
            </td>
            <td>
              <span class="ct-admin__reporting-table-number">
                {renderReportingCountCell(row.learnerClaimCount)}
              </span>
            </td>
            <td>
              <span class="ct-admin__reporting-table-number">
                {renderReportingCountCell(row.walletAcceptCount)}
              </span>
            </td>
            <td>{formatReportingRate(row.claimRate)}</td>
            <td>{formatReportingRate(row.shareRate)}</td>
          </tr>
        ))}
      </>
    );
  };

  for (const version of input.badgeRuleVersions) {
    const versions = versionsByRuleId.get(version.ruleId);

    if (versions === undefined) {
      versionsByRuleId.set(version.ruleId, [version]);
      continue;
    }

    versions.push(version);
  }

  for (const versions of versionsByRuleId.values()) {
    versions.sort((left, right) => right.versionNumber - left.versionNumber);
  }

  const templateRows =
    input.badgeTemplates.length === 0 ? (
      <AdminEmptyTableRow colSpan={5}>No badge templates found.</AdminEmptyTableRow>
    ) : (
      input.badgeTemplates.map((template) => {
        const showcaseHref = `/showcase/${encodeURIComponent(
          input.tenant.id,
        )}?badgeTemplateId=${encodeURIComponent(template.id)}`;
        const criteriaRegistryHref = `/showcase/${encodeURIComponent(
          input.tenant.id,
        )}/criteria?badgeTemplateId=${encodeURIComponent(template.id)}`;
        return (
          <tr>
            <td>
              {template.imageUri === null ? (
                <span class="ct-admin__template-placeholder">No image</span>
              ) : (
                <img
                  class="ct-admin__template-image"
                  src={template.imageUri}
                  alt={`${template.title} artwork`}
                  loading="lazy"
                />
              )}
            </td>
            <td>
              <strong>{template.title}</strong>
              <AdminMeta>{template.id}</AdminMeta>
            </td>
            <td>{template.slug}</td>
            <td>{formatIsoTimestamp(template.updatedAt)}</td>
            <td>
              <a href={showcaseHref} target="_blank" rel="noopener noreferrer">
                Showcase
              </a>
              {" · "}
              <a href={criteriaRegistryHref} target="_blank" rel="noopener noreferrer">
                Criteria
              </a>
            </td>
          </tr>
        );
      })
    );

  const orgUnitRows =
    input.orgUnits.length === 0 ? (
      <AdminEmptyTableRow colSpan={4}>No org units found.</AdminEmptyTableRow>
    ) : (
      input.orgUnits.map((orgUnit) => (
        <tr>
          <td>{orgUnit.displayName}</td>
          <td>{orgUnit.unitType}</td>
          <td>{orgUnit.id}</td>
          <td>{orgUnit.isActive ? "Active" : "Inactive"}</td>
        </tr>
      ))
    );

  const apiKeyRows =
    input.activeApiKeys.length === 0 ? (
      <AdminEmptyTableRow colSpan={5}>No active API keys found.</AdminEmptyTableRow>
    ) : (
      input.activeApiKeys.map((apiKey) => {
        const revokeApiKeyPath = `/v1/tenants/${encodeURIComponent(
          input.tenant.id,
        )}/api-keys/${encodeURIComponent(apiKey.id)}/revoke`;

        return (
          <tr>
            <td>{apiKey.label}</td>
            <td>{apiKey.keyPrefix}</td>
            <td>{formatScopesSummary(apiKey.scopesJson)}</td>
            <td>{apiKey.expiresAt === null ? "Never" : formatIsoTimestamp(apiKey.expiresAt)}</td>
            <td>
              <AdminButton
                type="button"
                variant="danger"
                dataAttributes={{
                  "data-revoke-api-key-path": revokeApiKeyPath,
                  "data-api-key-label": apiKey.label,
                }}
              >
                Revoke
              </AdminButton>
            </td>
          </tr>
        );
      })
    );

  const assignableTenantRoles: TenantMembershipRole[] =
    input.membershipRole === "owner"
      ? ["owner", "admin", "issuer", "viewer"]
      : ["admin", "issuer", "viewer"];
  const tenantMemberRoleOptions = (selectedRole: TenantMembershipRole): HonoElement => {
    const roles: readonly TenantMembershipRole[] =
      input.membershipRole === "owner" ? assignableTenantRoles : ["admin", "issuer", "viewer"];

    return (
      <>
        {roles.map((role) => (
          <option value={role} selected={role === selectedRole}>
            {role}
          </option>
        ))}
      </>
    );
  };
  const tenantMemberRows =
    input.tenantMembers.length === 0 ? (
      <AdminEmptyTableRow colSpan={6}>No tenant members found.</AdminEmptyTableRow>
    ) : (
      input.tenantMembers.map((member) => {
        const canManageMember =
          member.userId !== input.userId &&
          (input.membershipRole === "owner" || member.role !== "owner");

        return (
          <tr>
            <td>
              <span class="ct-admin__member-identity">{member.email}</span>
              <AdminMeta>{member.userId}</AdminMeta>
            </td>
            <td>
              {canManageMember ? (
                <select
                  aria-label={`Tenant role for ${member.email}`}
                  data-tenant-member-role-user-id={member.userId}
                  data-tenant-member-current-role={member.role}
                >
                  {tenantMemberRoleOptions(member.role)}
                </select>
              ) : (
                <AdminStatusPill>{member.role}</AdminStatusPill>
              )}
            </td>
            <td>{formatIsoTimestamp(member.createdAt)}</td>
            <td>{formatIsoTimestamp(member.updatedAt)}</td>
            <td>{member.userId === input.userId ? "You" : "Member"}</td>
            <td>
              {canManageMember ? (
                <AdminActions>
                  <AdminButton
                    type="button"
                    size="tiny"
                    variant="secondary"
                    dataAttributes={{
                      "data-tenant-member-invite-user-id": member.userId,
                      "data-tenant-member-email": member.email,
                    }}
                  >
                    Resend invite
                  </AdminButton>
                  <AdminButton
                    type="button"
                    size="tiny"
                    variant="danger"
                    dataAttributes={{
                      "data-tenant-member-remove-user-id": member.userId,
                      "data-tenant-member-email": member.email,
                    }}
                  >
                    Remove
                  </AdminButton>
                </AdminActions>
              ) : (
                <AdminMeta as="span">
                  {member.userId === input.userId ? "Current user" : "Owner action"}
                </AdminMeta>
              )}
            </td>
          </tr>
        );
      })
    );

  const membershipScopeRows =
    input.membershipOrgUnitScopes.length === 0 ? (
      <AdminEmptyTableRow colSpan={5}>No scoped roles assigned yet.</AdminEmptyTableRow>
    ) : (
      input.membershipOrgUnitScopes.map((scope) => {
        const scopeLabel = orgUnitById.get(scope.orgUnitId)?.displayName ?? scope.orgUnitId;

        return (
          <tr>
            <td>
              <strong>{scope.userId}</strong>
            </td>
            <td>{renderOrgUnitSummary(scope.orgUnitId)}</td>
            <td>
              <AdminStatusPill>{scope.role}</AdminStatusPill>
            </td>
            <td>{formatIsoTimestamp(scope.updatedAt)}</td>
            <td>
              <AdminButton
                type="button"
                size="tiny"
                variant="danger"
                dataAttributes={{
                  "data-membership-scope-remove-user-id": scope.userId,
                  "data-membership-scope-remove-org-unit-id": scope.orgUnitId,
                  "data-membership-scope-remove-label": `${scope.userId} · ${scopeLabel}`,
                }}
              >
                Remove
              </AdminButton>
            </td>
          </tr>
        );
      })
    );

  const delegatedGrantRows =
    input.delegatedIssuingAuthorityGrants.length === 0 ? (
      <AdminEmptyTableRow colSpan={6}>No delegated authority grants exist yet.</AdminEmptyTableRow>
    ) : (
      input.delegatedIssuingAuthorityGrants.map((grant) => {
        const canRemove = grant.status === "active" || grant.status === "scheduled";
        const statusMeta =
          grant.status === "revoked"
            ? grant.revokedAt === null
              ? "Removed"
              : `Removed ${formatIsoTimestamp(grant.revokedAt)}`
            : `Ends ${formatIsoTimestamp(grant.endsAt)}`;
        return (
          <tr>
            <td>
              <strong>{grant.delegateUserId}</strong>
              <AdminMeta>{grant.id}</AdminMeta>
            </td>
            <td>{renderOrgUnitSummary(grant.orgUnitId)}</td>
            <td>
              {grant.allowedActions
                .map((action) => formatDelegatedIssuingActionLabel(action))
                .join(", ")}
              <AdminMeta>{renderBadgeTemplateScopeSummary(grant.badgeTemplateIds)}</AdminMeta>
            </td>
            <td>
              <strong>{formatIsoTimestamp(grant.startsAt)}</strong>
              <AdminMeta>Starts</AdminMeta>
              <AdminMeta>Granted by {grant.delegatedByUserId ?? "system"}</AdminMeta>
            </td>
            <td>
              <AdminStatusPill tone={grant.status}>{grant.status}</AdminStatusPill>
              <AdminMeta>{statusMeta}</AdminMeta>
              {grant.revokedReason === null ? null : (
                <AdminMeta>Reason: {grant.revokedReason}</AdminMeta>
              )}
            </td>
            <td>
              {canRemove ? (
                <AdminButton
                  type="button"
                  size="tiny"
                  variant="danger"
                  dataAttributes={{
                    "data-delegated-grant-remove-user-id": grant.delegateUserId,
                    "data-delegated-grant-remove-id": grant.id,
                    "data-delegated-grant-remove-label": `${grant.delegateUserId} · ${grant.id}`,
                  }}
                >
                  Remove
                </AdminButton>
              ) : (
                <AdminMeta as="span">No action</AdminMeta>
              )}
            </td>
          </tr>
        );
      })
    );

  const ruleRows =
    input.badgeRules.length === 0 ? (
      <AdminEmptyTableRow colSpan={8}>
        No badge rules found. <a href={ruleBuilderPath}>Create your first rule</a>.
      </AdminEmptyTableRow>
    ) : (
      input.badgeRules.map((rule) => {
        const templateTitle = templateById.get(rule.badgeTemplateId)?.title ?? rule.badgeTemplateId;
        const versions = versionsByRuleId.get(rule.id) ?? [];
        const latestVersion = versions[0] ?? null;
        const submitApprovalPath =
          latestVersion === null
            ? null
            : `/v1/tenants/${encodeURIComponent(input.tenant.id)}/badge-rules/${encodeURIComponent(
                rule.id,
              )}/versions/${encodeURIComponent(latestVersion.id)}/submit-approval`;
        const approvePath =
          latestVersion === null
            ? null
            : `/v1/tenants/${encodeURIComponent(input.tenant.id)}/badge-rules/${encodeURIComponent(
                rule.id,
              )}/versions/${encodeURIComponent(latestVersion.id)}/decision`;
        const activatePath =
          latestVersion === null
            ? null
            : `/v1/tenants/${encodeURIComponent(input.tenant.id)}/badge-rules/${encodeURIComponent(
                rule.id,
              )}/versions/${encodeURIComponent(latestVersion.id)}/activate`;
        const actionButtons: HonoElement[] = [];

        if (latestVersion !== null) {
          if (latestVersion.status === "draft" || latestVersion.status === "rejected") {
            actionButtons.push(
              <AdminButton
                type="button"
                size="tiny"
                dataAttributes={{
                  "data-rule-submit-path": submitApprovalPath ?? "",
                  "data-rule-label": rule.name,
                }}
              >
                Submit
              </AdminButton>,
            );
          }

          if (latestVersion.status === "pending_approval") {
            actionButtons.push(
              <AdminButton
                type="button"
                size="tiny"
                dataAttributes={{
                  "data-rule-decision-path": approvePath ?? "",
                  "data-rule-decision": "approved",
                  "data-rule-label": rule.name,
                }}
              >
                Approve
              </AdminButton>,
            );
            actionButtons.push(
              <AdminButton
                type="button"
                size="tiny"
                variant="danger"
                dataAttributes={{
                  "data-rule-decision-path": approvePath ?? "",
                  "data-rule-decision": "rejected",
                  "data-rule-label": rule.name,
                }}
              >
                Reject
              </AdminButton>,
            );
          }

          if (latestVersion.status === "approved" || latestVersion.status === "active") {
            actionButtons.push(
              <AdminButton
                type="button"
                size="tiny"
                dataAttributes={{
                  "data-rule-activate-path": activatePath ?? "",
                  "data-rule-label": rule.name,
                }}
              >
                Activate
              </AdminButton>,
            );
          }
        }

        return (
          <tr>
            <td>
              <strong>{rule.name}</strong>
              <AdminMeta>{rule.id}</AdminMeta>
            </td>
            <td>{templateTitle}</td>
            <td>{rule.lmsProviderKind}</td>
            <td>{rule.activeVersionId ?? "none"}</td>
            <td>
              {latestVersion === null
                ? "none"
                : `v${String(latestVersion.versionNumber)} (${latestVersion.id})`}
            </td>
            <td>
              <AdminStatusPill tone={latestVersion?.status ?? "none"}>
                {latestVersion?.status ?? "none"}
              </AdminStatusPill>
            </td>
            <td>{formatIsoTimestamp(rule.updatedAt)}</td>
            <td>
              {actionButtons.length > 0 ? (
                <AdminActions>{actionButtons}</AdminActions>
              ) : (
                <AdminMeta as="span">No actions</AdminMeta>
              )}
            </td>
          </tr>
        );
      })
    );

  const manualIssueApiPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/assertions/manual-issue`;
  const createApiKeyPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/api-keys`;
  const createOrgUnitPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/org-units`;
  const badgeTemplateApiPathPrefix = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/badge-templates`;
  const badgeRuleApiPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/badge-rules`;
  const badgeRuleValueListApiPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/badge-rule-value-lists`;
  const badgeRulePreviewSimulationApiPath = `${badgeRuleApiPath}/preview-simulate`;
  const badgeRuleReviewQueueApiPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/badge-rules/review-queue`;
  const assertionsApiPathPrefix = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/assertions`;
  const issuedBadgeRowsPath = `${assertionsApiPathPrefix}/table-rows`;
  const tenantUsersApiPathPrefix = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/users`;
  const adminAuditLogPath = `/admin/audit-logs?tenantId=${encodeURIComponent(input.tenant.id)}`;
  const showcasePath = `/showcase/${encodeURIComponent(input.tenant.id)}`;
  const orgUnitParentOptions = input.orgUnits
    .filter((orgUnit) => orgUnit.isActive)
    .map((orgUnit) => {
      return (
        <option value={orgUnit.id} data-unit-type={orgUnit.unitType}>
          {`${orgUnit.displayName} (${orgUnit.unitType})`}
        </option>
      );
    });
  const activeOrgUnitOptions = input.orgUnits
    .filter((orgUnit) => orgUnit.isActive)
    .map((orgUnit) => {
      return <option value={orgUnit.id}>{`${orgUnit.displayName} (${orgUnit.unitType})`}</option>;
    });
  const templateOptions = input.badgeTemplates.map((template, index) => {
    return (
      <option value={template.id} selected={index === 0}>
        {`${template.title} (${template.id})`}
      </option>
    );
  });
  const templateFilterOptions = input.badgeTemplates.map((template) => {
    return <option value={template.id}>{template.title}</option>;
  });
  const formatRuleOption = (
    rule: BadgeIssuanceRuleRecord,
    includeSelected: boolean,
    index: number,
  ): HonoElement => {
    const versions = versionsByRuleId.get(rule.id) ?? [];
    const latestVersion = versions[0] ?? null;

    return (
      <option
        value={rule.id}
        selected={includeSelected && index === 0}
        data-version-id={latestVersion?.id ?? ""}
        data-version-status={latestVersion?.status ?? "none"}
        data-rule-label={rule.name}
      >
        {`${rule.name} (${rule.id}) · latest ${
          latestVersion === null
            ? "none"
            : `v${String(latestVersion.versionNumber)} ${latestVersion.status}`
        }`}
      </option>
    );
  };
  const ruleOptions = input.badgeRules.map((rule, index) => formatRuleOption(rule, true, index));
  const templateSelectOptions =
    templateOptions.length > 0 ? (
      templateOptions
    ) : (
      <option value="">No badge templates available</option>
    );
  const activeOrgUnitSelectOptions =
    activeOrgUnitOptions.length > 0 ? (
      activeOrgUnitOptions
    ) : (
      <option value="">No active org units available</option>
    );
  const ruleSelectOptions =
    ruleOptions.length > 0 ? ruleOptions : <option value="">No rules available</option>;
  const reportingState = reportingOverview?.filters.state ?? null;
  const reportingIssuedFromValue = reportingOverview?.filters.issuedFrom ?? "";
  const reportingIssuedToValue = reportingOverview?.filters.issuedTo ?? "";
  const reportingBadgeTemplateIdValue = reportingOverview?.filters.badgeTemplateId ?? "";
  const reportingOrgUnitIdValue = reportingOverview?.filters.orgUnitId ?? "";
  const reportingTemplateFilterOptions = input.badgeTemplates.map((template) => {
    return (
      <option value={template.id} selected={reportingBadgeTemplateIdValue === template.id}>
        {template.title}
      </option>
    );
  });
  const reportingOrgUnitOptions = input.orgUnits
    .filter((orgUnit) => orgUnit.isActive)
    .map((orgUnit) => {
      return (
        <option value={orgUnit.id} selected={reportingOrgUnitIdValue === orgUnit.id}>
          {`${orgUnit.displayName} (${orgUnit.unitType})`}
        </option>
      );
    });
  const reportingPageQueryEntries = buildReportingPageQueryEntries({
    issuedFrom: reportingIssuedFromValue,
    issuedTo: reportingIssuedToValue,
    badgeTemplateId: reportingBadgeTemplateIdValue,
    orgUnitId: reportingOrgUnitIdValue,
    state: reportingState ?? undefined,
  });
  const reportingAggregateExportEntries = [...reportingPageQueryEntries] as const;
  const reportingExploreHref = buildPathWithQuery(reportingExplorePath, reportingPageQueryEntries);
  const reportingTrendsHref = buildPathWithQuery(reportingTrendsPath, reportingPageQueryEntries);
  const reportingReportsHref = buildPathWithQuery(reportingReportsPath, reportingPageQueryEntries);
  const reportingReportsExportsHref = `${reportingReportsHref}#reporting-reports-exports`;
  const reportingOverviewExportHref = buildPathWithQuery(
    `/v1/tenants/${encodeURIComponent(input.tenant.id)}/reporting/overview/export.csv`,
    reportingAggregateExportEntries,
  );
  const reportingEngagementExportHref = buildPathWithQuery(
    `/v1/tenants/${encodeURIComponent(input.tenant.id)}/reporting/engagement/export.csv`,
    reportingAggregateExportEntries,
  );
  const reportingTrendsExportHref = buildPathWithQuery(
    `/v1/tenants/${encodeURIComponent(input.tenant.id)}/reporting/trends/export.csv`,
    [...reportingAggregateExportEntries, ["bucket", "day"]] as const,
  );
  const reportingTemplateComparisonExportHref = buildPathWithQuery(
    `/v1/tenants/${encodeURIComponent(input.tenant.id)}/reporting/comparisons/export.csv`,
    [...reportingAggregateExportEntries, ["groupBy", "badgeTemplate"]] as const,
  );
  const reportingOrgUnitComparisonExportHref = buildPathWithQuery(
    `/v1/tenants/${encodeURIComponent(input.tenant.id)}/reporting/comparisons/export.csv`,
    [...reportingAggregateExportEntries, ["groupBy", "orgUnit"]] as const,
  );
  const buildReportingHierarchyExportHref = (focus: {
    focusOrgUnitId: string;
    level: ReportingHierarchyLevel;
  }): string => {
    return buildPathWithQuery(
      `/v1/tenants/${encodeURIComponent(input.tenant.id)}/reporting/hierarchy/export.csv`,
      buildReportingHierarchyQueryEntries({
        issuedFrom: reportingIssuedFromValue,
        issuedTo: reportingIssuedToValue,
        badgeTemplateId: reportingBadgeTemplateIdValue,
        orgUnitId: reportingOrgUnitIdValue,
        state: reportingState ?? undefined,
        focusOrgUnitId: focus.focusOrgUnitId,
        level: focus.level,
      }),
    );
  };
  const reportingExportsPanelMarkup = (
    <article id="reporting-reports-exports" class="ct-admin__panel ct-stack">
      <div class="ct-cluster">
        <h2>Export CSV</h2>
        <span class="ct-admin__status-pill">Supporting operations</span>
      </div>
      <p>
        Download CSV files for the selected filters. These links preserve issue date, badge,
        organization, and lifecycle state selections.
      </p>
      <div class="ct-cluster">
        <AdminButtonLink href={reportingOverviewExportHref} variant="secondary">
          Overview CSV
        </AdminButtonLink>
        <AdminButtonLink href={reportingEngagementExportHref} variant="secondary">
          Engagement CSV
        </AdminButtonLink>
        <AdminButtonLink href={reportingTrendsExportHref} variant="secondary">
          Trends CSV
        </AdminButtonLink>
        <AdminButtonLink href={reportingTemplateComparisonExportHref} variant="secondary">
          Template comparisons CSV
        </AdminButtonLink>
        <AdminButtonLink href={reportingOrgUnitComparisonExportHref} variant="secondary">
          Org-unit comparisons CSV
        </AdminButtonLink>
      </div>
      <p class="ct-admin__hint">
        Recipient-level ledger export stays in Operations for owner/admin users and does not appear
        in the reporting workspace.
      </p>
    </article>
  );
  const reportingGeneratedAtLabel =
    reportingOverview === null
      ? "Generated just now"
      : `Generated ${formatIsoTimestamp(reportingOverview.generatedAt)}`;
  const reportingTrendSeries = reportingTrends?.series ?? [];
  const reportingTrendActivityRowCount = reportingTrendSeries.filter((row) =>
    hasReportingActivity(row),
  ).length;
  const reportingTrendState = classifyReportingPanelState(reportingTrendActivityRowCount);
  const reportingTrendStartRow = reportingTrendSeries[0] ?? null;
  const reportingTrendLatestRow =
    reportingTrendSeries[reportingTrendSeries.length - 1] ?? reportingTrendStartRow;
  const reportingTrendPeakRow =
    reportingTrendSeries.reduce<TenantReportingTrendRecord["series"][number] | null>(
      (highestRow, row) => {
        if (highestRow === null || row.issuedCount > highestRow.issuedCount) {
          return row;
        }

        return highestRow;
      },
      null,
    ) ?? reportingTrendLatestRow;
  const reportingMomentumDelta =
    reportingTrendStartRow === null || reportingTrendLatestRow === null
      ? null
      : reportingTrendLatestRow.issuedCount - reportingTrendStartRow.issuedCount;
  const reportingMomentumDeltaLabel =
    reportingMomentumDelta === null
      ? "No trend delta yet"
      : reportingMomentumDelta === 0
        ? "No change from start"
        : `${reportingMomentumDelta > 0 ? "+" : ""}${formatReportingCount(
            reportingMomentumDelta,
          )} from start`;
  const reportingMomentumVisualMarkup =
    reportingTrendSeries.length === 0
      ? null
      : renderReportingVisualModule({
          kind: "trend-area",
          id: "reporting-highlights-momentum",
          headingLevel: "h4",
          title: "90-day issuance momentum",
          description:
            "Area trend for the default reporting window, generated from the same daily issued counts used in Trend Detail.",
          series: reportingTrendSeries.map((row) => ({
            label: formatReportingDateLabel(row.bucketStart),
            value: row.issuedCount,
            detail: `${formatReportingCount(row.publicBadgeViewCount)} public views · ${formatReportingCount(row.walletAcceptCount)} wallet accepts`,
          })),
          ...(reportingTrendStartRow === null ||
          reportingTrendLatestRow === null ||
          reportingTrendPeakRow === null
            ? {}
            : {
                summaryOverride: `${reportingMomentumDeltaLabel}. Peak was ${formatReportingCount(
                  reportingTrendPeakRow.issuedCount,
                )} on ${formatReportingDateLabel(reportingTrendPeakRow.bucketStart)}; latest is ${formatReportingCount(
                  reportingTrendLatestRow.issuedCount,
                )} on ${formatReportingDateLabel(reportingTrendLatestRow.bucketStart)}.`,
              }),
        });
  const reportingSummaryMomentumMarkup = (
    <section class="ct-admin__reporting-summary-feature" aria-label="Issuance momentum">
      {reportingMomentumVisualMarkup ?? (
        <div class="ct-admin__reporting-summary-feature-empty ct-stack">
          <p class="ct-admin__eyebrow">90-day momentum</p>
          <h3>No issuance trend yet</h3>
          <p class="ct-admin__hint">
            The summary becomes visual once the selected reporting slice has daily issued badge
            counts.
          </p>
        </div>
      )}
      <dl class="ct-admin__reporting-summary-feature-stats">
        <div>
          <dt>Latest day</dt>
          <dd>
            {reportingTrendLatestRow === null
              ? "No activity"
              : `${formatReportingCount(
                  reportingTrendLatestRow.issuedCount,
                )} on ${formatReportingDateLabel(reportingTrendLatestRow.bucketStart)}`}
          </dd>
        </div>
        <div>
          <dt>Peak day</dt>
          <dd>
            {reportingTrendPeakRow === null
              ? "No activity"
              : `${formatReportingCount(
                  reportingTrendPeakRow.issuedCount,
                )} on ${formatReportingDateLabel(reportingTrendPeakRow.bucketStart)}`}
          </dd>
        </div>
      </dl>
    </section>
  );
  const selectTopReportingComparisonRow = (
    rows: readonly TenantReportingComparisonRowRecord[],
  ): TenantReportingComparisonRowRecord | null => {
    return (
      rows
        .filter((row) => hasReportingActivity(row))
        .sort((left, right) => {
          if (right.issuedCount !== left.issuedCount) {
            return right.issuedCount - left.issuedCount;
          }

          return getReportingComparisonLabel(left).localeCompare(
            getReportingComparisonLabel(right),
          );
        })[0] ?? null
    );
  };
  const buildReportingIssuedShareLabel = (
    row: TenantReportingComparisonRowRecord,
    rows: readonly TenantReportingComparisonRowRecord[],
  ): string => {
    const totalIssued = rows.reduce((sum, item) => sum + item.issuedCount, 0);

    if (totalIssued <= 0) {
      return `${formatReportingCount(row.issuedCount)} issued`;
    }

    return `${formatReportingRate((row.issuedCount / totalIssued) * 100)} of visible issued volume`;
  };
  const reportingTopTemplateRow = selectTopReportingComparisonRow(reportingTemplateComparisons);
  const reportingTopOrgUnitRow = selectTopReportingComparisonRow(reportingOrgUnitComparisons);
  const reportingClaimRateLeader =
    [...reportingTemplateComparisons, ...reportingOrgUnitComparisons]
      .filter((row) => row.issuedCount >= REPORTING_RATE_MIN_ISSUED)
      .sort((left, right) => {
        if (right.claimRate !== left.claimRate) {
          return right.claimRate - left.claimRate;
        }

        if (right.issuedCount !== left.issuedCount) {
          return right.issuedCount - left.issuedCount;
        }

        return getReportingComparisonLabel(left).localeCompare(getReportingComparisonLabel(right));
      })[0] ?? null;
  const reportingInsightItems: Array<{
    detail: string;
    eyebrow: string;
    metric: string;
    title: string;
  }> = [];

  if (reportingTopTemplateRow !== null) {
    reportingInsightItems.push({
      eyebrow: "Template signal",
      metric: formatReportingCount(reportingTopTemplateRow.issuedCount),
      title: getReportingComparisonLabel(reportingTopTemplateRow),
      detail: buildReportingIssuedShareLabel(reportingTopTemplateRow, reportingTemplateComparisons),
    });
  }

  if (reportingTopOrgUnitRow !== null) {
    reportingInsightItems.push({
      eyebrow: "Org signal",
      metric: formatReportingCount(reportingTopOrgUnitRow.issuedCount),
      title: getReportingComparisonLabel(reportingTopOrgUnitRow),
      detail: buildReportingIssuedShareLabel(reportingTopOrgUnitRow, reportingOrgUnitComparisons),
    });
  }

  if (reportingClaimRateLeader !== null) {
    reportingInsightItems.push({
      eyebrow: "Engagement signal",
      metric: formatReportingRate(reportingClaimRateLeader.claimRate),
      title: getReportingComparisonLabel(reportingClaimRateLeader),
      detail: `${formatReportingCount(
        reportingClaimRateLeader.issuedCount,
      )} issued badges at or above the rate threshold`,
    });
  }

  const reportingInsightCalloutsMarkup =
    reportingInsightItems.length === 0 ? null : (
      <section class="ct-admin__reporting-insight-grid" aria-label="Reporting insight callouts">
        {reportingInsightItems.map((item) => (
          <article class="ct-admin__reporting-insight-card ct-stack">
            <p class="ct-admin__eyebrow">{item.eyebrow}</p>
            <div class="ct-admin__reporting-insight-card-main">
              <strong>{item.metric}</strong>
              <span>{item.title}</span>
            </div>
            <p class="ct-admin__hint">{item.detail}</p>
          </article>
        ))}
      </section>
    );
  const reportingSummaryContextItems = [
    {
      label: "Issued window",
      value:
        reportingIssuedFromValue.length > 0 && reportingIssuedToValue.length > 0
          ? `${formatReportingDateLabel(reportingIssuedFromValue)} to ${formatReportingDateLabel(reportingIssuedToValue)}`
          : reportingIssuedFromValue.length > 0
            ? `From ${formatReportingDateLabel(reportingIssuedFromValue)}`
            : reportingIssuedToValue.length > 0
              ? `Through ${formatReportingDateLabel(reportingIssuedToValue)}`
              : "All issue dates",
    },
    {
      label: "Badge template",
      value:
        reportingBadgeTemplateIdValue.length > 0
          ? (templateById.get(reportingBadgeTemplateIdValue)?.title ??
            reportingBadgeTemplateIdValue)
          : "All templates",
    },
    {
      label: "Org scope",
      value:
        reportingOrgUnitIdValue.length > 0
          ? getReportingOrgUnitLabel(reportingOrgUnitIdValue)
          : "All visible org units",
    },
    {
      label: "Lifecycle state",
      value: formatReportingStateLabel(reportingState),
    },
  ] as const;
  const reportingHierarchyScopeSummary = reportingSummaryContextItems
    .map((item) => `${item.label}: ${item.value}`)
    .join(" · ");
  const reportingExecutiveSummaryMetrics = [
    {
      key: "issued",
      label: "Issued badges",
      value: formatReportingCount(
        reportingOverview?.counts.issued ?? reportingEngagementCounts?.issuedCount ?? 0,
      ),
      detail: "Current issued volume for the selected reporting slice.",
    },
    {
      key: "claim-rate",
      label: "Claim rate",
      value: formatReportingRate(reportingEngagementCounts?.claimRate ?? 0),
      detail: "Distinct claimed or accepted assertions over issued badges.",
    },
    {
      key: "share-rate",
      label: "Share rate",
      value: formatReportingRate(reportingEngagementCounts?.shareRate ?? 0),
      detail: "Distinct shared assertions over issued badges in the same slice.",
    },
    {
      key: "public-badge-views",
      label: "Public badge views",
      value: formatReportingCount(reportingEngagementCounts?.publicBadgeViewCount ?? 0),
      detail: "CredTrail-owned public badge page loads for the current slice.",
    },
  ] as const;
  const reportingExecutiveSummaryMarkup = (
    <article class="ct-admin__panel ct-stack">
      <div class="ct-admin__reporting-summary-band">
        <div class="ct-admin__reporting-summary-layout">
          <div class="ct-admin__reporting-summary-main">
            <div class="ct-stack">
              <div class="ct-cluster">
                <div class="ct-stack">
                  <p class="ct-admin__eyebrow">KPI readout</p>
                  <h2>Executive Summary</h2>
                </div>
                <span class="ct-admin__status-pill">KPI-first</span>
              </div>
              <p class="ct-admin__reporting-summary-copy">
                Current reporting slice shows{" "}
                {formatReportingCount(
                  reportingOverview?.counts.issued ?? reportingEngagementCounts?.issuedCount ?? 0,
                )}{" "}
                issued badges, {formatReportingRate(reportingEngagementCounts?.claimRate ?? 0)}{" "}
                claim rate, {formatReportingRate(reportingEngagementCounts?.shareRate ?? 0)} share
                rate, and{" "}
                {formatReportingCount(reportingEngagementCounts?.publicBadgeViewCount ?? 0)} public
                badge views.
              </p>
            </div>
            <div class="ct-admin__reporting-summary-metrics">
              {reportingExecutiveSummaryMetrics.map((metric) => (
                <article
                  class="ct-admin__metric-card ct-admin__metric-card--reporting-summary ct-stack"
                  data-reporting-summary-metric={metric.key}
                >
                  <p class="ct-admin__eyebrow">{metric.label}</p>
                  <strong class="ct-admin__metric-value">{metric.value}</strong>
                  <p class="ct-admin__hint">{metric.detail}</p>
                </article>
              ))}
            </div>
          </div>
          {reportingSummaryMomentumMarkup}
        </div>
      </div>
      {reportingInsightCalloutsMarkup}
      <section class="ct-admin__reporting-summary-context" aria-label="Current slice">
        <div class="ct-stack">
          <div class="ct-cluster">
            <p class="ct-admin__eyebrow">Current slice</p>
            <span class="ct-admin__status-pill">{reportingGeneratedAtLabel}</span>
          </div>
          <div class="ct-cluster">
            {reportingSummaryContextItems.map((item) => (
              <span class="ct-admin__status-pill">
                <strong>{item.label}:</strong> {item.value}
              </span>
            ))}
          </div>
        </div>
      </section>
    </article>
  );
  const reportingMetricCardsMarkup =
    reportingMetrics.filter((metric) => metric.available).length === 0 ? (
      <p class="ct-admin__empty">No reporting metrics are available yet.</p>
    ) : (
      reportingMetrics
        .filter((metric) => metric.available)
        .map((metric) => {
          const metricValue =
            metric.key === "claimRate" || metric.key === "shareRate"
              ? formatReportingRate(metric.value ?? 0)
              : formatReportingCount(metric.value ?? 0);

          return (
            <article class="ct-admin__metric-card ct-stack">
              <p class="ct-admin__eyebrow">{metric.label}</p>
              <strong class="ct-admin__metric-value">{metricValue}</strong>
              <p class="ct-admin__hint">{metric.description}</p>
            </article>
          );
        })
    );
  const reportingDeferredMetrics = reportingMetrics.filter((metric) => !metric.available);
  const reportingDeferredMetricsMarkup = reportingDeferredMetrics.map((metric) => {
    return (
      <article class="ct-admin__panel ct-admin__panel--nested ct-stack">
        <div class="ct-cluster">
          <strong>{metric.label}</strong>
          <span class="ct-admin__status-pill">Deferred</span>
        </div>
        <p>{metric.description}</p>
        <p class="ct-admin__hint">{metric.availabilityNote ?? "Not available yet."}</p>
      </article>
    );
  });
  const reportingDefinitionRows =
    reportingMetrics.length === 0 ? (
      <AdminEmptyTableRow colSpan={4}>No reporting definitions loaded yet.</AdminEmptyTableRow>
    ) : (
      reportingMetrics.map((metric) => {
        return (
          <tr>
            <td>
              <strong>{metric.label}</strong>
            </td>
            <td>{metric.source}</td>
            <td>{metric.available ? "Available" : "Deferred"}</td>
            <td>{metric.availabilityNote ?? metric.description}</td>
          </tr>
        );
      })
    );
  const reportingEngagementCardsMarkup =
    reportingEngagementCounts === null ? (
      <p class="ct-admin__empty">Engagement counts are not available yet.</p>
    ) : (
      [
        {
          label: "Public badge views",
          description: "Successful public badge page loads captured on CredTrail-owned routes.",
          value: reportingEngagementCounts.publicBadgeViewCount,
        },
        {
          label: "Verification views",
          description: "Successful credential verification responses served by CredTrail.",
          value: reportingEngagementCounts.verificationViewCount,
        },
        {
          label: "Share clicks",
          description: "Outbound share actions routed through CredTrail before handoff.",
          value: reportingEngagementCounts.shareClickCount,
        },
        {
          label: "Claim actions",
          description: "Explicit learner claim actions captured in the dashboard.",
          value: reportingEngagementCounts.learnerClaimCount,
        },
        {
          label: "Wallet accepts",
          description: "Successful OID4VCI credential retrievals recorded as acceptance.",
          value: reportingEngagementCounts.walletAcceptCount,
        },
      ].map((metric) => (
        <article class="ct-admin__metric-card ct-stack">
          <p class="ct-admin__eyebrow">{metric.label}</p>
          <strong class="ct-admin__metric-value">{formatReportingCount(metric.value)}</strong>
          <p class="ct-admin__hint">{metric.description}</p>
        </article>
      ))
    );
  const reportingRateCardsMarkup =
    reportingEngagementCounts === null
      ? []
      : [
          {
            label: "Claim rate",
            description:
              "Distinct claimed or accepted assertions over issued badges in the same window.",
            value: reportingEngagementCounts.claimRate,
          },
          {
            label: "Share rate",
            description: "Distinct shared assertions over issued badges, not raw repeat clicks.",
            value: reportingEngagementCounts.shareRate,
          },
        ].map((metric) => (
          <article class="ct-admin__metric-card ct-stack ct-admin__metric-card--rate">
            <p class="ct-admin__eyebrow">{metric.label}</p>
            <strong class="ct-admin__metric-value">{formatReportingRate(metric.value)}</strong>
            <p class="ct-admin__hint">{metric.description}</p>
          </article>
        ));
  const reportingEngagementVisualsMarkup =
    reportingEngagementCounts === null ? null : (
      <div class="ct-admin__reporting-visual-grid">
        {renderReportingVisualModule({
          kind: "comparison-bars",
          title: "Supported engagement signals",
          description:
            "Server-rendered visual of the same raw event totals shown in the metric cards below.",
          series: [
            {
              label: "Public badge views",
              value: reportingEngagementCounts.publicBadgeViewCount,
              detail: "Product-owned page-load events.",
            },
            {
              label: "Verification views",
              value: reportingEngagementCounts.verificationViewCount,
              detail: "Successful verification responses.",
            },
            {
              label: "Share clicks",
              value: reportingEngagementCounts.shareClickCount,
              detail: "CredTrail-owned outbound share actions.",
            },
            {
              label: "Claim actions",
              value: reportingEngagementCounts.learnerClaimCount,
              detail: "Explicit learner claim events.",
            },
            {
              label: "Wallet accepts",
              value: reportingEngagementCounts.walletAcceptCount,
              detail: "Successful credential retrievals.",
            },
          ] as const,
          note: "Cards below keep the same raw counts visible for review and export parity checks.",
        })}
        {renderReportingVisualModule({
          kind: "comparison-bars",
          title: "Rate context",
          description:
            "Claim and share rates stay derived from distinct engaged assertions over the same issued-badge window.",
          series: [
            {
              label: "Claim rate",
              value: reportingEngagementCounts.claimRate,
              detail: `${formatReportingCount(reportingEngagementCounts.learnerClaimCount)} claim actions over ${formatReportingCount(reportingEngagementCounts.issuedCount)} issued badges.`,
            },
            {
              label: "Share rate",
              value: reportingEngagementCounts.shareRate,
              detail: `${formatReportingCount(reportingEngagementCounts.shareClickCount)} share clicks over ${formatReportingCount(reportingEngagementCounts.issuedCount)} issued badges.`,
            },
          ] as const,
          note: "This visual does not replace the rate cards; it keeps the same definitions in a shared presentation seam.",
        })}
      </div>
    );
  const reportingJourneyVisualMarkup =
    reportingEngagementCounts === null
      ? renderReportingStateShell({
          state: "empty",
          eyebrow: "No journey yet",
          title: "Credential journey signals appear once engagement counts are available.",
          description:
            "The Highlights home keeps this module ready for public views, claim actions, sharing, and verification signals.",
        })
      : renderReportingVisualModule({
          kind: "journey-funnel",
          id: "reporting-highlights-credential-journey",
          title: "Credential journey",
          description:
            "A post-issuance signal path from issued badges through public visibility, learner action, sharing, and verification.",
          series: [
            {
              label: "Issued",
              value: reportingEngagementCounts.issuedCount,
              detail: "Badges issued in the selected reporting slice.",
            },
            {
              label: "Public viewed",
              value: reportingEngagementCounts.publicBadgeViewCount,
              detail: "CredTrail-owned public badge page views.",
            },
            {
              label: "Claimed or accepted",
              value:
                reportingEngagementCounts.learnerClaimCount +
                reportingEngagementCounts.walletAcceptCount,
              detail: `${formatReportingCount(
                reportingEngagementCounts.learnerClaimCount,
              )} claim actions · ${formatReportingCount(
                reportingEngagementCounts.walletAcceptCount,
              )} wallet accepts`,
            },
            {
              label: "Shared",
              value: reportingEngagementCounts.shareClickCount,
              detail: "Outbound share actions routed through CredTrail.",
            },
            {
              label: "Verified",
              value: reportingEngagementCounts.verificationViewCount,
              detail: "Successful verification responses served by CredTrail.",
            },
          ] as const,
          note: "Signals are product-owned event totals, so this reads as a demo-friendly journey rather than a unique-user conversion funnel.",
        });
  const reportingJourneyPanelMarkup = (
    <AdminPanel className="ct-admin__reporting-journey-panel">
      <div class="ct-cluster">
        <div class="ct-stack">
          <p class="ct-admin__eyebrow">Credential journey</p>
          <h2>What happens after issuance</h2>
        </div>
        <AdminStatusPill>Demo story</AdminStatusPill>
      </div>
      <p>
        Issuance is only the first signal. This module turns downstream public views, learner
        action, sharing, and verification into a single story for leadership demos.
      </p>
      {reportingJourneyVisualMarkup}
    </AdminPanel>
  );
  const reportingOverviewVisualMarkup =
    reportingOverview === null
      ? null
      : renderReportingVisualModule({
          kind: "stacked-summary",
          title: "Current badge state mix",
          description:
            "Shows whether badges in this slice are active, suspended, revoked, or waiting for review.",
          series: [
            {
              label: "Active",
              value: reportingOverview.counts.active,
              detail: `${formatReportingCount(reportingOverview.counts.active)} currently active badges`,
            },
            {
              label: "Suspended",
              value: reportingOverview.counts.suspended,
              detail: `${formatReportingCount(reportingOverview.counts.suspended)} currently suspended badges`,
            },
            {
              label: "Revoked",
              value: reportingOverview.counts.revoked,
              detail: `${formatReportingCount(reportingOverview.counts.revoked)} revoked badges`,
            },
            {
              label: "Pending review",
              value: reportingOverview.counts.pendingReview,
              detail: `${formatReportingCount(reportingOverview.counts.pendingReview)} badges pending review`,
            },
          ] as const,
          note: "Use the state cards below for exact counts before exporting or investigating.",
        });
  const renderReportingTrendVisualMarkup = (includeDetailedContext: boolean): HonoElement => {
    if (reportingTrendSeries.length === 0) {
      return <></>;
    }

    return renderReportingVisualModule({
      kind: "trend-series",
      title: "Issued over time",
      description: includeDetailedContext
        ? "Tracks issued badge volume over the selected dates. The table below keeps the exact daily engagement counts."
        : "Tracks issued badge volume over the selected dates.",
      density: includeDetailedContext ? "regular" : "compact",
      showLegend: false,
      showTrendContext: includeDetailedContext,
      series: reportingTrendSeries.map((row) => ({
        label: formatReportingDateLabel(row.bucketStart),
        value: row.issuedCount,
        detail: `${formatReportingCount(row.publicBadgeViewCount)} public views · ${formatReportingCount(row.shareClickCount)} shares`,
      })),
      ...(includeDetailedContext
        ? {
            note: "The table below preserves every visible count so the chart remains a summary, not a second interpretation layer.",
          }
        : {}),
    });
  };
  const reportingTrendRowsMarkup =
    reportingTrendSeries.length === 0 ? (
      <AdminEmptyTableRow colSpan={7}>
        No trend data available for the selected filters.
      </AdminEmptyTableRow>
    ) : (
      reportingTrendSeries.map((row) => (
        <tr>
          <td>
            <strong>{formatReportingDateLabel(row.bucketStart)}</strong>
          </td>
          <td>
            <span class="ct-admin__reporting-table-number">
              {renderReportingCountCell(row.issuedCount)}
            </span>
          </td>
          <td>
            <span class="ct-admin__reporting-table-number">
              {renderReportingCountCell(row.publicBadgeViewCount)}
            </span>
          </td>
          <td>
            <span class="ct-admin__reporting-table-number">
              {renderReportingCountCell(row.verificationViewCount)}
            </span>
          </td>
          <td>
            <span class="ct-admin__reporting-table-number">
              {renderReportingCountCell(row.shareClickCount)}
            </span>
          </td>
          <td>
            <span class="ct-admin__reporting-table-number">
              {renderReportingCountCell(row.learnerClaimCount)}
            </span>
          </td>
          <td>
            <span class="ct-admin__reporting-table-number">
              {renderReportingCountCell(row.walletAcceptCount)}
            </span>
          </td>
        </tr>
      ))
    );
  const getReportingTrendIntroCopy = (includeDetailedTable: boolean): string => {
    if (reportingTrendState === "rich") {
      return includeDetailedTable
        ? "Daily issued badge counts for the selected filters, with exact engagement counts in the table below."
        : "Daily issued badge counts for the selected filters. Open trend detail for exact engagement counts.";
    }

    if (reportingTrendState === "sparse") {
      return "The selected filters return one day of trend data.";
    }

    return "No trend data is available for the selected filters yet.";
  };
  const renderReportingTrendHeroMarkup = (includeDetailedTable: boolean): HonoElement =>
    reportingTrendState === "empty"
      ? renderReportingStateShell({
          state: "empty",
          eyebrow: "No trend line yet",
          title: "The selected filters do not have enough activity to chart yet.",
          description:
            "Expand the date range or remove a filter to see how issuance changes over time.",
        })
      : reportingTrendState === "sparse"
        ? renderReportingStateShell({
            state: "sparse",
            eyebrow: "Limited trend data",
            title: "Only one day matches the selected filters.",
            description: includeDetailedTable
              ? "Use the table below for the exact counts for that day."
              : "Open trend detail to review the exact counts for that day.",
          })
        : (() => {
            const startRow = reportingTrendSeries[0];

            if (startRow === undefined) {
              return (
                <div class="ct-admin__empty">No trend data available for the selected filters.</div>
              );
            }

            const latestRow = reportingTrendSeries[reportingTrendSeries.length - 1] ?? startRow;
            const peakRow = reportingTrendSeries.reduce((highestRow, row) => {
              return row.issuedCount > highestRow.issuedCount ? row : highestRow;
            }, startRow);

            return (
              <div class="ct-admin__reporting-trend-hero">
                <div class="ct-admin__reporting-trend-intro ct-stack">
                  <p class="ct-admin__eyebrow">Issued badges</p>
                  <h3>Issuance over time</h3>
                  <p>
                    Use the chart to compare daily issued badge counts for the selected filters.{" "}
                    {includeDetailedTable
                      ? "The table below lists the exact engagement counts for each day."
                      : "Open trend detail for the exact engagement counts behind each day."}
                  </p>
                  <div class="ct-admin__reporting-trend-callouts">
                    {renderReportingTrendCallout({
                      kind: "peak",
                      label: "Peak day",
                      row: peakRow,
                    })}
                    {renderReportingTrendCallout({
                      kind: "latest",
                      label: "Latest day",
                      row: latestRow,
                    })}
                  </div>
                </div>
                {renderReportingTrendVisualMarkup(true)}
              </div>
            );
          })();
  const renderReportingComparisonRows = (
    rows: readonly TenantReportingComparisonRowRecord[],
    emptyLabel: string,
  ): HonoElement => {
    if (rows.length === 0) {
      return <AdminEmptyTableRow colSpan={9}>{emptyLabel}</AdminEmptyTableRow>;
    }

    return (
      <>
        {rows.map((row) => (
          <tr>
            <td>{renderReportingComparisonGroupLabel(row)}</td>
            <td>
              <span class="ct-admin__reporting-table-number">
                {renderReportingCountCell(row.issuedCount)}
              </span>
            </td>
            <td>
              <span class="ct-admin__reporting-table-number">
                {renderReportingCountCell(row.publicBadgeViewCount)}
              </span>
            </td>
            <td>
              <span class="ct-admin__reporting-table-number">
                {renderReportingCountCell(row.verificationViewCount)}
              </span>
            </td>
            <td>
              <span class="ct-admin__reporting-table-number">
                {renderReportingCountCell(row.shareClickCount)}
              </span>
            </td>
            <td>
              <span class="ct-admin__reporting-table-number">
                {renderReportingCountCell(row.learnerClaimCount)}
              </span>
            </td>
            <td>
              <span class="ct-admin__reporting-table-number">
                {renderReportingCountCell(row.walletAcceptCount)}
              </span>
            </td>
            <td>{formatReportingRate(row.claimRate)}</td>
            <td>{formatReportingRate(row.shareRate)}</td>
          </tr>
        ))}
      </>
    );
  };
  const reportingTemplateComparisonRowsMarkup = renderReportingComparisonRows(
    reportingTemplateComparisons,
    "No badge-template comparisons available for the selected filters.",
  );
  const reportingTemplateComparisonState = classifyReportingPanelState(
    reportingTemplateComparisons.filter((row) => hasReportingActivity(row)).length,
  );
  const reportingTemplateComparisonVisualMarkup =
    reportingTemplateComparisonState === "empty"
      ? renderReportingStateShell({
          state: "empty",
          eyebrow: "No comparison rows yet",
          title: "No badge-template rows are visible for this slice yet.",
          description:
            "Widen the reporting window or remove a filter to compare badge-template performance inside this workspace.",
        })
      : renderReportingVisualModule({
          kind: "comparison-ranked",
          title: "Issued ranking by badge template",
          description:
            "Volume-first comparison ranks badge templates by issued count while keeping public views and claim/share rates visible as adjacent detail.",
          series: buildReportingComparisonSeries(reportingTemplateComparisons),
          ...(reportingTemplateComparisonState === "sparse"
            ? {
                sparseMessage:
                  "Only one badge template row is visible in this slice, so the exact row below carries the full comparison detail.",
              }
            : {}),
          note: "The table below keeps the full row set with exact counts and rate definitions.",
        });
  const reportingOrgUnitComparisonRowsMarkup = renderReportingComparisonRows(
    reportingOrgUnitComparisons,
    "No org-unit comparisons available for the selected filters.",
  );
  const reportingOrgUnitComparisonState = classifyReportingPanelState(
    reportingOrgUnitComparisons.filter((row) => hasReportingActivity(row)).length,
  );
  const reportingOrgUnitComparisonVisualMarkup =
    reportingOrgUnitComparisonState === "empty"
      ? renderReportingStateShell({
          state: "empty",
          eyebrow: "No comparison rows yet",
          title: "No org-unit rows are visible for this slice yet.",
          description:
            "Widen the reporting window or remove a filter to compare org-unit performance inside this workspace.",
        })
      : renderReportingVisualModule({
          kind: "comparison-ranked",
          title: "Issued ranking by org unit",
          description:
            "Volume-first comparison ranks org units by issued count while keeping public views and claim/share rates visible as adjacent detail.",
          series: buildReportingComparisonSeries(reportingOrgUnitComparisons),
          ...(reportingOrgUnitComparisonState === "sparse"
            ? {
                sparseMessage:
                  "Only one org-unit row is visible in this slice, so use the exact row below to read the current context.",
              }
            : {}),
          note: "The table below keeps the full row set with exact counts and rate definitions.",
        });
  const reportingTemplateHighlightRows = selectReportingHighlightRows(reportingTemplateComparisons);
  const reportingOrgUnitHighlightRows = selectReportingHighlightRows(reportingOrgUnitComparisons);
  const renderReportingHighlightComparisonPanel = (input: {
    actionHref: string;
    exportHref: string;
    emptyDescription: string;
    emptyTitle: string;
    eyebrow: string;
    rows: readonly TenantReportingComparisonRowRecord[];
    title: string;
    totalRowCount: number;
    visualDescription: string;
    visualId: string;
  }): HonoElement => {
    const activeRowCount = input.rows.filter((row) => hasReportingActivity(row)).length;
    const state = classifyReportingPanelState(activeRowCount);
    const visualMarkup =
      state === "empty"
        ? renderReportingStateShell({
            state: "empty",
            eyebrow: input.eyebrow,
            title: input.emptyTitle,
            description: input.emptyDescription,
          })
        : renderReportingVisualModule({
            kind: "comparison-ranked",
            id: input.visualId,
            title: input.title,
            description: input.visualDescription,
            series: buildReportingComparisonSeries(input.rows),
            seriesOrder: "input",
            note: `Top ${formatReportingCount(input.rows.length)} of ${formatReportingCount(
              input.totalRowCount,
            )} visible rows shown. Open Explore for the complete table and hierarchy context.`,
          });

    return (
      <AdminPanel
        className="ct-admin__reporting-highlight-panel"
        dataAttributes={{ "data-reporting-state": state }}
      >
        <div class="ct-cluster">
          <div class="ct-stack">
            <p class="ct-admin__eyebrow">{input.eyebrow}</p>
            <h2>{input.title}</h2>
          </div>
          <AdminStatusPill>{state === "rich" ? "Top rows" : "Current slice"}</AdminStatusPill>
        </div>
        {visualMarkup}
        <div class="ct-admin__reporting-highlight-actions">
          <AdminButtonLink href={input.actionHref} variant="secondary">
            Open Explore
          </AdminButtonLink>
          <AdminButtonLink href={input.exportHref} variant="ghost">
            Export CSV
          </AdminButtonLink>
        </div>
      </AdminPanel>
    );
  };
  const reportingHierarchyRowsByLevel = new Map(
    REPORTING_HIERARCHY_LEVELS.map((level) => [
      level,
      aggregateReportingHierarchyRows({
        comparisonRows: reportingOrgUnitComparisons,
        level,
      }),
    ]),
  );
  const reportingHierarchyComparableRowCount = Math.max(
    0,
    ...REPORTING_HIERARCHY_LEVELS.map(
      (level) =>
        reportingHierarchyRowsByLevel.get(level)?.filter((row) => hasReportingActivity(row))
          .length ?? 0,
    ),
  );
  const reportingHierarchyState = classifyReportingPanelState(reportingHierarchyComparableRowCount);
  const reportingVisibleRoots = input.orgUnits
    .filter(
      (orgUnit) =>
        isReportingHierarchyLevel(orgUnit.unitType) &&
        (orgUnit.parentOrgUnitId === null || !orgUnitById.has(orgUnit.parentOrgUnitId)) &&
        (reportingHierarchyRowsByLevel
          .get(orgUnit.unitType)
          ?.some((row) => row.orgUnitId === orgUnit.id) ??
          false),
    )
    .sort((left, right) => left.displayName.localeCompare(right.displayName));
  const renderReportingHierarchyFocusSection = (
    focusOrgUnit: TenantOrgUnitRecord,
    breadcrumb: readonly TenantOrgUnitRecord[],
  ): HonoElement => {
    if (!isReportingHierarchyLevel(focusOrgUnit.unitType)) {
      return <></>;
    }

    const childLevel = getNextReportingHierarchyLevel(focusOrgUnit.unitType);
    const sectionId = buildReportingHierarchyFocusId(focusOrgUnit.id);
    const rootSectionId = buildReportingHierarchyFocusId((breadcrumb[0] ?? focusOrgUnit).id);
    const currentLevelLabel = formatReportingHierarchyLevelLabel(focusOrgUnit.unitType);
    const childLevelLabel =
      childLevel === null
        ? "Deepest reporting level"
        : formatReportingHierarchyLevelLabel(childLevel);
    const rows =
      childLevel === null
        ? []
        : aggregateReportingHierarchyRows({
            comparisonRows: reportingOrgUnitComparisons,
            focusOrgUnitId: focusOrgUnit.id,
            level: childLevel,
          });
    const breadcrumbMarkup = (
      <nav class="ct-admin__reporting-breadcrumb-nav" aria-label="Reporting hierarchy breadcrumb">
        <ol class="ct-admin__reporting-breadcrumb-list">
          {breadcrumb.map((orgUnit, index) => {
            const isCurrent = index === breadcrumb.length - 1;

            return (
              <li class="ct-admin__reporting-breadcrumb-item">
                {isCurrent ? (
                  <span class="ct-admin__reporting-breadcrumb-current" aria-current="page">
                    {orgUnit.displayName}
                  </span>
                ) : (
                  <a
                    class="ct-admin__reporting-breadcrumb-link"
                    href={buildReportingHierarchyDrillHref(orgUnit.id)}
                    data-reporting-focus-link
                    data-reporting-focus-target={buildReportingHierarchyFocusId(orgUnit.id)}
                  >
                    {orgUnit.displayName}
                  </a>
                )}
              </li>
            );
          })}
        </ol>
      </nav>
    );
    const focusSummaryCopy =
      childLevel === null
        ? "Keeps this drilldown inside reporting while marking the deepest visible reporting leaf for the current workspace slice."
        : `Keeps this drilldown inside reporting while the exact ${childLevelLabel.toLowerCase()} table and export link stay adjacent to the shared visual.`;
    const focusSummaryMarkup = (
      <section
        class="ct-admin__reporting-focus-summary ct-stack"
        aria-label="Hierarchy focus summary"
      >
        <div class="ct-stack">
          <p class="ct-admin__eyebrow">Current focus</p>
          <p class="ct-admin__reporting-focus-summary-title">{focusOrgUnit.displayName}</p>
          <p class="ct-admin__hint">{focusSummaryCopy}</p>
        </div>
        <dl class="ct-admin__reporting-focus-summary-grid">
          <div class="ct-admin__reporting-focus-summary-item">
            <dt>Current hierarchy level</dt>
            <dd>{currentLevelLabel}</dd>
          </div>
          <div class="ct-admin__reporting-focus-summary-item">
            <dt>Next child level</dt>
            <dd>{childLevelLabel}</dd>
          </div>
          <div class="ct-admin__reporting-focus-summary-item">
            <dt>Reporting workspace</dt>
            <dd>{reportingHierarchyScopeSummary}</dd>
          </div>
        </dl>
      </section>
    );
    const visualMarkup =
      childLevel === null || rows.length === 0
        ? null
        : renderReportingVisualModule({
            kind: "comparison-ranked",
            headingLevel: "h4",
            id: `${sectionId}-visual`,
            title: `${focusOrgUnit.displayName} ${childLevelLabel} ranking`,
            description:
              "Volume-first hierarchy summary ranks the visible child rows by issued count while keeping public views plus claim/share detail adjacent to each ranked row.",
            series: rows.map((row) => ({
              label: getReportingOrgUnitLabel(row.orgUnitId),
              value: row.issuedCount,
              detail: buildReportingLegendDetail({
                publicBadgeViewCount: row.publicBadgeViewCount,
                claimRate: row.claimRate,
                shareRate: row.shareRate,
              }),
            })),
            note: `The exact ${childLevelLabel.toLowerCase()} table below keeps every visible row, drill target, and export context intact.`,
          });
    const childMarkup =
      childLevel === null ? (
        <p class="ct-admin__hint">Program is the deepest reporting level in this workspace.</p>
      ) : (
        <div class="ct-admin__reporting-panel-media">
          {visualMarkup}
          <AdminTable
            headers={[
              formatReportingHierarchyLevelLabel(childLevel),
              "Issued",
              "Public badge views",
              "Verification views",
              "Share clicks",
              "Claim actions",
              "Wallet accepts",
              "Claim rate",
              "Share rate",
            ]}
            tbodyDataAttributes={{ "data-reporting-bar-group": sectionId }}
          >
            {renderReportingHierarchyRows(
              rows,
              `No ${formatReportingHierarchyLevelLabel(childLevel).toLowerCase()} rows available for this focus.`,
            )}
          </AdminTable>
        </div>
      );
    const descendantMarkup = rows.map((row) => {
      const childOrgUnit = orgUnitById.get(row.orgUnitId);

      if (childOrgUnit === undefined || !isReportingHierarchyLevel(childOrgUnit.unitType)) {
        return null;
      }

      return renderReportingHierarchyFocusSection(childOrgUnit, [...breadcrumb, childOrgUnit]);
    });

    return (
      <section
        id={sectionId}
        class="ct-admin__reporting-focus-section ct-stack"
        data-reporting-focus-root={rootSectionId}
        data-reporting-focus-section
        tabindex={-1}
      >
        <div class="ct-cluster">
          <h3>{focusOrgUnit.displayName}</h3>
          <div class="ct-cluster">
            <span class="ct-admin__status-pill">
              {childLevel === null
                ? "Program leaf"
                : `Shows ${formatReportingHierarchyLevelLabel(childLevel).toLowerCase()} rows`}
            </span>
            {childLevel === null ? null : (
              <AdminButtonLink
                variant="secondary"
                href={buildReportingHierarchyExportHref({
                  focusOrgUnitId: focusOrgUnit.id,
                  level: childLevel,
                })}
              >
                Export CSV
              </AdminButtonLink>
            )}
          </div>
        </div>
        <p class="ct-admin__eyebrow">Breadcrumb</p>
        {breadcrumbMarkup}
        {focusSummaryMarkup}
        {childMarkup}
        {descendantMarkup}
      </section>
    );
  };
  const reportingHierarchyStateShellMarkup =
    reportingHierarchyState === "rich"
      ? null
      : reportingHierarchyState === "sparse"
        ? renderReportingStateShell({
            state: "sparse",
            eyebrow: "Thin-data slice",
            title: "This slice currently resolves to one visible reporting path.",
            description:
              "Use the current focus summary and exact hierarchy table below to review the visible path without implying a fuller tree.",
          })
        : renderReportingStateShell({
            state: "empty",
            eyebrow: "No hierarchy rows yet",
            title:
              "Hierarchy drilldowns appear here once visible org-unit rows exist for this slice.",
            description:
              "The reporting route stays the same; this panel fills in as soon as the current slice exposes hierarchy rows.",
          });
  const reportingHierarchyPanelMarkup = (
    <article class="ct-admin__panel ct-stack" data-reporting-state={reportingHierarchyState}>
      <div class="ct-cluster">
        <h2>Hierarchy drilldown</h2>
        <span class="ct-admin__status-pill">Workspace-local</span>
      </div>
      <p>
        Use these tables to move between institution, college, department, and program views without
        leaving reporting. The overview filters above stay exact-match; hierarchy drilldowns stay
        explicit here.
      </p>
      {reportingHierarchyStateShellMarkup}
      {reportingHierarchyState === "empty" ? null : (
        <>
          <p class="ct-admin__hint">Visible roots stay inside the reporting workspace.</p>
          <div class="ct-admin__reporting-root-links">
            {reportingVisibleRoots.map((rootOrgUnit) => (
              <a
                class="ct-admin__reporting-root-link"
                href={buildReportingHierarchyDrillHref(rootOrgUnit.id)}
                data-reporting-focus-link
                data-reporting-root-link
                data-reporting-focus-target={buildReportingHierarchyFocusId(rootOrgUnit.id)}
              >
                {rootOrgUnit.displayName}
              </a>
            ))}
          </div>
          {reportingVisibleRoots.map((rootOrgUnit) =>
            renderReportingHierarchyFocusSection(rootOrgUnit, [rootOrgUnit]),
          )}
        </>
      )}
    </article>
  );
  const reportingPerformerLevel =
    REPORTING_HIERARCHY_LEVELS.filter(
      (level) => (reportingHierarchyRowsByLevel.get(level)?.length ?? 0) > 1,
    ).sort((left, right) => {
      const countDifference =
        (reportingHierarchyRowsByLevel.get(right)?.length ?? 0) -
        (reportingHierarchyRowsByLevel.get(left)?.length ?? 0);

      if (countDifference !== 0) {
        return countDifference;
      }

      return REPORTING_HIERARCHY_DEPTH[right] - REPORTING_HIERARCHY_DEPTH[left];
    })[0] ?? null;
  const reportingPerformerRows =
    reportingPerformerLevel === null
      ? []
      : (reportingHierarchyRowsByLevel.get(reportingPerformerLevel) ?? []);
  const reportingPerformerCompareLevelLabel =
    reportingPerformerLevel === null
      ? null
      : formatReportingHierarchyLevelLabel(reportingPerformerLevel).toLowerCase();
  const reportingPerformerState = classifyReportingPanelState(reportingHierarchyComparableRowCount);
  const reportingRateEligibleRows = reportingPerformerRows.filter(
    (row) => row.issuedCount >= REPORTING_RATE_MIN_ISSUED,
  );
  const buildPerformerSummaryOverride = (input: {
    metricLabel: "claim rate" | "issued volume" | "share rate";
    rankingIntent: "highest" | "lowest";
    summaryKind: "rate" | "volume";
  }): string => {
    const compareLevelLabel = reportingPerformerCompareLevelLabel ?? "visible";
    const rankingCopy =
      input.rankingIntent === "highest"
        ? "Highest values appear first."
        : "Lowest values appear first.";

    if (input.summaryKind === "rate") {
      return `Comparing ${compareLevelLabel} rows by ${input.metricLabel}. Issued totals stay visible beside each ranked rate row. ${rankingCopy}`;
    }

    return `Comparing ${compareLevelLabel} rows by ${input.metricLabel}. Claim and share rates stay visible beside each ranked row. ${rankingCopy}`;
  };
  const renderPerformerTableRows = (
    rows: readonly ReportingHierarchyRow[],
    emptyLabel: string,
  ): HonoElement => {
    if (rows.length === 0) {
      return <AdminEmptyTableRow colSpan={4}>{emptyLabel}</AdminEmptyTableRow>;
    }

    return (
      <>
        {rows.map((row) => (
          <tr>
            <td>{renderOrgUnitSummary(row.orgUnitId)}</td>
            <td>
              <span class="ct-admin__reporting-table-number">
                {renderReportingCountCell(row.issuedCount)}
              </span>
            </td>
            <td>{formatReportingRate(row.claimRate)}</td>
            <td>{formatReportingRate(row.shareRate)}</td>
          </tr>
        ))}
      </>
    );
  };
  const renderPerformerPanel = (input: {
    description: string;
    title: string;
    rows: readonly ReportingHierarchyRow[];
    emptyLabel: string;
    barGroup: string;
    rankingIntent: "highest" | "lowest";
    metric: "claimRate" | "issuedCount" | "shareRate";
  }): HonoElement => {
    const summaryOverride =
      input.metric === "issuedCount"
        ? buildPerformerSummaryOverride({
            metricLabel: "issued volume",
            rankingIntent: input.rankingIntent,
            summaryKind: "volume",
          })
        : buildPerformerSummaryOverride({
            metricLabel: input.metric === "claimRate" ? "claim rate" : "share rate",
            rankingIntent: input.rankingIntent,
            summaryKind: "rate",
          });
    const visualMarkup =
      input.rows.length === 0
        ? null
        : renderReportingVisualModule({
            kind: "comparison-ranked",
            headingLevel: "h4",
            id: `performer-${input.barGroup}`,
            title: input.title,
            description: input.description,
            seriesOrder: "input",
            summaryOverride,
            series: input.rows.map((row) => ({
              label: getReportingOrgUnitLabel(row.orgUnitId),
              value:
                input.metric === "issuedCount"
                  ? row.issuedCount
                  : input.metric === "claimRate"
                    ? row.claimRate
                    : row.shareRate,
              detail:
                input.metric === "issuedCount"
                  ? `${formatReportingRate(row.claimRate)} claim · ${formatReportingRate(row.shareRate)} share`
                  : `${formatReportingCount(row.issuedCount)} issued · ${
                      input.metric === "claimRate"
                        ? `${formatReportingRate(row.shareRate)} share`
                        : `${formatReportingRate(row.claimRate)} claim`
                    }`,
            })),
            note: "The exact table below preserves the same rows, issued totals, and rate semantics for detailed comparison.",
          });

    return (
      <article class="ct-admin__panel ct-admin__panel--nested ct-stack">
        <h3>{input.title}</h3>
        {visualMarkup}
        <AdminTable
          headers={["Org unit", "Issued", "Claim rate", "Share rate"]}
          compact={true}
          tbodyDataAttributes={{ "data-reporting-bar-group": input.barGroup }}
        >
          {renderPerformerTableRows(input.rows, input.emptyLabel)}
        </AdminTable>
      </article>
    );
  };
  const reportingHighestVolumeRows = [...reportingPerformerRows]
    .sort((left, right) => {
      if (right.issuedCount !== left.issuedCount) {
        return right.issuedCount - left.issuedCount;
      }

      return left.orgUnitId.localeCompare(right.orgUnitId);
    })
    .slice(0, REPORTING_PERFORMER_ROW_LIMIT);
  const reportingLowestVolumeRows = [...reportingPerformerRows]
    .sort((left, right) => {
      if (left.issuedCount !== right.issuedCount) {
        return left.issuedCount - right.issuedCount;
      }

      return left.orgUnitId.localeCompare(right.orgUnitId);
    })
    .slice(0, REPORTING_PERFORMER_ROW_LIMIT);
  const reportingHighestClaimRateRows = [...reportingRateEligibleRows]
    .sort((left, right) => {
      if (right.claimRate !== left.claimRate) {
        return right.claimRate - left.claimRate;
      }

      if (right.issuedCount !== left.issuedCount) {
        return right.issuedCount - left.issuedCount;
      }

      return left.orgUnitId.localeCompare(right.orgUnitId);
    })
    .slice(0, REPORTING_PERFORMER_ROW_LIMIT);
  const reportingLowestClaimRateRows = [...reportingRateEligibleRows]
    .sort((left, right) => {
      if (left.claimRate !== right.claimRate) {
        return left.claimRate - right.claimRate;
      }

      if (left.issuedCount !== right.issuedCount) {
        return left.issuedCount - right.issuedCount;
      }

      return left.orgUnitId.localeCompare(right.orgUnitId);
    })
    .slice(0, REPORTING_PERFORMER_ROW_LIMIT);
  const reportingHighestShareRateRows = [...reportingRateEligibleRows]
    .sort((left, right) => {
      if (right.shareRate !== left.shareRate) {
        return right.shareRate - left.shareRate;
      }

      if (right.issuedCount !== left.issuedCount) {
        return right.issuedCount - left.issuedCount;
      }

      return left.orgUnitId.localeCompare(right.orgUnitId);
    })
    .slice(0, REPORTING_PERFORMER_ROW_LIMIT);
  const reportingLowestShareRateRows = [...reportingRateEligibleRows]
    .sort((left, right) => {
      if (left.shareRate !== right.shareRate) {
        return left.shareRate - right.shareRate;
      }

      if (left.issuedCount !== right.issuedCount) {
        return left.issuedCount - right.issuedCount;
      }

      return left.orgUnitId.localeCompare(right.orgUnitId);
    })
    .slice(0, REPORTING_PERFORMER_ROW_LIMIT);
  const renderPerformerGroup = (input: {
    title: string;
    description: string;
    panels: readonly HonoElement[];
  }): HonoElement => {
    return (
      <section class="ct-admin__reporting-performer-group ct-stack">
        <div class="ct-stack">
          <p class="ct-admin__eyebrow">{input.title}</p>
          <p class="ct-admin__hint">{input.description}</p>
        </div>
        <div class="ct-admin__reporting-performer-grid">{input.panels}</div>
      </section>
    );
  };
  const reportingPerformerPanelsMarkup =
    reportingPerformerState !== "rich" || reportingPerformerLevel === null ? (
      <article class="ct-admin__panel ct-stack" data-reporting-state={reportingPerformerState}>
        <h2>Performer panels</h2>
        {renderReportingStateShell({
          state: reportingPerformerState === "empty" ? "empty" : "sparse",
          eyebrow: reportingPerformerState === "empty" ? "No rankings yet" : "Thin-data slice",
          title:
            reportingPerformerState === "empty"
              ? "Performer rankings appear once this slice includes comparable hierarchy rows."
              : "Rankings stay paused until this slice has more than one comparable hierarchy row.",
          description:
            reportingPerformerState === "empty"
              ? "This section reuses the same visible hierarchy rows shown above, so it stays honest when the current slice has nothing comparable to rank."
              : "The current slice still shows real hierarchy data above, but performer rankings wait until more than one visible row can be compared honestly.",
        })}
      </article>
    ) : (
      <article class="ct-admin__panel ct-stack" data-reporting-state="rich">
        <div class="ct-cluster">
          <h2>Performer panels</h2>
          <span class="ct-admin__status-pill">
            {`${formatReportingHierarchyLevelLabel(reportingPerformerLevel)} rows`}
          </span>
        </div>
        <p>These rankings keep issued volume separate from claim and share rates.</p>
        <p class="ct-admin__hint">
          Compare level:{" "}
          {`${reportingPerformerCompareLevelLabel} rows in the current visible hierarchy.`}
        </p>
        <div class="ct-admin__reporting-performer-groups">
          {renderPerformerGroup({
            title: "Volume rankings",
            description:
              "Issued volume stays primary while claim and share rates remain visible beside each ranked row.",
            panels: [
              renderPerformerPanel({
                title: "Highest issuance volume",
                description:
                  "Highlights the org units issuing the most badges while keeping exact totals and rates visible.",
                rows: reportingHighestVolumeRows,
                emptyLabel: "No org units available for volume rankings.",
                barGroup: "performer-high-volume",
                rankingIntent: "highest",
                metric: "issuedCount",
              }),
              renderPerformerPanel({
                title: "Lowest issuance volume",
                description:
                  "Highlights lower-volume org units without separating the ranking from its exact table rows.",
                rows: reportingLowestVolumeRows,
                emptyLabel: "No org units available for volume rankings.",
                barGroup: "performer-low-volume",
                rankingIntent: "lowest",
                metric: "issuedCount",
              }),
            ],
          })}
          {renderPerformerGroup({
            title: "Rate rankings",
            description: `Rate rankings require at least ${formatReportingCount(
              REPORTING_RATE_MIN_ISSUED,
            )} issued badges so issued totals stay visible beside every rate callout.`,
            panels: [
              renderPerformerPanel({
                title: "Highest claim rate",
                description:
                  "Ranks claim-rate leaders that meet the minimum issued-badge threshold.",
                rows: reportingHighestClaimRateRows,
                emptyLabel: `No ${formatReportingHierarchyLevelLabel(reportingPerformerLevel).toLowerCase()} rows meet the minimum rate sample.`,
                barGroup: "performer-high-claim-rate",
                rankingIntent: "highest",
                metric: "claimRate",
              }),
              renderPerformerPanel({
                title: "Lowest claim rate",
                description: "Ranks lower claim-rate rows using the same minimum-sample rule.",
                rows: reportingLowestClaimRateRows,
                emptyLabel: `No ${formatReportingHierarchyLevelLabel(reportingPerformerLevel).toLowerCase()} rows meet the minimum rate sample.`,
                barGroup: "performer-low-claim-rate",
                rankingIntent: "lowest",
                metric: "claimRate",
              }),
              renderPerformerPanel({
                title: "Highest share rate",
                description:
                  "Ranks share-rate leaders while keeping issued totals visible in the adjacent table.",
                rows: reportingHighestShareRateRows,
                emptyLabel: `No ${formatReportingHierarchyLevelLabel(reportingPerformerLevel).toLowerCase()} rows meet the minimum rate sample.`,
                barGroup: "performer-high-share-rate",
                rankingIntent: "highest",
                metric: "shareRate",
              }),
              renderPerformerPanel({
                title: "Lowest share rate",
                description:
                  "Ranks lower share-rate rows with the same volume threshold used by the table below.",
                rows: reportingLowestShareRateRows,
                emptyLabel: `No ${formatReportingHierarchyLevelLabel(reportingPerformerLevel).toLowerCase()} rows meet the minimum rate sample.`,
                barGroup: "performer-low-share-rate",
                rankingIntent: "lowest",
                metric: "shareRate",
              }),
            ],
          })}
        </div>
      </article>
    );
  const authPolicyApiPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/auth-policy`;
  const authProvidersApiPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/auth-providers`;
  const enterpriseAuthPolicy = input.enterpriseAuthPolicy ?? {
    tenantId: input.tenant.id,
    loginMode: "local" as const,
    breakGlassEnabled: false,
    localMfaRequired: false,
    defaultProviderId: null,
    enforceForRoles: "all_users" as const,
    createdAt: "",
    updatedAt: "",
  };
  const enterpriseAuthProviders = input.enterpriseAuthProviders ?? [];
  const supportedEnterpriseAuthProviders = enterpriseAuthProviders.filter(
    (provider) => provider.protocol === "oidc",
  );
  const legacySamlProviders = enterpriseAuthProviders.filter(
    (provider) => provider.protocol === "saml",
  );
  const legacyDefaultProvider = legacySamlProviders.find(
    (provider) => provider.id === enterpriseAuthPolicy.defaultProviderId,
  );
  const breakGlassAccounts = input.breakGlassAccounts ?? [];
  const enterpriseAuthProviderOptions = supportedEnterpriseAuthProviders.map((provider) => {
    return (
      <option value={provider.id} selected={enterpriseAuthPolicy.defaultProviderId === provider.id}>
        {provider.label}
      </option>
    );
  });
  const enterpriseAuthProviderRows =
    supportedEnterpriseAuthProviders.length === 0 ? (
      <AdminEmptyTableRow colSpan={6}>
        No OIDC enterprise providers configured yet.
      </AdminEmptyTableRow>
    ) : (
      supportedEnterpriseAuthProviders.map((provider) => {
        return (
          <tr>
            <td>
              <strong>{provider.label}</strong>
              <AdminMeta>{provider.id}</AdminMeta>
            </td>
            <td>{provider.protocol}</td>
            <td>{provider.isDefault ? "Default" : "Secondary"}</td>
            <td>{provider.enabled ? "Enabled" : "Disabled"}</td>
            <td>{formatIsoTimestamp(provider.updatedAt)}</td>
            <td>
              <AdminButton
                type="button"
                size="tiny"
                dataAttributes={{
                  "data-enterprise-auth-edit-provider": "true",
                  "data-provider-id": provider.id,
                  "data-provider-protocol": provider.protocol,
                  "data-provider-label": provider.label,
                  "data-provider-enabled": provider.enabled ? "true" : "false",
                  "data-provider-is-default": provider.isDefault ? "true" : "false",
                  "data-provider-config-json": provider.configJson,
                }}
              >
                Edit
              </AdminButton>
              <AdminButton
                type="button"
                size="tiny"
                variant="danger"
                dataAttributes={{
                  "data-enterprise-auth-delete-provider-id": provider.id,
                  "data-provider-label": provider.label,
                }}
              >
                Delete
              </AdminButton>
            </td>
          </tr>
        );
      })
    );
  const legacySamlRows =
    legacySamlProviders.length === 0 ? (
      <AdminEmptyTableRow colSpan={5}>
        No legacy SAML compatibility entries detected.
      </AdminEmptyTableRow>
    ) : (
      legacySamlProviders.map((provider) => {
        return (
          <tr>
            <td>
              <strong>{provider.label}</strong>
              <AdminMeta>{provider.id}</AdminMeta>
            </td>
            <td>{provider.isDefault ? "Default" : "Secondary"}</td>
            <td>{provider.enabled ? "Enabled" : "Disabled"}</td>
            <td>{formatIsoTimestamp(provider.updatedAt)}</td>
            <td>
              <AdminButton
                type="button"
                size="tiny"
                variant="danger"
                dataAttributes={{
                  "data-enterprise-auth-delete-provider-id": provider.id,
                  "data-provider-label": provider.label,
                }}
              >
                Delete
              </AdminButton>
            </td>
          </tr>
        );
      })
    );
  const enterpriseAuthPanelMarkup =
    input.tenant.planTier !== "enterprise" ? null : (
      <article id="enterprise-auth-panel" class="ct-admin__panel ct-stack">
        <h2>Enterprise Auth</h2>
        <p>
          Hosted enterprise sign-in supports OIDC providers. Legacy SAML compatibility stays visible
          for cleanup only.
        </p>
        <AdminForm id="enterprise-auth-policy-form">
          <AdminField label="Login mode">
            <select name="loginMode" required>
              <option value="local" selected={enterpriseAuthPolicy.loginMode === "local"}>
                Local only
              </option>
              <option value="hybrid" selected={enterpriseAuthPolicy.loginMode === "hybrid"}>
                Hybrid
              </option>
              <option
                value="sso_required"
                selected={enterpriseAuthPolicy.loginMode === "sso_required"}
              >
                SSO required
              </option>
            </select>
          </AdminField>
          <AdminField label="Default provider">
            <select name="defaultProviderId">
              <option value="">No default provider</option>
              {enterpriseAuthProviderOptions}
            </select>
          </AdminField>
          <p class="ct-admin__hint">
            SSO enforcement applies to the tenant login experience. Role-specific enforcement is not
            configurable in the hosted runtime.
          </p>
          {legacyDefaultProvider === undefined ? null : (
            <p class="ct-admin__hint">
              This tenant still references <strong>{legacyDefaultProvider.label}</strong> as a
              legacy default. Choose an OIDC provider before requiring institution sign-in.
            </p>
          )}
          <AdminCheckboxRow>
            <input
              name="breakGlassEnabled"
              type="checkbox"
              checked={enterpriseAuthPolicy.breakGlassEnabled}
            />
            Break-glass local access enabled
          </AdminCheckboxRow>
          <AdminCheckboxRow>
            <input
              name="localMfaRequired"
              type="checkbox"
              checked={enterpriseAuthPolicy.localMfaRequired}
            />
            Require MFA for local access
          </AdminCheckboxRow>
          <AdminButton type="submit">Save auth policy</AdminButton>
        </AdminForm>
        <AdminStatus id="enterprise-auth-policy-status"></AdminStatus>
        <AdminForm id="enterprise-auth-provider-form">
          <input type="hidden" name="providerId" value="" />
          <input type="hidden" name="protocol" value="oidc" />
          <p class="ct-admin__hint">
            Add or edit hosted OIDC providers here. Use a new OIDC connection instead of modifying
            legacy SAML settings.
          </p>
          <AdminField label="OIDC provider label">
            <input name="label" type="text" required placeholder="Campus OIDC" />
          </AdminField>
          <AdminField label="OIDC discovery or connection JSON">
            <textarea
              id="enterprise-auth-provider-config-json"
              name="configJson"
              rows={8}
              required
              spellcheck={false}
              placeholder='{"issuer":"https://idp.example.edu","clientId":"credtrail"}'
            ></textarea>
          </AdminField>
          <AdminCheckboxRow>
            <input name="enabled" type="checkbox" checked />
            Provider enabled
          </AdminCheckboxRow>
          <AdminCheckboxRow>
            <input name="isDefault" type="checkbox" />
            Set as default provider
          </AdminCheckboxRow>
          <div class="ct-cluster">
            <AdminButton type="submit">Save provider</AdminButton>
            <AdminButton id="enterprise-auth-provider-reset" type="button" variant="secondary">
              Clear form
            </AdminButton>
          </div>
        </AdminForm>
        <AdminStatus id="enterprise-auth-provider-status"></AdminStatus>
        <AdminTable
          headers={["Provider", "Protocol", "Role", "Status", "Updated", "Actions"]}
          tbodyId="enterprise-auth-provider-body"
        >
          {enterpriseAuthProviderRows}
        </AdminTable>
        {legacySamlProviders.length === 0 ? null : (
          <section class="ct-stack" aria-labelledby="legacy-saml-title">
            <h3 id="legacy-saml-title">Legacy SAML compatibility</h3>
            <p>
              These entries remain visible so you can audit or remove older SAML setup after an OIDC
              cutover. They are not editable from the hosted provider workflow.
            </p>
            <AdminTable headers={["Legacy entry", "Role", "Status", "Updated", "Actions"]}>
              {legacySamlRows}
            </AdminTable>
          </section>
        )}
        <section class="ct-stack" aria-labelledby="break-glass-accounts-title">
          <h3 id="break-glass-accounts-title">Break-glass local accounts</h3>
          <p>
            Limit local fallback access to explicit accounts only. CredTrail emails setup links and
            records recent fallback usage.
          </p>
          <AdminForm id="break-glass-account-form">
            <AdminField label="Institution email">
              <input name="email" type="email" required placeholder="admin@institution.edu" />
            </AdminField>
            <AdminCheckboxRow>
              <input name="sendEnrollmentEmail" type="checkbox" checked />
              Email setup or password-reset link now
            </AdminCheckboxRow>
            <AdminButton type="submit">Add break-glass account</AdminButton>
          </AdminForm>
          <AdminStatus id="break-glass-account-status"></AdminStatus>
          <AdminTable
            headers={["Email", "Local status", "Last used", "Enrollment email", "Actions"]}
            tbodyId="break-glass-account-body"
          >
            {breakGlassAccounts.length === 0 ? (
              <AdminEmptyTableRow colSpan={5}>
                No break-glass accounts configured yet.
              </AdminEmptyTableRow>
            ) : (
              breakGlassAccounts.map((account) => {
                const localStatus = account.twoFactorEnabled
                  ? "MFA ready"
                  : account.localCredentialEnabled
                    ? "Password ready"
                    : "Setup pending";

                return (
                  <tr>
                    <td>
                      <strong>{account.email}</strong>
                      <AdminMeta>{account.userId}</AdminMeta>
                    </td>
                    <td>{localStatus}</td>
                    <td>
                      {account.lastUsedAt === null
                        ? "Never"
                        : formatIsoTimestamp(account.lastUsedAt)}
                    </td>
                    <td>
                      {account.lastEnrollmentEmailSentAt === null
                        ? "Not sent"
                        : formatIsoTimestamp(account.lastEnrollmentEmailSentAt)}
                    </td>
                    <td>
                      <AdminButton
                        type="button"
                        size="tiny"
                        variant="danger"
                        dataAttributes={{
                          "data-break-glass-delete-user-id": account.userId,
                          "data-break-glass-email": account.email,
                        }}
                      >
                        Revoke
                      </AdminButton>
                    </td>
                  </tr>
                );
              })
            )}
          </AdminTable>
        </section>
        {enterpriseAuthProviders.length > 0 ? (
          <details class="ct-admin__panel ct-admin__panel--nested">
            <summary>Selected provider config preview</summary>
            <pre class="ct-admin__code-output">
              {formatJsonTextareaValue(enterpriseAuthProviders[0]?.configJson ?? "{}")}
            </pre>
          </details>
        ) : null}
      </article>
    );
  const adminPageContextJson = serializeJsonScriptContent({
    tenantAdminPath,
    manualIssueApiPath,
    createApiKeyPath,
    createOrgUnitPath,
    badgeTemplateApiPathPrefix,
    badgeRuleApiPath,
    badgeRuleValueListApiPath,
    badgeRulePreviewSimulationApiPath,
    badgeRuleReviewQueueApiPath,
    assertionsApiPathPrefix,
    issuedBadgeRowsPath,
    tenantMembersApiPath: `/v1/tenants/${encodeURIComponent(input.tenant.id)}/members`,
    tenantUsersApiPathPrefix,
    reportingComparisonsApiPath: `/v1/tenants/${encodeURIComponent(input.tenant.id)}/reporting/comparisons`,
    reportingEngagementApiPath: `/v1/tenants/${encodeURIComponent(input.tenant.id)}/reporting/engagement`,
    reportingPagePath: reportingPath,
    reportingOverviewApiPath: `/v1/tenants/${encodeURIComponent(input.tenant.id)}/reporting/overview`,
    reportingTrendsApiPath: `/v1/tenants/${encodeURIComponent(input.tenant.id)}/reporting/trends`,
    authPolicyApiPath: input.tenant.planTier === "enterprise" ? authPolicyApiPath : "",
    authProvidersApiPath: input.tenant.planTier === "enterprise" ? authProvidersApiPath : "",
    breakGlassAccountsApiPath:
      input.tenant.planTier === "enterprise"
        ? `/v1/tenants/${encodeURIComponent(input.tenant.id)}/break-glass-accounts`
        : "",
  });
  const sidebarSections: readonly AdminSidebarSection[] = [
    {
      links: [{ href: tenantAdminPath, label: "Home", isCurrent: view === "home" }],
    },
    {
      label: "Operations",
      links: [
        { href: operationsPath, label: "Overview", isCurrent: view === "operations" },
        {
          href: operationsLearnerRecordsPath,
          label: "Learner Records",
          isCurrent: view === "operationsLearnerRecords",
          isSub: true,
        },
        {
          href: operationsLearnerRecordImportsPath,
          label: "Learner Record Imports",
          isCurrent: view === "operationsLearnerRecordImports",
          isSub: true,
        },
        {
          href: operationsReviewQueuePath,
          label: "Review Queue",
          isCurrent: view === "operationsReviewQueue",
          isSub: true,
        },
        {
          href: operationsIssuedBadgesPath,
          label: "Issued Badges",
          isCurrent: view === "operationsIssuedBadges",
          isSub: true,
        },
        {
          href: operationsBadgeStatusPath,
          label: "Badge Status",
          isCurrent: view === "operationsBadgeStatus",
          isSub: true,
        },
      ],
    },
    {
      label: "Reporting",
      links: [
        { href: reportingPath, label: "Highlights", isCurrent: view === "reporting" },
        {
          href: reportingExplorePath,
          label: "Explore",
          isCurrent: view === "reportingExplore",
          isSub: true,
        },
        {
          href: reportingTrendsPath,
          label: "Trends",
          isCurrent: view === "reportingTrends",
          isSub: true,
        },
        {
          href: reportingReportsPath,
          label: "Reports",
          isCurrent: view === "reportingReports",
          isSub: true,
        },
      ],
    },
    {
      label: "Configuration",
      links: [
        { href: rulesWorkspacePath, label: "Rules", isCurrent: view === "rules" },
        { href: ruleBuilderPath, label: "Rule Builder", isSub: true },
      ],
    },
    {
      label: "Access",
      links: [
        { href: accessPath, label: "Overview", isCurrent: view === "access" },
        {
          href: accessMembersPath,
          label: "Members",
          isCurrent: view === "accessMembers",
          isSub: true,
        },
        {
          href: accessGovernancePath,
          label: "Governance",
          isCurrent: view === "accessGovernance",
          isSub: true,
        },
        {
          href: accessApiKeysPath,
          label: "API Keys",
          isCurrent: view === "accessApiKeys",
          isSub: true,
        },
        {
          href: accessOrgUnitsPath,
          label: "Org Units",
          isCurrent: view === "accessOrgUnits",
          isSub: true,
        },
      ],
    },
  ];
  const sidebarFooterLinks: readonly AdminSidebarFooterLink[] = [
    { href: adminAuditLogPath, label: "Audit logs", isExternal: true },
    {
      href: showcasePath,
      label: "Public showcase",
      isExternal: true,
      target: "_blank",
      rel: "noopener noreferrer",
    },
    ...(switchOrganizationPath.length > 0
      ? [{ href: switchOrganizationPath, label: "Switch organization" }]
      : []),
  ];

  const renderPageHeader = (
    title: string,
    description: string,
    noteMarkup: HonoElement | null = null,
  ): HonoElement => {
    return <AdminPageHeader title={title} description={description} note={noteMarkup} />;
  };

  const workspaceCardsMarkup = (
    <section class="ct-admin__workspace-grid ct-grid" aria-label="Institution admin workspaces">
      <AdminWorkspaceCard>
        <p class="ct-admin__eyebrow">Daily work</p>
        <h2>Operations</h2>
        <p>
          Issue badges, route manual review, inspect issued badges, and update badge status across
          focused pages.
        </p>
        <div class="ct-admin__workspace-stats ct-cluster">
          <AdminStatusPill>{badgeTemplateCount} templates</AdminStatusPill>
          <AdminStatusPill>{ruleCount} rules</AdminStatusPill>
        </div>
      </AdminWorkspaceCard>
      <AdminWorkspaceCard>
        <p class="ct-admin__eyebrow">Analytics</p>
        <h2>Reporting</h2>
        <p>
          Track issuance volume and badge status with filters, definitions, and clear source notes.
        </p>
        <div class="ct-admin__workspace-stats ct-cluster">
          <AdminStatusPill>Issued {reportingOverview?.counts.issued ?? 0}</AdminStatusPill>
          <AdminStatusPill>
            Pending review {reportingOverview?.counts.pendingReview ?? 0}
          </AdminStatusPill>
        </div>
      </AdminWorkspaceCard>
      <AdminWorkspaceCard>
        <p class="ct-admin__eyebrow">Authoring</p>
        <h2>Rules</h2>
        <p>
          Maintain templates, reusable lists, governance context, and the dedicated rule builder.
        </p>
        {input.badgeRules.length === 0 ? (
          <p class="ct-admin__hint">No badge rules found. Create your first rule.</p>
        ) : null}
        <div class="ct-admin__workspace-stats ct-cluster">
          <AdminStatusPill>{ruleCount} active rule records</AdminStatusPill>
          <AdminStatusPill>{badgeTemplateCount} templates</AdminStatusPill>
        </div>
      </AdminWorkspaceCard>
      <AdminWorkspaceCard>
        <p class="ct-admin__eyebrow">Setup</p>
        <h2>Access</h2>
        <p>
          Manage permissions and enterprise auth here, with separate pages for API keys and org
          structure.
        </p>
        <div class="ct-admin__workspace-stats ct-cluster">
          <AdminStatusPill>{tenantMemberCount} members</AdminStatusPill>
          <AdminStatusPill>{activeApiKeyCount} active keys</AdminStatusPill>
          <AdminStatusPill>{orgUnitCount} org units</AdminStatusPill>
        </div>
      </AdminWorkspaceCard>
    </section>
  );

  const manualIssuePanelMarkup = (
    <AdminPanel id="manual-issue-panel">
      <h2>Manual Issue Badge</h2>
      <p>Issue a badge for a learner using this form.</p>
      <AdminForm id="manual-issue-form">
        <AdminField label="Badge template">
          <select name="badgeTemplateId" required>
            {templateSelectOptions}
          </select>
        </AdminField>
        <AdminField label="Recipient email">
          <input name="recipientIdentity" type="email" required placeholder="csev@umich.edu" />
        </AdminField>
        <AdminButton type="submit">Issue badge</AdminButton>
      </AdminForm>
      <AdminStatus id="manual-issue-status"></AdminStatus>
    </AdminPanel>
  );

  const templateImagePanelMarkup = (
    <AdminPanel id="template-image-panel">
      <h2>Upload Badge Template Image</h2>
      <p>Upload template artwork (PNG, JPEG, or WebP, max 2 MB).</p>
      <AdminForm id="badge-template-image-upload-form">
        <AdminField label="Badge template">
          <select name="badgeTemplateId" required>
            {templateSelectOptions}
          </select>
        </AdminField>
        <AdminField label="Image file">
          <input name="file" type="file" required accept="image/png,image/jpeg,image/webp" />
        </AdminField>
        <AdminButton type="submit">Upload image</AdminButton>
      </AdminForm>
      <AdminStatus id="badge-template-image-upload-status"></AdminStatus>
    </AdminPanel>
  );

  const addDisclosureControlMarkup = (
    <span class="ct-admin__add-disclosure-control">
      <span class="ct-admin__add-disclosure-control-open">Open form</span>
      <span class="ct-admin__add-disclosure-control-close">Hide form</span>
    </span>
  );

  const apiKeyPanelMarkup = (
    <details id="api-key-panel" class="ct-admin__panel ct-admin__add-disclosure">
      <summary class="ct-admin__add-disclosure-summary">
        <span>
          <strong>Create API key</strong>
          <small>Create a scoped key and reveal the secret once.</small>
        </span>
        {addDisclosureControlMarkup}
      </summary>
      <AdminForm
        id="api-key-form"
        className="ct-admin__form ct-admin__add-disclosure-form ct-admin__add-disclosure-form--api-key ct-grid"
      >
        <AdminField label="Label">
          <input name="label" type="text" required value="Institution integration key" />
        </AdminField>
        <AdminField label="Scopes (comma separated)">
          <input name="scopes" type="text" value="queue.issue, queue.revoke" />
        </AdminField>
        <AdminButton type="submit">Create API key</AdminButton>
      </AdminForm>
      <AdminStatus id="api-key-status"></AdminStatus>
      <pre id="api-key-secret" class="ct-admin__secret" hidden></pre>
    </details>
  );

  const orgUnitPanelMarkup = (
    <details id="org-unit-panel" class="ct-admin__panel ct-admin__add-disclosure">
      <summary class="ct-admin__add-disclosure-summary">
        <span>
          <strong>Create org unit</strong>
          <small>Add college, department, program, or institution hierarchy.</small>
        </span>
        {addDisclosureControlMarkup}
      </summary>
      <p class="ct-admin__hint">
        Hierarchy: college → institution, department → college, program → department.
      </p>
      <AdminForm
        id="org-unit-form"
        className="ct-admin__form ct-admin__add-disclosure-form ct-admin__add-disclosure-form--org-unit ct-grid"
      >
        <AdminField label="Unit type">
          <select name="unitType" required>
            <option value="college">College</option>
            <option value="department">Department</option>
            <option value="program">Program</option>
            <option value="institution">Institution</option>
          </select>
        </AdminField>
        <AdminField label="Slug">
          <input name="slug" type="text" required placeholder="engineering-college" />
        </AdminField>
        <AdminField label="Display name">
          <input name="displayName" type="text" required placeholder="College of Engineering" />
        </AdminField>
        <AdminField label="Parent org unit">
          <select name="parentOrgUnitId">
            <option value="">None</option>
            {orgUnitParentOptions}
          </select>
        </AdminField>
        <AdminButton type="submit">Create org unit</AdminButton>
      </AdminForm>
      <AdminStatus id="org-unit-status"></AdminStatus>
    </details>
  );

  const governanceGuidePanelMarkup = (
    <AdminPanel id="governance-panel">
      <h2>Before you delegate</h2>
      <p>
        Use this page to give an existing tenant member limited access inside a selected org unit.
        Choosing a parent org unit also covers the child units beneath it.
      </p>
      <p class="ct-admin__hint">
        The user ID on this page belongs to the person receiving access. This workflow does not
        create tenant membership, so the person must already exist in this tenant.
      </p>
      <ul>
        <li>Use a scoped role for standing access inside an org unit.</li>
        <li>Use delegated authority for temporary badge actions with an end date.</li>
        <li>
          Leave badge template IDs blank when the delegation should cover every template in scope.
        </li>
      </ul>
    </AdminPanel>
  );

  const tenantMemberRoleSelectOptions = assignableTenantRoles.map((role) => (
    <option value={role}>{role}</option>
  ));
  const tenantMembersPanelMarkup = (
    <details class="ct-admin__panel ct-admin__add-disclosure">
      <summary class="ct-admin__add-disclosure-summary">
        <span>
          <strong>Add member</strong>
          <small>Add a colleague by institution email and assign their tenant-level role.</small>
        </span>
        {addDisclosureControlMarkup}
      </summary>
      <AdminForm
        id="tenant-member-form"
        className="ct-admin__form ct-admin__add-disclosure-form ct-admin__add-disclosure-form--member ct-grid"
      >
        <AdminField label="Institution email">
          <input name="email" type="email" required placeholder="colleague@institution.edu" />
        </AdminField>
        <AdminField label="Tenant role">
          <select name="role" required>
            {tenantMemberRoleSelectOptions}
          </select>
        </AdminField>
        <AdminCheckboxRow>
          <input name="sendInvite" type="checkbox" checked />
          Email sign-in invite now
        </AdminCheckboxRow>
        <AdminButton type="submit">Save member</AdminButton>
      </AdminForm>
      <AdminStatus id="tenant-member-status"></AdminStatus>
    </details>
  );

  const tenantMembersTableMarkup = (
    <AdminPanel variant="table" className="ct-admin__members-table">
      <h2>Current Members ({tenantMemberCount})</h2>
      <p>
        Review tenant-level access, resend invites, and remove members who no longer need this
        organization.
      </p>
      <AdminTable
        headers={["Member", "Tenant role", "Joined", "Updated", "Status", "Actions"]}
        tbodyId="tenant-member-body"
      >
        {tenantMemberRows}
      </AdminTable>
      <AdminStatus id="tenant-member-list-status"></AdminStatus>
    </AdminPanel>
  );

  const accessOverviewPanelMarkup = (
    <section class="ct-admin__workspace-grid ct-grid" aria-label="Access pages">
      <AdminWorkspaceCard>
        <p class="ct-admin__eyebrow">People</p>
        <h2>Members</h2>
        <p>
          Add colleagues by email, assign tenant roles, resend invites, and remove tenant access.
        </p>
        <div class="ct-admin__workspace-stats ct-cluster">
          <AdminStatusPill>{tenantMemberCount} members</AdminStatusPill>
        </div>
      </AdminWorkspaceCard>
      <AdminWorkspaceCard>
        <p class="ct-admin__eyebrow">Delegation</p>
        <h2>Governance</h2>
        <p>Grant org-unit scoped roles and time-boxed badge authority.</p>
        <div class="ct-admin__workspace-stats ct-cluster">
          <AdminStatusPill>{scopedRoleCount} scoped roles</AdminStatusPill>
          <AdminStatusPill>{delegatedAuthorityGrantCount} delegations</AdminStatusPill>
        </div>
      </AdminWorkspaceCard>
      <AdminWorkspaceCard>
        <p class="ct-admin__eyebrow">Integrations</p>
        <h2>API Keys</h2>
        <p>Create and revoke tenant API keys for trusted integrations.</p>
        <div class="ct-admin__workspace-stats ct-cluster">
          <AdminStatusPill>{activeApiKeyCount} active</AdminStatusPill>
          <AdminStatusPill>{revokedApiKeyCount} revoked</AdminStatusPill>
        </div>
      </AdminWorkspaceCard>
      <AdminWorkspaceCard>
        <p class="ct-admin__eyebrow">Structure</p>
        <h2>Org Units</h2>
        <p>Maintain institution, college, department, and program hierarchy.</p>
        <div class="ct-admin__workspace-stats ct-cluster">
          <AdminStatusPill>{orgUnitCount} org units</AdminStatusPill>
        </div>
      </AdminWorkspaceCard>
    </section>
  );

  const membershipScopePanelMarkup = (
    <AdminPanel>
      <h2>Scoped Roles</h2>
      <p>Assign the smallest org-unit role that matches the person’s ongoing responsibilities.</p>
      <AdminForm id="membership-scope-form">
        <AdminField label="Tenant member user ID">
          <input name="userId" type="text" required placeholder="usr_issuer" />
        </AdminField>
        <p class="ct-admin__hint">
          This is the person receiving access. They must already belong to this tenant.
        </p>
        <AdminField label="Org unit">
          <select name="orgUnitId" required>
            {activeOrgUnitSelectOptions}
          </select>
        </AdminField>
        <AdminField label="Scoped role">
          <select name="role" required>
            <option value="viewer">viewer</option>
            <option value="issuer">issuer</option>
            <option value="admin">admin</option>
          </select>
        </AdminField>
        <ul>
          <li>
            <strong>viewer</strong> can view in-scope templates and governance context.
          </li>
          <li>
            <strong>issuer</strong> includes viewer access and issuer workflows inside the selected
            scope.
          </li>
          <li>
            <strong>admin</strong> is the highest org-unit role and covers issuer and viewer checks.
          </li>
        </ul>
        <AdminButton type="submit">Save scoped role</AdminButton>
      </AdminForm>
      <AdminStatus id="membership-scope-status"></AdminStatus>
    </AdminPanel>
  );

  const membershipScopeTableMarkup = (
    <AdminPanel variant="table">
      <h2>Current Scoped Roles ({scopedRoleCount})</h2>
      <p>Remove access directly from the list instead of re-entering the same identifiers.</p>
      <AdminTable
        headers={["Member", "Org unit", "Role", "Updated", "Action"]}
        tbodyId="membership-scope-body"
      >
        {membershipScopeRows}
      </AdminTable>
      <AdminStatus id="membership-scope-list-status"></AdminStatus>
    </AdminPanel>
  );

  const delegatedGrantPanelMarkup = (
    <AdminPanel>
      <h2>Delegated Authority</h2>
      <p>Grant time-boxed badge authority without changing the person’s standing org-unit role.</p>
      <AdminForm id="delegated-grant-form">
        <AdminField label="Delegate user ID">
          <input name="delegateUserId" type="text" required placeholder="usr_issuer" />
        </AdminField>
        <p class="ct-admin__hint">This is the tenant member receiving the delegation.</p>
        <AdminField label="Org unit">
          <select name="orgUnitId" required>
            {activeOrgUnitSelectOptions}
          </select>
        </AdminField>
        <AdminFieldset legend="Allowed badge actions">
          <AdminCheckboxRow>
            <input name="allowedAction" type="checkbox" value="issue_badge" checked />
            Issue badges
          </AdminCheckboxRow>
          <AdminCheckboxRow>
            <input name="allowedAction" type="checkbox" value="revoke_badge" />
            Revoke badges
          </AdminCheckboxRow>
          <AdminCheckboxRow>
            <input name="allowedAction" type="checkbox" value="manage_lifecycle" />
            Change badge status
          </AdminCheckboxRow>
        </AdminFieldset>
        <p class="ct-admin__hint">
          “Change badge status” covers non-revocation lifecycle changes such as suspend, expire, or
          restore.
        </p>
        <AdminField label="Limit to badge template IDs (optional)">
          <input
            name="badgeTemplateIds"
            type="text"
            placeholder="badge_template_001,badge_template_002"
          />
        </AdminField>
        <p class="ct-admin__hint">
          Leave blank to allow all badge templates inside the selected org-unit scope.
        </p>
        <AdminField label="Ends at">
          <input name="endsAt" type="datetime-local" required />
        </AdminField>
        <p class="ct-admin__hint">
          Delegations are time-boxed. Choose when this authority should expire.
        </p>
        <AdminField label="Reason (optional)">
          <input name="reason" type="text" placeholder="Coverage for spring term operations." />
        </AdminField>
        <AdminButton type="submit">Save delegation</AdminButton>
      </AdminForm>
      <AdminStatus id="delegated-grant-status"></AdminStatus>
    </AdminPanel>
  );

  const delegatedGrantTableMarkup = (
    <AdminPanel variant="table">
      <h2>Current Delegations ({String(input.delegatedIssuingAuthorityGrants.length)})</h2>
      <p>Remove active or scheduled delegations directly from the list.</p>
      <AdminTable
        headers={["Delegate", "Org unit", "Allowed actions", "Granted", "Status", "Action"]}
        tbodyId="delegated-grant-body"
      >
        {delegatedGrantRows}
      </AdminTable>
      <AdminStatus id="delegated-grant-list-status"></AdminStatus>
    </AdminPanel>
  );

  const ruleValueListsPanelMarkup = (
    <AdminPanel id="rule-value-lists-panel">
      <h2>Rule Value Lists</h2>
      <p>
        Create reusable course and badge-template lists so authors stop copying long IDs into every
        rule.
      </p>
      <AdminForm id="rule-value-list-form">
        <AdminField label="Label">
          <input name="label" type="text" required placeholder="Core CS sequence" />
        </AdminField>
        <AdminField label="List kind">
          <select name="kind" required>
            <option value="course_ids">Course IDs</option>
            <option value="badge_template_ids">Badge template IDs</option>
          </select>
        </AdminField>
        <AdminField label="Values (comma separated)">
          <textarea
            name="values"
            rows={4}
            required
            spellcheck={false}
            placeholder="CS101, CS102, CS103"
          ></textarea>
        </AdminField>
        <AdminButton type="submit">Create value list</AdminButton>
      </AdminForm>
      <AdminStatus id="rule-value-list-status"></AdminStatus>
      <AdminTable headers={["Label", "Kind", "Values"]} tbodyId="rule-value-list-body">
        <AdminEmptyTableRow colSpan={3}>No rule value lists loaded yet.</AdminEmptyTableRow>
      </AdminTable>
    </AdminPanel>
  );

  const evaluateRulePanelMarkup = (
    <AdminPanel>
      <h2>Evaluate Rule</h2>
      <p>Run rule evaluation in dry run mode before issuing for real.</p>
      <AdminForm id="rule-evaluate-form">
        <AdminField label="Rule">
          <select name="ruleId" required>
            {ruleSelectOptions}
          </select>
        </AdminField>
        <AdminField label="Learner ID">
          <input name="learnerId" type="text" required placeholder="canvas:12345" />
        </AdminField>
        <AdminField label="Recipient email">
          <input name="recipientIdentity" type="email" required placeholder="learner@example.edu" />
        </AdminField>
        <AdminField label="Course ID for provided facts">
          <input name="courseId" type="text" required placeholder="CS101" />
        </AdminField>
        <AdminField label="Final score for provided facts">
          <input
            name="finalScore"
            type="number"
            min="0"
            max="100"
            step="0.01"
            required
            value="92"
          />
        </AdminField>
        <AdminCheckboxRow>
          <input name="completed" type="checkbox" checked />
          Learner completed course
        </AdminCheckboxRow>
        <AdminCheckboxRow>
          <input name="dryRun" type="checkbox" checked />
          Dry run (don’t issue badge)
        </AdminCheckboxRow>
        <AdminButton type="submit">Evaluate rule</AdminButton>
      </AdminForm>
      <AdminStatus id="rule-evaluate-status"></AdminStatus>
    </AdminPanel>
  );

  const badgeStatusPanelMarkup = (
    <AdminPanel id="lifecycle-panel">
      <h2>Badge Status</h2>
      <p>
        Look up a badge, review its current status, and apply state changes with institutional
        reason codes.
      </p>
      <AdminForm id="assertion-lifecycle-view-form">
        <AdminField label="Assertion ID">
          <input name="assertionId" type="text" required placeholder="tenant_123:assertion_456" />
        </AdminField>
        <AdminButton type="submit">Load lifecycle</AdminButton>
      </AdminForm>
      <AdminStatus id="assertion-lifecycle-view-status"></AdminStatus>
      <pre id="assertion-lifecycle-output" class="ct-admin__code-output" hidden></pre>
      <AdminForm id="assertion-lifecycle-transition-form">
        <AdminField label="Assertion ID">
          <input name="assertionId" type="text" required placeholder="tenant_123:assertion_456" />
        </AdminField>
        <AdminField label="Transition to">
          <select name="toState" required>
            <option value="active">active</option>
            <option value="suspended">suspended</option>
            <option value="revoked">revoked</option>
            <option value="expired">expired</option>
          </select>
        </AdminField>
        <AdminField label="Reason code">
          <select name="reasonCode" required>
            <option value="administrative_hold">administrative_hold</option>
            <option value="policy_violation">policy_violation</option>
            <option value="appeal_pending">appeal_pending</option>
            <option value="appeal_resolved">appeal_resolved</option>
            <option value="credential_expired">credential_expired</option>
            <option value="issuer_requested">issuer_requested</option>
            <option value="other">other</option>
          </select>
        </AdminField>
        <AdminField label="Reason details (optional)">
          <input
            name="reason"
            type="text"
            placeholder="Explain why this transition is being applied."
          />
        </AdminField>
        <AdminButton type="submit">Apply transition</AdminButton>
      </AdminForm>
      <AdminStatus id="assertion-lifecycle-transition-status"></AdminStatus>
    </AdminPanel>
  );

  const ruleGovernancePanelMarkup = (
    <AdminPanel>
      <h2>Rule Governance Context</h2>
      <p>Inspect latest approval chain and rule audit events for operator drill-down.</p>
      <AdminForm id="rule-governance-form">
        <AdminField label="Rule">
          <select name="ruleId" required>
            {ruleSelectOptions}
          </select>
        </AdminField>
        <AdminField label="Audit log limit">
          <input name="auditLimit" type="number" min="1" max="100" step="1" value="20" />
        </AdminField>
        <AdminButton type="submit">Load governance context</AdminButton>
      </AdminForm>
      <AdminStatus id="rule-governance-status"></AdminStatus>
      <pre id="rule-governance-output" class="ct-admin__code-output" hidden></pre>
    </AdminPanel>
  );

  const ruleReviewQueuePanelMarkup = (
    <AdminPanel id="rule-review-queue-panel" variant="table">
      <h2>Rule Review Queue</h2>
      <p>
        Missing-data evaluations that require a human issue-or-dismiss decision before a badge is
        created.
      </p>
      <AdminActions>
        <AdminButton id="rule-review-queue-refresh" type="button" size="tiny" variant="secondary">
          Refresh review queue
        </AdminButton>
      </AdminActions>
      <AdminStatus id="rule-review-queue-status">No review queue entries loaded yet.</AdminStatus>
      <AdminTable
        headers={["Evaluated", "Recipient", "Rule", "Summary", "Actions"]}
        tbodyId="rule-review-queue-body"
      >
        <AdminEmptyTableRow colSpan={5}>No review queue entries loaded yet.</AdminEmptyTableRow>
      </AdminTable>
    </AdminPanel>
  );

  const issuedBadgesPanelMarkup = (
    <AdminPanel id="issued-badges-panel" variant="table">
      <h2>Issued Badges Ledger</h2>
      <p>Tenant-wide assertion log with direct audit and revocation actions.</p>
      <AdminForm
        id="issued-badges-filter-form"
        className="ct-admin__form ct-admin__form--inline ct-grid"
      >
        <AdminField label="Recipient / assertion search">
          <input
            name="recipientQuery"
            type="text"
            placeholder="csev@umich.edu or tenant_123:assertion_456"
          />
        </AdminField>
        <AdminField label="Badge template">
          <select name="badgeTemplateId">
            <option value="">All templates</option>
            {templateFilterOptions}
          </select>
        </AdminField>
        <AdminField label="Lifecycle state">
          <select name="state">
            <option value="">All states</option>
            <option value="active">active</option>
            <option value="suspended">suspended</option>
            <option value="revoked">revoked</option>
            <option value="expired">expired</option>
          </select>
        </AdminField>
        <AdminField label="Limit">
          <input name="limit" type="number" min="1" max="500" step="1" value="100" />
        </AdminField>
        <AdminButton type="submit">Load issued badges</AdminButton>
      </AdminForm>
      <AdminPanel as="section" variant="nested">
        <div class="ct-cluster">
          <h3>Ledger export</h3>
          <AdminStatusPill>Owner/admin only</AdminStatusPill>
        </div>
        <p>
          Download an audit-focused CSV directly from the operations workspace. This export stays
          separate from the browser-loaded ledger list and runs as a plain server-side attachment
          response.
        </p>
        <AdminForm
          id="issued-badges-export-form"
          method="get"
          action={`/v1/tenants/${input.tenant.id}/assertions/ledger-export.csv`}
          className="ct-admin__form ct-admin__form--inline ct-grid"
        >
          <AdminField label="Issued from">
            <input name="issuedFrom" type="date" />
          </AdminField>
          <AdminField label="Issued to">
            <input name="issuedTo" type="date" />
          </AdminField>
          <AdminField label="Badge template">
            <select name="badgeTemplateId">
              <option value="">All templates</option>
              {templateFilterOptions}
            </select>
          </AdminField>
          <AdminField label="Org unit">
            <select name="orgUnitId">
              <option value="">All org units</option>
              {activeOrgUnitOptions}
            </select>
          </AdminField>
          <AdminField label="Lifecycle state">
            <select name="state">
              <option value="">All current states</option>
              <option value="active">active</option>
              <option value="suspended">suspended</option>
              <option value="revoked">revoked</option>
              <option value="expired">expired</option>
              <option value="pending_review">pending review</option>
            </select>
          </AdminField>
          <AdminField label="Recipient / assertion search">
            <input
              name="recipientQuery"
              type="text"
              placeholder="Filter by recipient, identifier, or assertion ID"
            />
          </AdminField>
          <AdminButton type="submit">Export ledger CSV</AdminButton>
        </AdminForm>
        <p class="ct-admin__hint">
          Synchronous CSV export is capped at 5000 rows. Narrow the filters above if the export is
          too large for direct download.
        </p>
        <p class="ct-admin__hint">
          Ancestor lineage columns reflect the current org tree only, while stable leaf attribution
          remains the historical contract for audit use.
        </p>
      </AdminPanel>
      <AdminStatus id="issued-badges-status">Load tenant assertions from the browser.</AdminStatus>
      <AdminTable
        headers={["Issued", "Recipient", "Template", "State", "Assertion", "Actions"]}
        tbodyId="issued-badges-body"
      >
        <AdminEmptyTableRow colSpan={6}>No assertions loaded yet.</AdminEmptyTableRow>
      </AdminTable>
      <AdminStatus id="issued-badges-action-status"></AdminStatus>
    </AdminPanel>
  );

  const renderReportingFiltersForm = (
    actionPath: string,
    formClass = "ct-admin__form ct-admin__form--inline ct-grid",
    resetPath = actionPath,
  ): HonoElement => (
    <>
      <AdminForm
        id="reporting-filters-form"
        method="get"
        action={actionPath}
        className={formClass}
        dataAttributes={{
          "data-reporting-submit-state": "idle",
        }}
      >
        <AdminField label="Issued from">
          <input name="issuedFrom" type="date" value={reportingIssuedFromValue} />
        </AdminField>
        <AdminField label="Issued to">
          <input name="issuedTo" type="date" value={reportingIssuedToValue} />
        </AdminField>
        <AdminField label="Badge template">
          <select name="badgeTemplateId">
            <option value="">All templates</option>
            {reportingTemplateFilterOptions}
          </select>
        </AdminField>
        <AdminField label="Org unit">
          <select name="orgUnitId">
            <option value="">All org units</option>
            {reportingOrgUnitOptions}
          </select>
        </AdminField>
        <AdminField label="Lifecycle state">
          <select name="state">
            <option value="">All current states</option>
            <option value="active" selected={reportingState === "active"}>
              active
            </option>
            <option value="suspended" selected={reportingState === "suspended"}>
              suspended
            </option>
            <option value="revoked" selected={reportingState === "revoked"}>
              revoked
            </option>
            <option value="expired" selected={reportingState === "expired"}>
              expired
            </option>
            <option value="pending_review" selected={reportingState === "pending_review"}>
              pending review
            </option>
          </select>
        </AdminField>
        <div class="ct-cluster">
          <AdminButton type="submit">Apply filters</AdminButton>
          <AdminButtonLink href={resetPath} variant="secondary">
            Reset
          </AdminButtonLink>
        </div>
      </AdminForm>
      <p
        id="reporting-filters-status"
        class="ct-admin__hint"
        data-reporting-submit-status
        aria-live="polite"
      >
        Applying filters refreshes this page with the selected reporting slice.
      </p>
    </>
  );

  const reportingOverviewPanelMarkup = (
    <AdminPanel id="reporting-overview-panel">
      <div class="ct-cluster">
        <h2>Reporting Overview</h2>
        <AdminStatusPill>Supporting detail</AdminStatusPill>
      </div>
      <p>
        Filter by issue date, template, org unit, or current badge state. Counts reflect
        product-owned data only, and analytics stay in this reporting workspace.
      </p>
      {renderReportingFiltersForm(reportingExplorePath)}
      <p class="ct-admin__hint">
        Need CSV downloads for this slice?{" "}
        <a href={reportingReportsExportsHref}>Open export options</a>.
      </p>
      <div class="ct-admin__reporting-panel-media">
        {reportingOverviewVisualMarkup}
        <div class="ct-admin__metric-grid">{reportingMetricCardsMarkup}</div>
      </div>
      <p class="ct-admin__hint">
        Generated{" "}
        {reportingOverview === null
          ? "just now"
          : formatIsoTimestamp(reportingOverview.generatedAt)}
      </p>
    </AdminPanel>
  );

  const reportingTrendFiltersPanelMarkup = (
    <details id="reporting-trend-filters-panel" class="ct-admin__panel ct-admin__add-disclosure">
      <summary class="ct-admin__add-disclosure-summary">
        <span>
          <strong>Filter trend data</strong>
          <small>Change date, badge, org unit, or state only when you need a narrower view.</small>
        </span>
        <span class="ct-admin__add-disclosure-control">
          <span class="ct-admin__add-disclosure-control-open">Show filters</span>
          <span class="ct-admin__add-disclosure-control-close">Hide filters</span>
        </span>
      </summary>
      {renderReportingFiltersForm(
        reportingTrendsPath,
        "ct-admin__form ct-admin__add-disclosure-form ct-grid",
      )}
    </details>
  );

  const reportingExportFiltersPanelMarkup = (
    <AdminPanel id="reporting-export-filters-panel">
      <div class="ct-cluster">
        <h2>Export filters</h2>
      </div>
      <p>Choose filters before downloading CSV files.</p>
      {renderReportingFiltersForm(reportingReportsPath)}
    </AdminPanel>
  );

  const reportingEngagementPanelMarkup = (
    <AdminPanel>
      <div class="ct-cluster">
        <h2>Engagement Counts</h2>
        <AdminStatusPill>Product-owned events</AdminStatusPill>
      </div>
      <p>
        Raw counts show event totals. Rates use distinct engaged assertions over issued badges, so
        comparison tables do not inflate because of repeat clicks from one assertion.
      </p>
      {reportingEngagementVisualsMarkup}
      <div class="ct-admin__metric-grid">{reportingEngagementCardsMarkup}</div>
      {reportingRateCardsMarkup.length === 0 ? null : (
        <div class="ct-admin__metric-grid ct-admin__metric-grid--rates">
          {reportingRateCardsMarkup}
        </div>
      )}
    </AdminPanel>
  );

  const renderReportingTrendPanelMarkup = (input: {
    includeDetailedTable: boolean;
  }): HonoElement => (
    <AdminPanel variant="table" dataAttributes={{ "data-reporting-state": reportingTrendState }}>
      <h2>Trend lines</h2>
      <p>{getReportingTrendIntroCopy(input.includeDetailedTable)}</p>
      {input.includeDetailedTable || reportingTrendState !== "rich"
        ? renderReportingTrendHeroMarkup(input.includeDetailedTable)
        : renderReportingTrendVisualMarkup(false)}
      {input.includeDetailedTable ? (
        <div>
          <h3>Detailed trend table</h3>
          <AdminTable
            headers={[
              "Day",
              "Issued",
              "Public badge views",
              "Verification views",
              "Share clicks",
              "Claim actions",
              "Wallet accepts",
            ]}
            tbodyDataAttributes={{ "data-reporting-bar-group": "trends" }}
          >
            {reportingTrendRowsMarkup}
          </AdminTable>
        </div>
      ) : (
        <p class="ct-admin__hint">
          Need exact daily counts? <a href={reportingTrendsHref}>Open trend detail</a>.
        </p>
      )}
    </AdminPanel>
  );

  const reportingTemplateComparisonPanelMarkup = (
    <AdminPanel
      variant="table"
      dataAttributes={{ "data-reporting-state": reportingTemplateComparisonState }}
    >
      <h2>Compare by badge template</h2>
      <p>
        {reportingTemplateComparisonState === "rich"
          ? "Start with the ranked visual for volume-first scanning, then use the exact table below to inspect every visible badge-template row."
          : reportingTemplateComparisonState === "sparse"
            ? "Only one badge template row is visible in this slice, so the exact row below carries the full comparison detail."
            : "Review the current slice below. The comparison table stays in place even when no badge-template rows are yet visible for the selected filters."}
      </p>
      <div class="ct-admin__reporting-panel-media">
        {reportingTemplateComparisonVisualMarkup}
        <AdminTable
          headers={[
            "Badge template",
            "Issued",
            "Public badge views",
            "Verification views",
            "Share clicks",
            "Claim actions",
            "Wallet accepts",
            "Claim rate",
            "Share rate",
          ]}
          tbodyDataAttributes={{ "data-reporting-bar-group": "template-comparisons" }}
        >
          {reportingTemplateComparisonRowsMarkup}
        </AdminTable>
      </div>
    </AdminPanel>
  );

  const reportingOrgUnitComparisonPanelMarkup = (
    <AdminPanel
      variant="table"
      dataAttributes={{ "data-reporting-state": reportingOrgUnitComparisonState }}
    >
      <h2>Compare by org unit</h2>
      <p>
        {reportingOrgUnitComparisonState === "rich"
          ? "Start with the ranked visual for volume-first scanning, then use the exact table below to inspect every visible org-unit row alongside hierarchy drilldowns."
          : reportingOrgUnitComparisonState === "sparse"
            ? "Only one org-unit row is visible in this slice, so use the exact row below to read the current context."
            : "Review the current slice below. The comparison table stays in place even when no org-unit rows are yet visible for the selected filters."}
      </p>
      <div class="ct-admin__reporting-panel-media">
        {reportingOrgUnitComparisonVisualMarkup}
        <AdminTable
          headers={[
            "Org unit",
            "Issued",
            "Public badge views",
            "Verification views",
            "Share clicks",
            "Claim actions",
            "Wallet accepts",
            "Claim rate",
            "Share rate",
          ]}
          tbodyDataAttributes={{ "data-reporting-bar-group": "org-comparisons" }}
        >
          {reportingOrgUnitComparisonRowsMarkup}
        </AdminTable>
      </div>
    </AdminPanel>
  );

  const reportingDefinitionsPanelMarkup = (
    <AdminPanel variant="table">
      <h2>Metric Definitions</h2>
      <p>
        Every number in this page lists its source so institution admins can tell the difference
        between event totals and rate-style comparisons.
      </p>
      <AdminTable headers={["Metric", "Source", "Status", "Notes"]}>
        {reportingDefinitionRows}
      </AdminTable>
    </AdminPanel>
  );

  const reportingDeferredPanelMarkup =
    reportingDeferredMetricsMarkup.length === 0 ? null : (
      <section class="ct-admin__grid ct-stack">{reportingDeferredMetricsMarkup}</section>
    );
  const reportingPresentationNoteMarkup = (
    <aside
      class="ct-admin__reporting-presentation-note ct-stack"
      aria-label="Selected reporting slice note"
    >
      <p>
        <strong>Smart defaults active.</strong> Current slice, visible org scope, and deep links
        stay aligned.
      </p>
      <p class="ct-admin__hint">
        <a href={reportingExploreHref}>Explore filters</a> ·{" "}
        <a href={reportingTrendsHref}>Trend detail</a> · <a href={reportingReportsHref}>Reports</a>
      </p>
    </aside>
  );
  const reportingTemplateHighlightsPanelMarkup = renderReportingHighlightComparisonPanel({
    eyebrow: "Template performance",
    title: "Top badge templates",
    visualId: "reporting-highlights-templates",
    visualDescription:
      "Top issued badge templates for the selected reporting slice, with public views plus claim and share context carried beside each row.",
    rows: reportingTemplateHighlightRows,
    totalRowCount: reportingTemplateComparisons.length,
    emptyTitle: "No template highlights are available for this slice yet.",
    emptyDescription:
      "Widen the date window or remove a filter in Explore to review badge-template performance.",
    actionHref: reportingExploreHref,
    exportHref: reportingTemplateComparisonExportHref,
  });
  const reportingOrgUnitHighlightsPanelMarkup = renderReportingHighlightComparisonPanel({
    eyebrow: "Org performance",
    title: "Top org units",
    visualId: "reporting-highlights-org-units",
    visualDescription:
      "Top issued organization units for the selected reporting slice, scoped to the rows this user can see.",
    rows: reportingOrgUnitHighlightRows,
    totalRowCount: reportingOrgUnitComparisons.length,
    emptyTitle: "No org-unit highlights are available for this slice yet.",
    emptyDescription:
      "Widen the date window or remove a filter in Explore to review org-unit performance.",
    actionHref: reportingExploreHref,
    exportHref: reportingOrgUnitComparisonExportHref,
  });
  const reportingDrilldownHighlightsPanelMarkup = (
    <AdminPanel
      className="ct-admin__reporting-highlight-panel"
      dataAttributes={{ "data-reporting-state": reportingHierarchyState }}
    >
      <div class="ct-cluster">
        <div class="ct-stack">
          <p class="ct-admin__eyebrow">Scoped drilldowns</p>
          <h2>Open a visible reporting path</h2>
        </div>
        <AdminStatusPill>{reportingVisibleRoots.length} roots</AdminStatusPill>
      </div>
      {reportingVisibleRoots.length === 0 ? (
        renderReportingStateShell({
          state: reportingHierarchyState === "empty" ? "empty" : "sparse",
          eyebrow: "No drilldown path yet",
          title: "Drilldowns appear when visible org-unit rows exist.",
          description:
            "The Highlights home keeps the selected slice stable; Explore will show hierarchy tables once comparable rows exist.",
        })
      ) : (
        <>
          <p>
            Start from the highest visible reporting roots, then continue through Explore for exact
            hierarchy tables and CSV context.
          </p>
          <div class="ct-admin__reporting-root-links">
            {reportingVisibleRoots.map((rootOrgUnit) => (
              <a
                class="ct-admin__reporting-root-link"
                href={buildReportingHierarchyDrillHref(rootOrgUnit.id)}
                data-reporting-focus-link
                data-reporting-root-link
                data-reporting-focus-target={buildReportingHierarchyFocusId(rootOrgUnit.id)}
              >
                {rootOrgUnit.displayName}
              </a>
            ))}
          </div>
        </>
      )}
      <div class="ct-admin__reporting-highlight-actions">
        <AdminButtonLink href={reportingExploreHref} variant="secondary">
          Open hierarchy
        </AdminButtonLink>
      </div>
    </AdminPanel>
  );
  const reportingDeepLinksMarkup = (
    <section class="ct-admin__reporting-deep-links" aria-label="Advanced reporting links">
      <a href={reportingExploreHref}>
        <span>Explore</span>
        <strong>Filters, tables, and hierarchy</strong>
      </a>
      <a href={reportingTrendsHref}>
        <span>Trends</span>
        <strong>Daily counts behind the chart</strong>
      </a>
      <a href={reportingReportsHref}>
        <span>Reports</span>
        <strong>Saved reports, custom setup, and exports</strong>
      </a>
    </section>
  );
  const reportingSavedReportsPanelMarkup = (
    <AdminPanel id="reporting-reports-saved" className="ct-admin__reporting-placeholder-panel">
      <div class="ct-cluster">
        <div class="ct-stack">
          <p class="ct-admin__eyebrow">Saved reports</p>
          <h2>Saved report shortcuts will live here.</h2>
        </div>
        <AdminStatusPill>Planned</AdminStatusPill>
      </div>
      <p>
        Reserved for named reports that preserve a reporting slice, audience, and export intent. For
        now, use Highlights for the default read and Explore for the exact table workspace.
      </p>
      <div class="ct-admin__reporting-highlight-actions">
        <AdminButtonLink href={reportingPath} variant="secondary">
          Open Highlights
        </AdminButtonLink>
        <AdminButtonLink href={reportingExploreHref} variant="ghost">
          Open Explore
        </AdminButtonLink>
      </div>
    </AdminPanel>
  );
  const reportingCustomReportsPanelMarkup = (
    <AdminPanel id="reporting-reports-custom" className="ct-admin__reporting-placeholder-panel">
      <div class="ct-cluster">
        <div class="ct-stack">
          <p class="ct-admin__eyebrow">Custom reports</p>
          <h2>Custom report setup will live here.</h2>
        </div>
        <AdminStatusPill>Planned</AdminStatusPill>
      </div>
      <p>
        Custom report builders and reusable export profiles are planned. Current filters still
        travel through Explore, Trends, and Reports.
      </p>
      <div class="ct-admin__reporting-highlight-actions">
        <AdminButtonLink href={reportingExploreHref} variant="secondary">
          Build from Explore
        </AdminButtonLink>
        <AdminButtonLink href={reportingReportsExportsHref} variant="ghost">
          Export current slice
        </AdminButtonLink>
      </div>
    </AdminPanel>
  );
  const reportingReportsLibraryMarkup = (
    <section class="ct-admin__reporting-highlight-grid">
      {reportingSavedReportsPanelMarkup}
      {reportingCustomReportsPanelMarkup}
    </section>
  );
  const reportingLowerStoryMarkup = (
    <section class="ct-admin__reporting-lower-story" aria-label="Reporting lower-page story">
      <div class="ct-admin__reporting-lower-story-intro ct-stack">
        <p class="ct-admin__eyebrow">Lower-page story</p>
        <p>
          Move from template comparison into hierarchy context, performer rankings, and org-unit
          comparison while the exact tables stay adjacent to each shared visual.
        </p>
      </div>
      {reportingTemplateComparisonPanelMarkup}
      {reportingHierarchyPanelMarkup}
      {reportingPerformerPanelsMarkup}
      {reportingOrgUnitComparisonPanelMarkup}
    </section>
  );

  const badgeRulesTableMarkup = (
    <AdminPanel variant="table">
      <h2>Badge Rules ({ruleCount})</h2>
      <p>Lifecycle actions operate on each rule’s latest version.</p>
      <AdminTable
        headers={[
          "Rule",
          "Template",
          "LMS",
          "Active Version",
          "Latest Version",
          "Status",
          "Updated",
          "Actions",
        ]}
      >
        {ruleRows}
      </AdminTable>
      <AdminStatus id="rule-action-status"></AdminStatus>
    </AdminPanel>
  );

  const badgeTemplatesTableMarkup = (
    <AdminPanel variant="table">
      <h2>Badge Templates ({badgeTemplateCount})</h2>
      <AdminTable headers={["Image", "Template", "Slug", "Updated", "Links"]}>
        {templateRows}
      </AdminTable>
    </AdminPanel>
  );

  const orgUnitsTableMarkup = (
    <AdminPanel variant="table" className="ct-admin__org-units-table">
      <h2>Org Units ({orgUnitCount})</h2>
      <AdminTable headers={["Name", "Type", "ID", "Status"]}>{orgUnitRows}</AdminTable>
    </AdminPanel>
  );

  const apiKeysTableMarkup = (
    <AdminPanel variant="table" className="ct-admin__api-keys-table">
      <h2>Active API Keys ({activeApiKeyCount})</h2>
      <p>Revoked keys: {revokedApiKeyCount}</p>
      <AdminTable headers={["Label", "Prefix", "Scopes", "Expires", "Action"]}>
        {apiKeyRows}
      </AdminTable>
      <AdminStatus id="api-key-revoke-status"></AdminStatus>
    </AdminPanel>
  );

  const formatLearnerRecordReviewDetailValue = (label: string, value: string): string => {
    if (label === "Issued" || label === "Revised" || label === "Revoked") {
      return `${formatIsoTimestamp(value)} UTC`;
    }

    return value;
  };

  const renderLearnerRecordReviewItem = (
    item: NonNullable<
      InstitutionAdminLearnerRecordReview["presentation"]
    >["sections"][number]["items"][number],
  ): HonoElement => {
    const descriptionMarkup = item.description === null ? null : <p>{item.description}</p>;
    const detailsMarkup =
      item.details.length === 0 ? (
        <p class="ct-admin__meta">No additional record details are attached to this item.</p>
      ) : (
        <dl class="ct-stack">
          {item.details.map((row) => (
            <div>
              <dt class="ct-admin__meta">{row.label}</dt>
              <dd>{row.value}</dd>
            </div>
          ))}
        </dl>
      );
    const provenanceMarkup = (
      <dl class="ct-stack">
        {item.provenanceDetails.map((row) => (
          <div>
            <dt class="ct-admin__meta">{row.label}</dt>
            <dd>{formatLearnerRecordReviewDetailValue(row.label, row.value)}</dd>
          </div>
        ))}
      </dl>
    );
    const evidenceMarkup =
      item.evidenceLinks.length === 0 ? null : (
        <div class="ct-stack">
          <p class="ct-admin__meta">Evidence</p>
          <ul class="ct-stack">
            {item.evidenceLinks.map((href) => (
              <li>
                <a href={href} target="_blank" rel="noopener noreferrer">
                  {href}
                </a>
              </li>
            ))}
          </ul>
        </div>
      );
    const publicBadgeMarkup =
      item.publicBadgePath === null ? null : (
        <AdminCtaLink href={item.publicBadgePath}>Open public badge</AdminCtaLink>
      );

    return (
      <AdminMetricCard stack>
        <div class="ct-stack">
          <p class="ct-admin__meta">{item.recordTypeLabel}</p>
          <h3>{item.title}</h3>
          {descriptionMarkup}
          <p class="ct-admin__meta">
            {item.trustLabel} · {item.statusLabel}
          </p>
          <p class="ct-admin__meta">{item.provenanceSummary}</p>
        </div>
        <div class="ct-stack">
          <section class="ct-stack">
            <h4>Record details</h4>
            {detailsMarkup}
          </section>
          <section class="ct-stack">
            <h4>Provenance</h4>
            {provenanceMarkup}
          </section>
          {evidenceMarkup}
        </div>
        {publicBadgeMarkup}
      </AdminMetricCard>
    );
  };

  const renderLearnerRecordReviewSections = (): HonoElement => {
    if (learnerRecordReview.lookupState === "idle") {
      return (
        <AdminPanel>
          <h2>Choose one learner</h2>
          <p>
            Use a learner profile ID or learner email already associated with this tenant to review
            one unified learner record. This page is intentionally bounded and does not try to be a
            full learner-search or ingest workspace.
          </p>
        </AdminPanel>
      );
    }

    if (learnerRecordReview.lookupState === "unresolved") {
      return (
        <AdminPanel>
          <h2>No learner record found</h2>
          <AdminStatus tone="warning">
            No learner profile matched this lookup. Check the learner profile ID or email and try
            again.
          </AdminStatus>
        </AdminPanel>
      );
    }

    const presentation = learnerRecordReview.presentation;

    if (presentation === null || learnerRecordReview.learnerProfile === null) {
      return <></>;
    }

    const exportLinksMarkup = (
      <AdminPanel>
        <h2>Export and standards mapping</h2>
        <p>
          These links point to the real Phase 27 runtime endpoints for the selected learner. They do
          not imply transcript exchange or full CLR conformance.
        </p>
        <div class="ct-admin__workspace-actions">
          {learnerRecordReview.exportPath === null ? null : (
            <AdminCtaLink href={learnerRecordReview.exportPath}>
              Download native portable export
            </AdminCtaLink>
          )}
          {learnerRecordReview.standardsMappingPath === null ? null : (
            <AdminCtaLink href={learnerRecordReview.standardsMappingPath}>
              Open standards mapping
            </AdminCtaLink>
          )}
        </div>
      </AdminPanel>
    );

    return (
      <section class="ct-stack">
        <AdminPanel>
          <h2>Learner overview</h2>
          <p>
            Reviewing{" "}
            <strong>
              {learnerRecordReview.learnerProfile.displayName ??
                learnerRecordReview.learnerProfile.id}
            </strong>
            .
          </p>
          <p class="ct-admin__meta">Learner profile ID: {learnerRecordReview.learnerProfile.id}</p>
          <p class="ct-admin__meta">Subject ID: {learnerRecordReview.learnerProfile.subjectId}</p>
          <section class="ct-admin__metric-grid">
            <AdminMetricCard>
              <p class="ct-admin__meta">Total items</p>
              <p class="ct-admin__metric-value">{presentation.summary.total}</p>
            </AdminMetricCard>
            <AdminMetricCard>
              <p class="ct-admin__meta">Issuer verified</p>
              <p class="ct-admin__metric-value">{presentation.summary.issuerVerified}</p>
            </AdminMetricCard>
            <AdminMetricCard>
              <p class="ct-admin__meta">Learner supplemental</p>
              <p class="ct-admin__metric-value">{presentation.summary.supplemental}</p>
            </AdminMetricCard>
            <AdminMetricCard>
              <p class="ct-admin__meta">Historical</p>
              <p class="ct-admin__metric-value">{presentation.summary.historical}</p>
            </AdminMetricCard>
          </section>
        </AdminPanel>
        {exportLinksMarkup}
        {presentation.sections.map((section) => (
          <AdminPanel>
            <h2>{section.title}</h2>
            <p>{section.description}</p>
            <p class="ct-admin__meta">{section.itemCountLabel}</p>
            <section class="ct-admin__metric-grid">
              {section.items.map((item) => renderLearnerRecordReviewItem(item))}
            </section>
          </AdminPanel>
        ))}
      </section>
    );
  };

  const learnerRecordReviewPanelMarkup = (
    <AdminPanel>
      <h2>Learner record review</h2>
      <p>
        Open one learner’s unified record by learner profile ID or learner email already associated
        with this tenant. This page is review-only and intentionally stops short of broader ingest
        or transcript workflow claims.
      </p>
      <AdminForm method="get" action={operationsLearnerRecordsPath}>
        <AdminField label="Learner profile ID">
          <input
            name="learnerProfileId"
            type="text"
            value={learnerRecordReview.lookup.learnerProfileId ?? ""}
            placeholder="lpr_123"
          />
        </AdminField>
        <AdminField label="Learner email">
          <input
            name="email"
            type="email"
            value={learnerRecordReview.lookup.email ?? ""}
            placeholder="learner@example.edu"
          />
        </AdminField>
        <div class="ct-admin__workspace-actions">
          <AdminButton type="submit">Load learner record</AdminButton>
          <AdminButtonLink href={operationsLearnerRecordsPath} variant="secondary">
            Clear lookup
          </AdminButtonLink>
        </div>
      </AdminForm>
    </AdminPanel>
  );

  const renderLearnerRecordImportRowReport = (
    report: LearnerRecordImportRowReport,
  ): HonoElement => {
    const preview = report.preview;
    const contextSummary =
      preview === null
        ? "No preview"
        : [
            preview.smartContext.orgUnitLabel === null
              ? "No org-unit default"
              : `Org unit: ${preview.smartContext.orgUnitLabel}`,
            preview.smartContext.badgeTemplateLabel === null
              ? "No badge-template default"
              : `Badge template: ${preview.smartContext.badgeTemplateLabel}`,
            preview.smartContext.pathwayLabel === null
              ? "No pathway hint"
              : `Pathway hint: ${preview.smartContext.pathwayLabel}`,
          ].join(" · ");
    const notes = [...report.errors, ...report.warnings];

    return (
      <tr>
        <td>{report.rowNumber}</td>
        <td>
          <span class="ct-admin__status-pill">{report.status}</span>
        </td>
        <td>
          {preview === null
            ? "No import preview available"
            : `${preview.learner.email} · ${preview.record.title}`}
        </td>
        <td>
          {preview === null ? "Unavailable" : `${preview.trustLevel} · ${preview.issuerName}`}
        </td>
        <td>{contextSummary}</td>
        <td>{notes.length === 0 ? "Ready to apply." : notes.join(" ")}</td>
      </tr>
    );
  };

  const learnerRecordImportFeedbackMarkup =
    learnerRecordImportWorkflow.feedback === null ? null : (
      <AdminPanel
        dataAttributes={{
          "data-learner-record-import-feedback": learnerRecordImportWorkflow.feedback.tone,
        }}
      >
        <h2>{learnerRecordImportWorkflow.feedback.title}</h2>
        <p>{learnerRecordImportWorkflow.feedback.detail}</p>
      </AdminPanel>
    );

  const learnerRecordImportSubmissionMarkup =
    learnerRecordImportWorkflow.submission === null ? (
      <AdminPanel dataAttributes={{ "data-learner-record-import-state": "idle" }}>
        <h2>No batch loaded yet</h2>
        <p>
          Upload a CSV to preview trust classification, inferred org-unit or badge-template context,
          and any pathway hints before you queue the batch.
        </p>
      </AdminPanel>
    ) : (
      <AdminPanel
        dataAttributes={{
          "data-learner-record-import-state": learnerRecordImportWorkflow.submission.mode,
        }}
      >
        <h2>
          {learnerRecordImportWorkflow.submission.mode === "apply"
            ? "Queued batch"
            : "Preview batch"}
        </h2>
        <p>
          {learnerRecordImportWorkflow.submission.fileName} · batch{" "}
          {learnerRecordImportWorkflow.submission.batchId}
        </p>
        <section class="ct-admin__metric-grid">
          <AdminMetricCard>
            <p class="ct-admin__meta">Total rows</p>
            <p class="ct-admin__metric-value">
              {formatReportingCount(learnerRecordImportWorkflow.submission.totalRows)}
            </p>
          </AdminMetricCard>
          <AdminMetricCard>
            <p class="ct-admin__meta">Valid rows</p>
            <p class="ct-admin__metric-value">
              {formatReportingCount(learnerRecordImportWorkflow.submission.validRows)}
            </p>
          </AdminMetricCard>
          <AdminMetricCard>
            <p class="ct-admin__meta">Invalid rows</p>
            <p class="ct-admin__metric-value">
              {formatReportingCount(learnerRecordImportWorkflow.submission.invalidRows)}
            </p>
          </AdminMetricCard>
          <AdminMetricCard>
            <p class="ct-admin__meta">Queued rows</p>
            <p class="ct-admin__metric-value">
              {formatReportingCount(learnerRecordImportWorkflow.submission.queuedRows)}
            </p>
          </AdminMetricCard>
        </section>
        <AdminTable
          headers={["Row", "Status", "Learner and record", "Trust", "Smart defaults", "Notes"]}
          wrapperClassName="ct-admin__table-shell"
        >
          {learnerRecordImportWorkflow.submission.rows.map((report) =>
            renderLearnerRecordImportRowReport(report),
          )}
        </AdminTable>
      </AdminPanel>
    );

  const learnerRecordImportProgressMarkup = (
    <AdminPanel>
      <h2>Current import progress</h2>
      <p>
        These batch states come from the real learner-record import queue. Failed rows can be
        retried without replaying the whole upload.
      </p>
      <section class="ct-admin__metric-grid">
        <AdminMetricCard>
          <p class="ct-admin__meta">Batches</p>
          <p class="ct-admin__metric-value">
            {formatReportingCount(learnerRecordImportWorkflow.progress.totals.batches)}
          </p>
        </AdminMetricCard>
        <AdminMetricCard>
          <p class="ct-admin__meta">Pending rows</p>
          <p class="ct-admin__metric-value">
            {formatReportingCount(learnerRecordImportWorkflow.progress.totals.pendingRows)}
          </p>
        </AdminMetricCard>
        <AdminMetricCard>
          <p class="ct-admin__meta">Completed rows</p>
          <p class="ct-admin__metric-value">
            {formatReportingCount(learnerRecordImportWorkflow.progress.totals.completedRows)}
          </p>
        </AdminMetricCard>
        <AdminMetricCard>
          <p class="ct-admin__meta">Failed rows</p>
          <p class="ct-admin__metric-value">
            {formatReportingCount(learnerRecordImportWorkflow.progress.totals.failedRows)}
          </p>
        </AdminMetricCard>
      </section>
      {learnerRecordImportWorkflow.progress.batches.length === 0 ? (
        <p class="ct-admin__hint">
          No learner-record import batches have been queued for this tenant yet.
        </p>
      ) : (
        <section class="ct-admin__metric-grid">
          {learnerRecordImportWorkflow.progress.batches.map((batch) => {
            const retryMarkup =
              batch.failedRows === 0 ? null : (
                <AdminForm
                  method="post"
                  action={`${operationsLearnerRecordImportsPath}/${encodeURIComponent(batch.batchId)}/retry`}
                  className="ct-stack"
                >
                  <AdminButton type="submit">Retry failed rows</AdminButton>
                </AdminForm>
              );

            return (
              <AdminMetricCard
                stack
                dataAttributes={{ "data-learner-record-import-batch": batch.batchId }}
              >
                <div class="ct-stack">
                  <p class="ct-admin__meta">{batch.fileName ?? "CSV import"}</p>
                  <h3>{batch.batchId}</h3>
                  <p class="ct-admin__meta">
                    Pending {formatReportingCount(batch.pendingRows)} · Processing{" "}
                    {formatReportingCount(batch.processingRows)} · Completed{" "}
                    {formatReportingCount(batch.completedRows)} · Failed{" "}
                    {formatReportingCount(batch.failedRows)}
                  </p>
                  <p class="ct-admin__meta">Updated {formatIsoTimestamp(batch.lastUpdatedAt)}</p>
                  {batch.latestError === null ? null : (
                    <AdminStatus tone="warning">{batch.latestError}</AdminStatus>
                  )}
                </div>
                {retryMarkup}
              </AdminMetricCard>
            );
          })}
        </section>
      )}
    </AdminPanel>
  );

  const learnerRecordImportPanelMarkup = (
    <AdminPanel>
      <h2>Learner record import</h2>
      <p>
        Upload one CSV, choose the default trust classification once, and let CredTrail infer
        matching org-unit and badge-template context when current organization data supports it.
        Pathway labels stay explicit imported metadata.
      </p>
      <div class="ct-admin__workspace-actions">
        <AdminCtaLink href={learnerRecordImportWorkflow.templatePath}>
          Download CSV template
        </AdminCtaLink>
      </div>
      <AdminForm
        method="post"
        encType="multipart/form-data"
        action={learnerRecordImportWorkflow.previewPath}
        className="ct-admin__form ct-stack"
      >
        <AdminField label="Batch default trust level">
          <select name="defaultTrustLevel">
            <option
              value="issuer_verified"
              selected={
                learnerRecordImportWorkflow.defaults.defaultTrustLevel === "issuer_verified"
              }
            >
              issuer verified
            </option>
            <option
              value="learner_supplemental"
              selected={
                learnerRecordImportWorkflow.defaults.defaultTrustLevel === "learner_supplemental"
              }
            >
              learner supplemental
            </option>
          </select>
        </AdminField>
        <AdminField label="Default issuer name">
          <input
            name="defaultIssuerName"
            type="text"
            value={learnerRecordImportWorkflow.defaults.defaultIssuerName}
            placeholder={input.tenant.displayName}
          />
        </AdminField>
        <AdminField label="CSV file">
          <input name="file" type="file" accept=".csv,text/csv" />
        </AdminField>
        <p class="ct-admin__hint">
          Smart defaults only infer from the current org-unit tree and live badge-template
          ownership. Missing context stays explicit instead of being fabricated.
        </p>
        <div class="ct-admin__workspace-actions">
          <AdminButton type="submit">Preview import</AdminButton>
          <AdminButton type="submit" formAction={learnerRecordImportWorkflow.applyPath}>
            Queue import
          </AdminButton>
        </div>
      </AdminForm>
    </AdminPanel>
  );

  const pageTitle =
    view === "home"
      ? `Institution Admin · ${input.tenant.displayName}`
      : view === "operations"
        ? `Operations · Institution Admin · ${input.tenant.displayName}`
        : view === "operationsLearnerRecords"
          ? `Learner Records · Institution Admin · ${input.tenant.displayName}`
          : view === "operationsLearnerRecordImports"
            ? `Learner Record Imports · Institution Admin · ${input.tenant.displayName}`
            : view === "operationsReviewQueue"
              ? `Rule Review Queue · Institution Admin · ${input.tenant.displayName}`
              : view === "operationsIssuedBadges"
                ? `Issued Badges · Institution Admin · ${input.tenant.displayName}`
                : view === "operationsBadgeStatus"
                  ? `Badge Status · Institution Admin · ${input.tenant.displayName}`
                  : view === "reporting"
                    ? `Reporting Highlights · Institution Admin · ${input.tenant.displayName}`
                    : view === "reportingExplore"
                      ? `Reporting Explore · Institution Admin · ${input.tenant.displayName}`
                      : view === "reportingTrends"
                        ? `Trend Detail · Reporting · Institution Admin · ${input.tenant.displayName}`
                        : view === "reportingReports"
                          ? `Report Library · Reporting · Institution Admin · ${input.tenant.displayName}`
                          : view === "rules"
                            ? `Rules · Institution Admin · ${input.tenant.displayName}`
                            : view === "access"
                              ? `Access · Institution Admin · ${input.tenant.displayName}`
                              : view === "accessMembers"
                                ? `Members · Institution Admin · ${input.tenant.displayName}`
                                : view === "accessGovernance"
                                  ? `Governance Delegation · Institution Admin · ${input.tenant.displayName}`
                                  : view === "accessApiKeys"
                                    ? `API Keys · Institution Admin · ${input.tenant.displayName}`
                                    : `Org Units · Institution Admin · ${input.tenant.displayName}`;

  const viewContent = (() => {
    switch (view) {
      case "home":
        return (
          <>
            {renderPageHeader(
              "Institution Admin",
              "Choose a workspace instead of forcing every task onto one page.",
              <aside class="ct-admin-page-header__note">
                <h2>Start Here</h2>
                <p>
                  Operations is the primary daily workspace. Use the Rules and Access pages to
                  configure policy and permissions.
                </p>
              </aside>,
            )}
            <section class="ct-admin ct-stack">{workspaceCardsMarkup}</section>
          </>
        );
      case "operations":
        return (
          <>
            {renderPageHeader(
              "Operations",
              "Issue badges here, then use dedicated pages for learner records, imports, review queue, issued badges, and badge status.",
            )}
            <section class="ct-admin ct-stack">{manualIssuePanelMarkup}</section>
          </>
        );
      case "operationsLearnerRecords":
        return (
          <>
            {renderPageHeader(
              "Learner Records",
              "Review one learner’s unified record without overloading operations with a broader learner-search or ingest surface.",
            )}
            <section class="ct-admin ct-stack">
              {learnerRecordReviewPanelMarkup}
              {renderLearnerRecordReviewSections()}
            </section>
          </>
        );
      case "operationsLearnerRecordImports":
        return (
          <>
            {renderPageHeader(
              "Learner Record Imports",
              "Import learner-record CSVs with one trust default, honest smart defaults, and queue-backed progress.",
            )}
            <section class="ct-admin ct-stack">
              {learnerRecordImportPanelMarkup}
              {learnerRecordImportFeedbackMarkup}
              {learnerRecordImportSubmissionMarkup}
              {learnerRecordImportProgressMarkup}
            </section>
          </>
        );
      case "operationsReviewQueue":
        return (
          <>
            {renderPageHeader(
              "Rule Review Queue",
              "Review pending badge decisions without mixing them into the rest of operations.",
            )}
            <section class="ct-admin ct-stack">{ruleReviewQueuePanelMarkup}</section>
          </>
        );
      case "operationsIssuedBadges":
        return (
          <>
            {renderPageHeader(
              "Issued Badges",
              "Search issued badges and take audit or revocation actions from one page.",
            )}
            <section class="ct-admin ct-stack">{issuedBadgesPanelMarkup}</section>
          </>
        );
      case "operationsBadgeStatus":
        return (
          <>
            {renderPageHeader(
              "Badge Status",
              "Look up a badge, inspect its current state, and apply status changes with a reason.",
            )}
            <section class="ct-admin ct-stack">{badgeStatusPanelMarkup}</section>
          </>
        );
      case "reporting":
        return (
          <>
            {renderPageHeader(
              "Reporting Highlights",
              "Start with smart-default rollups, current-scope drilldowns, and visually curated report modules before opening detailed reporting pages.",
            )}
            <section class="ct-admin ct-stack">
              <section class="ct-admin__reporting-presentation-shell ct-admin__reporting-presentation-shell--highlights ct-stack">
                {reportingPresentationNoteMarkup}
                <section class="ct-admin__reporting-primary-story ct-stack">
                  <section class="ct-admin__reporting-first-screen ct-stack">
                    {reportingExecutiveSummaryMarkup}
                  </section>
                  {reportingJourneyPanelMarkup}
                  <section class="ct-admin__reporting-highlight-grid">
                    {reportingTemplateHighlightsPanelMarkup}
                    {reportingOrgUnitHighlightsPanelMarkup}
                  </section>
                  {reportingDrilldownHighlightsPanelMarkup}
                  {reportingDeepLinksMarkup}
                </section>
              </section>
            </section>
          </>
        );
      case "reportingExplore":
        return (
          <>
            {renderPageHeader(
              "Reporting Explore",
              "Use the full reporting workspace for exact filters, supporting tables, hierarchy drilldowns, and metric definitions.",
            )}
            <section class="ct-admin ct-stack">
              <section class="ct-admin__reporting-presentation-shell ct-stack">
                <section class="ct-admin__reporting-primary-story ct-stack">
                  <section class="ct-admin__reporting-first-screen ct-stack">
                    {reportingExecutiveSummaryMarkup}
                    {reportingOverviewPanelMarkup}
                  </section>
                  {renderReportingTrendPanelMarkup({ includeDetailedTable: false })}
                  <section class="ct-admin__reporting-supporting-grid">
                    {reportingEngagementPanelMarkup}
                  </section>
                </section>
              </section>
              <section class="ct-admin__reporting-secondary-story ct-stack">
                {reportingLowerStoryMarkup}
                {reportingDefinitionsPanelMarkup}
                {reportingDeferredPanelMarkup}
              </section>
            </section>
          </>
        );
      case "reportingTrends":
        return (
          <>
            {renderPageHeader(
              "Trend Detail",
              "Use the focused trend page for exact daily counts behind the overview chart.",
            )}
            <section class="ct-admin ct-stack">
              {reportingTrendFiltersPanelMarkup}
              {renderReportingTrendPanelMarkup({ includeDetailedTable: true })}
            </section>
          </>
        );
      case "reportingReports":
        return (
          <>
            {renderPageHeader(
              "Report Library",
              "Use one focused page for saved report shortcuts, custom report setup, and CSV exports.",
            )}
            <section class="ct-admin ct-stack">
              {reportingReportsLibraryMarkup}
              {reportingExportFiltersPanelMarkup}
              {reportingExportsPanelMarkup}
            </section>
          </>
        );
      case "rules":
        return (
          <>
            {renderPageHeader(
              "Rules",
              "Keep authoring, template maintenance, and governance context together in one focused workspace.",
            )}
            <section class="ct-admin ct-stack">
              <section class="ct-admin__layout ct-grid ct-grid--sidebar">
                <div class="ct-admin__grid ct-stack">
                  {templateImagePanelMarkup}
                  {ruleValueListsPanelMarkup}
                  {evaluateRulePanelMarkup}
                  {ruleGovernancePanelMarkup}
                </div>
                <div class="ct-admin__grid ct-stack">
                  {badgeRulesTableMarkup}
                  {badgeTemplatesTableMarkup}
                </div>
              </section>
            </section>
          </>
        );
      case "access":
        return (
          <>
            {renderPageHeader(
              "Access",
              "Manage members, governance delegation, API keys, and org units from one workspace.",
            )}
            <section class="ct-admin ct-stack">
              {accessOverviewPanelMarkup}
              {enterpriseAuthPanelMarkup}
            </section>
          </>
        );
      case "accessMembers":
        return (
          <>
            {renderPageHeader(
              "Members",
              "Add colleagues, assign tenant roles, resend invites, and remove tenant access.",
              <aside class="ct-admin-page-header__note">
                <h2>Tenant-level access</h2>
                <p>
                  Use owner/admin roles for administration. Use issuer/viewer roles when someone
                  does not need full tenant control.
                </p>
              </aside>,
            )}
            <section class="ct-admin ct-stack">
              {tenantMembersPanelMarkup}
              {tenantMembersTableMarkup}
            </section>
          </>
        );
      case "accessGovernance":
        return (
          <>
            {renderPageHeader(
              "Governance Delegation",
              "Grant org-unit access and time-boxed badge authority with direct removal from the current assignments list.",
              <aside class="ct-admin-page-header__note">
                <h2>Choose The Smallest Access</h2>
                <p>
                  Use scoped roles for standing access. Use delegated authority when someone only
                  needs temporary badge operations.
                </p>
              </aside>,
            )}
            <section class="ct-admin ct-stack">
              {governanceGuidePanelMarkup}
              {membershipScopePanelMarkup}
              {membershipScopeTableMarkup}
              {delegatedGrantPanelMarkup}
              {delegatedGrantTableMarkup}
            </section>
          </>
        );
      case "accessApiKeys":
        return (
          <>
            {renderPageHeader("API Keys", "Create, review, and revoke tenant API keys.")}
            <section class="ct-admin ct-stack">
              {apiKeyPanelMarkup}
              {apiKeysTableMarkup}
            </section>
          </>
        );
      case "accessOrgUnits":
        return (
          <>
            {renderPageHeader("Org Units", "Create and review org structure.")}
            <section class="ct-admin ct-stack">
              {orgUnitPanelMarkup}
              {orgUnitsTableMarkup}
            </section>
          </>
        );
    }
  })();

  return appPage({
    title: pageTitle,
    assets: ["institutionAdminCss", "institutionAdminJs"],
    variant: "admin",
    body: (
      <AdminShell
        sidebar={
          <AdminSidebar
            brandHref={tenantAdminPath}
            sections={sidebarSections}
            footerLinks={sidebarFooterLinks}
          />
        }
        topbar={
          <AdminTopbar
            title={input.tenant.displayName}
            chips={[{ label: input.membershipRole }, { label: input.tenant.planTier }]}
            userLabel={userLabel}
            userTitle={`User ID: ${input.userId}`}
          />
        }
      >
        {viewContent}
        <div id="ct-admin-context" hidden data-context-json={adminPageContextJson}></div>
      </AdminShell>
    ),
  });
};

export const institutionAdminDashboardPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "home");
};

export const institutionAdminOperationsPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "operations");
};

export const institutionAdminLearnerRecordsPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "operationsLearnerRecords");
};

export const institutionAdminLearnerRecordImportsPage = (
  input: InstitutionAdminPageInput,
): AppPage => {
  return renderInstitutionAdminPage(input, "operationsLearnerRecordImports");
};

export const institutionAdminOperationsReviewQueuePage = (
  input: InstitutionAdminPageInput,
): AppPage => {
  return renderInstitutionAdminPage(input, "operationsReviewQueue");
};

export const institutionAdminIssuedBadgesPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "operationsIssuedBadges");
};

export const institutionAdminBadgeStatusPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "operationsBadgeStatus");
};

export const institutionAdminReportingPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "reporting");
};

export const institutionAdminReportingExplorePage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "reportingExplore");
};

export const institutionAdminReportingTrendsPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "reportingTrends");
};

export const institutionAdminReportingReportsPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "reportingReports");
};

export const institutionAdminRulesPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "rules");
};

export const institutionAdminAccessPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "access");
};

export const institutionAdminMembersPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "accessMembers");
};

export const institutionAdminGovernancePage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "accessGovernance");
};

export const institutionAdminApiKeysPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "accessApiKeys");
};

export const institutionAdminOrgUnitsPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "accessOrgUnits");
};
