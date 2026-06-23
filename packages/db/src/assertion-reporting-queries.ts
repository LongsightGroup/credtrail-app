import { listTenantOrgUnits } from "./tenant-org-units";
import type { SqlDatabase, SqlQueryResult } from "./tenant-scope";
import type {
  GetTenantExecutiveRollupInput,
  GetTenantExecutiveRollupResult,
  GetTenantReportingEngagementCountsInput,
  GetTenantReportingOverviewInput,
  GetTenantReportingTrendsInput,
  ListTenantReportingComparisonsInput,
  TenantReportingComparisonRowRecord,
  TenantReportingEngagementCounts,
  TenantReportingOverviewRecord,
  TenantReportingTrendRecord,
} from "./assertion-types.js";
import { normalizeReportingDateBoundary } from "./assertion-internal.js";
import type {
  TenantReportingEngagementRow,
  TenantReportingOverviewRow,
} from "./assertion-internal.js";
import { backfillAssertionReportingAttributionsForTenant } from "./assertion-reporting-attribution.js";
import {
  summarizeTenantReportingComparisonRows,
  summarizeTenantReportingEngagementCounts,
  summarizeTenantReportingOverviewRows,
  summarizeTenantReportingTrendRows,
  summarizeTenantExecutiveRollup,
} from "./assertion-reporting-summaries.js";

export const listTenantReportingEngagementRows = async (
  db: SqlDatabase,
  input: GetTenantReportingEngagementCountsInput,
): Promise<TenantReportingEngagementRow[]> => {
  await backfillAssertionReportingAttributionsForTenant(db, input.tenantId);

  const whereClauses = ["assertions.tenant_id = ?"];
  const params: unknown[] = [input.tenantId];

  if (input.from !== undefined) {
    whereClauses.push("assertions.issued_at >= ?");
    params.push(normalizeReportingDateBoundary(input.from, "start"));
  }

  if (input.to !== undefined) {
    whereClauses.push("assertions.issued_at <= ?");
    params.push(normalizeReportingDateBoundary(input.to, "end"));
  }

  if (input.badgeTemplateId !== undefined) {
    whereClauses.push("attribution.badge_template_id = ?");
    params.push(input.badgeTemplateId);
  }

  if (input.orgUnitId !== undefined) {
    whereClauses.push("attribution.org_unit_id = ?");
    params.push(input.orgUnitId);
  }

  const listStatement = (): Promise<SqlQueryResult<TenantReportingEngagementRow>> =>
    db
      .prepare(
        `
        SELECT
          assertions.id AS assertionId,
          attribution.badge_template_id AS badgeTemplateId,
          attribution.org_unit_id AS orgUnitId,
          assertions.issued_at AS issuedAt,
          assertions.revoked_at AS revokedAt,
          lifecycle.to_state AS latestToState,
          lifecycle.reason_code AS latestReasonCode,
          events.event_type AS eventType,
          events.occurred_at AS occurredAt
        FROM assertions
        INNER JOIN assertion_reporting_attributions attribution
          ON attribution.assertion_id = assertions.id
        LEFT JOIN assertion_lifecycle_events lifecycle
          ON lifecycle.id = (
            SELECT ale.id
            FROM assertion_lifecycle_events ale
            WHERE ale.tenant_id = assertions.tenant_id
              AND ale.assertion_id = assertions.id
            ORDER BY ale.transitioned_at DESC, ale.created_at DESC, ale.id DESC
            LIMIT 1
          )
        LEFT JOIN assertion_engagement_events events
          ON events.tenant_id = assertions.tenant_id
          AND events.assertion_id = assertions.id
        WHERE ${whereClauses.join("\n          AND ")}
        ORDER BY assertions.issued_at ASC, assertions.id ASC, events.occurred_at ASC, events.id ASC
      `,
      )
      .bind(...params)
      .all<TenantReportingEngagementRow>();

  return (await listStatement()).results;
};

export const getTenantReportingEngagementCounts = async (
  db: SqlDatabase,
  input: GetTenantReportingEngagementCountsInput,
): Promise<TenantReportingEngagementCounts> => {
  const rows = await listTenantReportingEngagementRows(db, input);
  return summarizeTenantReportingEngagementCounts(rows, input);
};

export const getTenantReportingTrends = async (
  db: SqlDatabase,
  input: GetTenantReportingTrendsInput,
): Promise<TenantReportingTrendRecord> => {
  const rows = await listTenantReportingEngagementRows(db, input);

  return {
    tenantId: input.tenantId,
    filters: {
      from: input.from ?? null,
      to: input.to ?? null,
      badgeTemplateId: input.badgeTemplateId ?? null,
      orgUnitId: input.orgUnitId ?? null,
      state: input.state ?? null,
    },
    bucket: input.bucket,
    series: summarizeTenantReportingTrendRows(rows, input),
    generatedAt: new Date().toISOString(),
  };
};

export const listTenantReportingComparisons = async (
  db: SqlDatabase,
  input: ListTenantReportingComparisonsInput,
): Promise<TenantReportingComparisonRowRecord[]> => {
  const rows = await listTenantReportingEngagementRows(db, input);
  return summarizeTenantReportingComparisonRows(rows, input);
};

export const getTenantExecutiveRollup = async (
  db: SqlDatabase,
  input: GetTenantExecutiveRollupInput,
): Promise<GetTenantExecutiveRollupResult> => {
  const [rows, orgUnits] = await Promise.all([
    listTenantReportingEngagementRows(db, {
      tenantId: input.tenantId,
      from: input.from,
      to: input.to,
      badgeTemplateId: input.badgeTemplateId,
      orgUnitId: input.orgUnitId,
      state: input.state,
    }),
    listTenantOrgUnits(db, {
      tenantId: input.tenantId,
      includeInactive: true,
    }),
  ]);

  return {
    tenantId: input.tenantId,
    ...summarizeTenantExecutiveRollup({
      rows,
      orgUnits: orgUnits.map((orgUnit) => {
        return {
          id: orgUnit.id,
          unitType: orgUnit.unitType,
          displayName: orgUnit.displayName,
          parentOrgUnitId: orgUnit.parentOrgUnitId,
        };
      }),
      query: {
        from: input.from,
        to: input.to,
        badgeTemplateId: input.badgeTemplateId,
        orgUnitId: input.orgUnitId,
        state: input.state,
        focusOrgUnitId: input.focusOrgUnitId,
        comparisonLevel: input.comparisonLevel,
      },
      scopedRootOrgUnitIds: input.scopedRootOrgUnitIds,
    }),
    generatedAt: new Date().toISOString(),
  };
};

export const getTenantReportingOverview = async (
  db: SqlDatabase,
  input: GetTenantReportingOverviewInput,
): Promise<TenantReportingOverviewRecord> => {
  await backfillAssertionReportingAttributionsForTenant(db, input.tenantId);

  const whereClauses = ["assertions.tenant_id = ?"];
  const params: unknown[] = [input.tenantId];

  if (input.issuedFrom !== undefined) {
    whereClauses.push("assertions.issued_at >= ?");
    params.push(normalizeReportingDateBoundary(input.issuedFrom, "start"));
  }

  if (input.issuedTo !== undefined) {
    whereClauses.push("assertions.issued_at <= ?");
    params.push(normalizeReportingDateBoundary(input.issuedTo, "end"));
  }

  if (input.badgeTemplateId !== undefined) {
    whereClauses.push("assertions.badge_template_id = ?");
    params.push(input.badgeTemplateId);
  }

  if (input.orgUnitId !== undefined) {
    whereClauses.push("attribution.org_unit_id = ?");
    params.push(input.orgUnitId);
  }

  const overviewStatement = (): Promise<SqlQueryResult<TenantReportingOverviewRow>> =>
    db
      .prepare(
        `
        SELECT
          assertions.id AS assertionId,
          assertions.issued_at AS issuedAt,
          assertions.badge_template_id AS badgeTemplateId,
          attribution.org_unit_id AS orgUnitId,
          assertions.revoked_at AS revokedAt,
          lifecycle.to_state AS latestToState,
          lifecycle.reason_code AS latestReasonCode
        FROM assertions
        INNER JOIN assertion_reporting_attributions attribution
          ON attribution.assertion_id = assertions.id
        LEFT JOIN assertion_lifecycle_events lifecycle
          ON lifecycle.id = (
            SELECT ale.id
            FROM assertion_lifecycle_events ale
            WHERE ale.tenant_id = assertions.tenant_id
              AND ale.assertion_id = assertions.id
            ORDER BY ale.transitioned_at DESC, ale.created_at DESC, ale.id DESC
            LIMIT 1
          )
        WHERE ${whereClauses.join("\n          AND ")}
        ORDER BY assertions.issued_at DESC, assertions.id DESC
      `,
      )
      .bind(...params)
      .all<TenantReportingOverviewRow>();

  const rows = (await overviewStatement()).results;

  const engagementCounts = await getTenantReportingEngagementCounts(db, {
    tenantId: input.tenantId,
    from: input.issuedFrom,
    to: input.issuedTo,
    badgeTemplateId: input.badgeTemplateId,
    orgUnitId: input.orgUnitId,
    state: input.state,
  });

  return {
    tenantId: input.tenantId,
    filters: {
      issuedFrom: input.issuedFrom ?? null,
      issuedTo: input.issuedTo ?? null,
      badgeTemplateId: input.badgeTemplateId ?? null,
      orgUnitId: input.orgUnitId ?? null,
      state: input.state ?? null,
    },
    counts: {
      ...summarizeTenantReportingOverviewRows(rows, input.state),
      claimRate: engagementCounts.claimRate,
      shareRate: engagementCounts.shareRate,
    },
    generatedAt: new Date().toISOString(),
  };
};
