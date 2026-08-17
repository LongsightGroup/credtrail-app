import { listTenantOrgUnits } from "./tenant-org-units";
import type { SqlDatabase, SqlQueryResult } from "./tenant-scope";
import type {
  GetTenantExecutiveRollupInput,
  GetTenantExecutiveRollupResult,
  GetTenantReportingEngagementCountsInput,
  GetTenantReportingOverviewInput,
  GetTenantReportingTrendsInput,
  ListTenantReportingComparisonsInput,
  TenantReportingComparisonGroupBy,
  TenantReportingComparisonRowRecord,
  TenantReportingEngagementCounts,
  TenantReportingLifecycleFilter,
  TenantReportingOverviewRecord,
  TenantReportingTrendBucketRecord,
  TenantReportingTrendRecord,
} from "./assertion-types.js";
import { normalizeReportingDateBoundary } from "./assertion-internal.js";
import { buildAssertionRecordFilterSql } from "./assertion-record-filter-sql.js";
import { summarizeTenantExecutiveRollup } from "./assertion-reporting-summaries.js";

type SqlCount = number | string;

interface ReportingAggregateRow {
  issuedCount: SqlCount;
  activeCount: SqlCount;
  suspendedCount: SqlCount;
  revokedCount: SqlCount;
  pendingReviewCount: SqlCount;
  publicBadgeViewCount: SqlCount;
  verificationViewCount: SqlCount;
  shareClickCount: SqlCount;
  learnerClaimCount: SqlCount;
  walletAcceptCount: SqlCount;
  shareEngagedCount: SqlCount;
  claimEngagedCount: SqlCount;
}

interface ReportingComparisonAggregateRow extends ReportingAggregateRow {
  groupId: string;
}

interface ReportingEngagementAggregate {
  readonly issuedCount: number;
  readonly publicBadgeViewCount: number;
  readonly verificationViewCount: number;
  readonly shareClickCount: number;
  readonly learnerClaimCount: number;
  readonly walletAcceptCount: number;
  readonly shareEngagedCount: number;
  readonly claimEngagedCount: number;
}

interface ReportingComparisonAggregate extends ReportingEngagementAggregate {
  readonly groupBy: TenantReportingComparisonGroupBy;
  readonly groupId: string;
}

interface ReportingTrendAggregateRow {
  bucketStart: string;
  issuedCount: SqlCount;
  publicBadgeViewCount: SqlCount;
  verificationViewCount: SqlCount;
  shareClickCount: SqlCount;
  learnerClaimCount: SqlCount;
  walletAcceptCount: SqlCount;
}

interface ReportingFilterInput {
  readonly tenantId: string;
  readonly from?: string | undefined;
  readonly to?: string | undefined;
  readonly badgeTemplateId?: string | undefined;
  readonly orgUnitId?: string | undefined;
  readonly state?: TenantReportingLifecycleFilter | undefined;
}

const EFFECTIVE_LIFECYCLE_STATE_SQL = `
          CASE
            WHEN assertions.revoked_at IS NOT NULL THEN 'revoked'
            WHEN lifecycle.to_state IS NOT NULL THEN lifecycle.to_state
            ELSE 'active'
          END`;

const LATEST_LIFECYCLE_JOIN_SQL = `
        LEFT JOIN assertion_lifecycle_events lifecycle
          ON lifecycle.id = (
            SELECT latest_event.id
            FROM assertion_lifecycle_events latest_event
            WHERE latest_event.tenant_id = assertions.tenant_id
              AND latest_event.assertion_id = assertions.id
            ORDER BY
              latest_event.transitioned_at DESC,
              latest_event.created_at DESC,
              latest_event.id DESC
            LIMIT 1
          )`;

const REPORTING_AGGREGATE_SELECT_SQL = `
          COUNT(DISTINCT filtered_assertions.assertion_id) AS issuedCount,
          COUNT(DISTINCT filtered_assertions.assertion_id)
            FILTER (WHERE filtered_assertions.lifecycle_state = 'active') AS activeCount,
          COUNT(DISTINCT filtered_assertions.assertion_id)
            FILTER (WHERE filtered_assertions.lifecycle_state = 'suspended') AS suspendedCount,
          COUNT(DISTINCT filtered_assertions.assertion_id)
            FILTER (WHERE filtered_assertions.lifecycle_state = 'revoked') AS revokedCount,
          COUNT(DISTINCT filtered_assertions.assertion_id)
            FILTER (
              WHERE filtered_assertions.lifecycle_state = 'suspended'
                AND filtered_assertions.latest_reason_code = 'appeal_pending'
            ) AS pendingReviewCount,
          COUNT(events.id) FILTER (WHERE events.event_type = 'public_badge_view')
            AS publicBadgeViewCount,
          COUNT(events.id) FILTER (WHERE events.event_type = 'verification_view')
            AS verificationViewCount,
          COUNT(events.id) FILTER (WHERE events.event_type = 'share_click') AS shareClickCount,
          COUNT(events.id) FILTER (WHERE events.event_type = 'learner_claim')
            AS learnerClaimCount,
          COUNT(events.id) FILTER (WHERE events.event_type = 'wallet_accept')
            AS walletAcceptCount,
          COUNT(DISTINCT filtered_assertions.assertion_id)
            FILTER (WHERE events.event_type = 'share_click') AS shareEngagedCount,
          COUNT(DISTINCT filtered_assertions.assertion_id)
            FILTER (WHERE events.event_type IN ('learner_claim', 'wallet_accept'))
            AS claimEngagedCount`;

const parseSqlCount = (value: SqlCount, fieldName: string): number => {
  const parsed = typeof value === "number" ? value : Number(value);

  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`Reporting query returned an invalid ${fieldName}`);
  }

  return parsed;
};

const buildFilteredAssertionsCte = (
  input: ReportingFilterInput,
): { readonly sql: string; readonly params: readonly unknown[] } => {
  const { whereClauses, params } = buildAssertionRecordFilterSql(
    {
      tenantId: input.tenantId,
      issuedFrom: input.from,
      issuedTo: input.to,
      badgeTemplateId: input.badgeTemplateId,
      orgUnitId: input.orgUnitId,
    },
    {
      context: "reporting",
      includeLifecycleStatePredicate: false,
    },
  );

  if (input.state === "pending_review") {
    whereClauses.push(
      `${EFFECTIVE_LIFECYCLE_STATE_SQL} = 'suspended' AND lifecycle.reason_code = 'appeal_pending'`,
    );
  } else if (input.state !== undefined) {
    whereClauses.push(`${EFFECTIVE_LIFECYCLE_STATE_SQL} = ?`);
    params.push(input.state);
  }

  return {
    sql: `
      WITH filtered_assertions AS (
        SELECT
          assertions.id AS assertion_id,
          attribution.badge_template_id AS badge_template_id,
          attribution.org_unit_id AS org_unit_id,
          assertions.issued_at AS issued_at,
          ${EFFECTIVE_LIFECYCLE_STATE_SQL} AS lifecycle_state,
          lifecycle.reason_code AS latest_reason_code
        FROM assertions
        INNER JOIN assertion_reporting_attributions attribution
          ON attribution.assertion_id = assertions.id
        ${LATEST_LIFECYCLE_JOIN_SQL}
        WHERE ${whereClauses.join("\n          AND ")}
      )`,
    params,
  };
};

const buildEngagementEventJoin = (input: Pick<ReportingFilterInput, "from" | "to">): string => {
  const joinClauses = [
    "events.tenant_id = ?",
    "events.assertion_id = filtered_assertions.assertion_id",
  ];
  if (input.from !== undefined) {
    joinClauses.push("events.occurred_at >= ?");
  }

  if (input.to !== undefined) {
    joinClauses.push("events.occurred_at <= ?");
  }

  return `
        LEFT JOIN assertion_engagement_events events
          ON ${joinClauses.join("\n          AND ")}`;
};

const engagementEventParams = (input: ReportingFilterInput): readonly unknown[] => {
  const params: unknown[] = [input.tenantId];

  if (input.from !== undefined) {
    params.push(normalizeReportingDateBoundary(input.from, "start"));
  }

  if (input.to !== undefined) {
    params.push(normalizeReportingDateBoundary(input.to, "end"));
  }

  return params;
};

const loadReportingAggregate = async (
  db: SqlDatabase,
  input: ReportingFilterInput,
): Promise<ReportingAggregateRow> => {
  const filteredAssertions = buildFilteredAssertionsCte(input);
  const eventJoin = buildEngagementEventJoin(input);
  const row = await db
    .prepare(
      `${filteredAssertions.sql}
        SELECT
          ${REPORTING_AGGREGATE_SELECT_SQL}
        FROM filtered_assertions
        ${eventJoin}
      `,
    )
    .bind(...filteredAssertions.params, ...engagementEventParams(input))
    .first<ReportingAggregateRow>();

  if (row === null) {
    throw new Error("Reporting aggregate query returned no row");
  }

  return row;
};

const parseReportingEngagementAggregate = (
  row: ReportingAggregateRow,
): ReportingEngagementAggregate => ({
  issuedCount: parseSqlCount(row.issuedCount, "issued count"),
  publicBadgeViewCount: parseSqlCount(row.publicBadgeViewCount, "public badge view count"),
  verificationViewCount: parseSqlCount(row.verificationViewCount, "verification view count"),
  shareClickCount: parseSqlCount(row.shareClickCount, "share click count"),
  learnerClaimCount: parseSqlCount(row.learnerClaimCount, "learner claim count"),
  walletAcceptCount: parseSqlCount(row.walletAcceptCount, "wallet accept count"),
  shareEngagedCount: parseSqlCount(row.shareEngagedCount, "share engaged count"),
  claimEngagedCount: parseSqlCount(row.claimEngagedCount, "claim engaged count"),
});

const engagementCountsFromAggregate = (
  aggregate: ReportingEngagementAggregate,
): TenantReportingEngagementCounts => {
  const { issuedCount } = aggregate;

  return {
    issuedCount,
    publicBadgeViewCount: aggregate.publicBadgeViewCount,
    verificationViewCount: aggregate.verificationViewCount,
    shareClickCount: aggregate.shareClickCount,
    learnerClaimCount: aggregate.learnerClaimCount,
    walletAcceptCount: aggregate.walletAcceptCount,
    claimRate: issuedCount === 0 ? 0 : aggregate.claimEngagedCount / issuedCount,
    shareRate: issuedCount === 0 ? 0 : aggregate.shareEngagedCount / issuedCount,
  };
};

/** Returns tenant engagement totals without materializing assertion-event rows. */
export const getTenantReportingEngagementCounts = async (
  db: SqlDatabase,
  input: GetTenantReportingEngagementCountsInput,
): Promise<TenantReportingEngagementCounts> => {
  const row = await loadReportingAggregate(db, input);
  return engagementCountsFromAggregate(parseReportingEngagementAggregate(row));
};

/** Returns daily reporting aggregates, including empty buckets inside an explicit range. */
export const getTenantReportingTrends = async (
  db: SqlDatabase,
  input: GetTenantReportingTrendsInput,
): Promise<TenantReportingTrendRecord> => {
  if (input.bucket !== "day") {
    throw new Error("Unsupported reporting trend bucket");
  }

  const filteredAssertions = buildFilteredAssertionsCte(input);
  const activityEventJoin = buildEngagementEventJoin(input);
  const aggregateEventJoin = buildEngagementEventJoin(input);
  const requestedFrom =
    input.from === undefined
      ? null
      : normalizeReportingDateBoundary(input.from, "start").slice(0, 10);
  const requestedTo =
    input.to === undefined ? null : normalizeReportingDateBoundary(input.to, "end").slice(0, 10);
  const eventParams = engagementEventParams(input);
  const result = await db
    .prepare(
      `${filteredAssertions.sql},
      activity_dates AS (
        SELECT
          (filtered_assertions.issued_at::timestamptz AT TIME ZONE 'UTC')::date AS activity_date
        FROM filtered_assertions
        UNION ALL
        SELECT (events.occurred_at::timestamptz AT TIME ZONE 'UTC')::date AS activity_date
        FROM filtered_assertions
        ${activityEventJoin}
        WHERE events.id IS NOT NULL
      ),
      requested_range AS (
        SELECT CAST(? AS date) AS requested_from, CAST(? AS date) AS requested_to
      ),
      range_bounds AS (
        SELECT
          COALESCE(requested_range.requested_from, MIN(activity_dates.activity_date), requested_range.requested_to)
            AS range_start,
          COALESCE(requested_range.requested_to, MAX(activity_dates.activity_date), requested_range.requested_from)
            AS range_end
        FROM requested_range
        LEFT JOIN activity_dates ON TRUE
        GROUP BY requested_range.requested_from, requested_range.requested_to
      ),
      buckets AS (
        SELECT GENERATE_SERIES(range_start, range_end, INTERVAL '1 day')::date AS bucket_start
        FROM range_bounds
        WHERE range_start IS NOT NULL
          AND range_end IS NOT NULL
          AND range_start <= range_end
      ),
      issued_counts AS (
        SELECT
          (filtered_assertions.issued_at::timestamptz AT TIME ZONE 'UTC')::date AS bucket_start,
          COUNT(DISTINCT filtered_assertions.assertion_id) AS issued_count
        FROM filtered_assertions
        GROUP BY
          (filtered_assertions.issued_at::timestamptz AT TIME ZONE 'UTC')::date
      ),
      event_counts AS (
        SELECT
          (events.occurred_at::timestamptz AT TIME ZONE 'UTC')::date AS bucket_start,
          COUNT(events.id) FILTER (WHERE events.event_type = 'public_badge_view')
            AS public_badge_view_count,
          COUNT(events.id) FILTER (WHERE events.event_type = 'verification_view')
            AS verification_view_count,
          COUNT(events.id) FILTER (WHERE events.event_type = 'share_click') AS share_click_count,
          COUNT(events.id) FILTER (WHERE events.event_type = 'learner_claim')
            AS learner_claim_count,
          COUNT(events.id) FILTER (WHERE events.event_type = 'wallet_accept')
            AS wallet_accept_count
        FROM filtered_assertions
        ${aggregateEventJoin}
        WHERE events.id IS NOT NULL
        GROUP BY (events.occurred_at::timestamptz AT TIME ZONE 'UTC')::date
      )
      SELECT
        TO_CHAR(buckets.bucket_start, 'YYYY-MM-DD') AS bucketStart,
        COALESCE(issued_counts.issued_count, 0) AS issuedCount,
        COALESCE(event_counts.public_badge_view_count, 0) AS publicBadgeViewCount,
        COALESCE(event_counts.verification_view_count, 0) AS verificationViewCount,
        COALESCE(event_counts.share_click_count, 0) AS shareClickCount,
        COALESCE(event_counts.learner_claim_count, 0) AS learnerClaimCount,
        COALESCE(event_counts.wallet_accept_count, 0) AS walletAcceptCount
      FROM buckets
      LEFT JOIN issued_counts ON issued_counts.bucket_start = buckets.bucket_start
      LEFT JOIN event_counts ON event_counts.bucket_start = buckets.bucket_start
      ORDER BY buckets.bucket_start ASC
      `,
    )
    .bind(...filteredAssertions.params, ...eventParams, requestedFrom, requestedTo, ...eventParams)
    .all<ReportingTrendAggregateRow>();

  const series: TenantReportingTrendBucketRecord[] = result.results.map((row) => ({
    bucketStart: row.bucketStart,
    issuedCount: parseSqlCount(row.issuedCount, "trend issued count"),
    publicBadgeViewCount: parseSqlCount(row.publicBadgeViewCount, "trend public badge view count"),
    verificationViewCount: parseSqlCount(
      row.verificationViewCount,
      "trend verification view count",
    ),
    shareClickCount: parseSqlCount(row.shareClickCount, "trend share click count"),
    learnerClaimCount: parseSqlCount(row.learnerClaimCount, "trend learner claim count"),
    walletAcceptCount: parseSqlCount(row.walletAcceptCount, "trend wallet accept count"),
  }));

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
    series,
    generatedAt: new Date().toISOString(),
  };
};

const loadTenantReportingComparisonAggregates = async (
  db: SqlDatabase,
  input: ListTenantReportingComparisonsInput,
): Promise<ReportingComparisonAggregate[]> => {
  const filteredAssertions = buildFilteredAssertionsCte(input);
  const eventJoin = buildEngagementEventJoin(input);
  const groupColumn = input.groupBy === "badgeTemplate" ? "badge_template_id" : "org_unit_id";
  const result: SqlQueryResult<ReportingComparisonAggregateRow> = await db
    .prepare(
      `${filteredAssertions.sql}
        SELECT
          filtered_assertions.${groupColumn} AS groupId,
          ${REPORTING_AGGREGATE_SELECT_SQL}
        FROM filtered_assertions
        ${eventJoin}
        GROUP BY filtered_assertions.${groupColumn}
        ORDER BY
          COUNT(DISTINCT filtered_assertions.assertion_id) DESC,
          filtered_assertions.${groupColumn} ASC
      `,
    )
    .bind(...filteredAssertions.params, ...engagementEventParams(input))
    .all<ReportingComparisonAggregateRow>();

  return result.results.map((row) => {
    return {
      groupBy: input.groupBy,
      groupId: row.groupId,
      ...parseReportingEngagementAggregate(row),
    };
  });
};

/** Returns one bounded aggregate row per badge template or organization unit. */
export const listTenantReportingComparisons = async (
  db: SqlDatabase,
  input: ListTenantReportingComparisonsInput,
): Promise<TenantReportingComparisonRowRecord[]> => {
  const aggregates = await loadTenantReportingComparisonAggregates(db, input);

  return aggregates.map((aggregate) => ({
    groupBy: aggregate.groupBy,
    groupId: aggregate.groupId,
    issuedCount: aggregate.issuedCount,
    publicBadgeViewCount: aggregate.publicBadgeViewCount,
    verificationViewCount: aggregate.verificationViewCount,
    shareClickCount: aggregate.shareClickCount,
    learnerClaimCount: aggregate.learnerClaimCount,
    walletAcceptCount: aggregate.walletAcceptCount,
    claimRate:
      aggregate.issuedCount === 0 ? 0 : aggregate.claimEngagedCount / aggregate.issuedCount,
    shareRate:
      aggregate.issuedCount === 0 ? 0 : aggregate.shareEngagedCount / aggregate.issuedCount,
  }));
};

/** Returns an executive rollup from bounded per-org-unit database aggregates. */
export const getTenantExecutiveRollup = async (
  db: SqlDatabase,
  input: GetTenantExecutiveRollupInput,
): Promise<GetTenantExecutiveRollupResult> => {
  const [comparisonRows, orgUnits] = await Promise.all([
    loadTenantReportingComparisonAggregates(db, {
      tenantId: input.tenantId,
      from: input.from,
      to: input.to,
      badgeTemplateId: input.badgeTemplateId,
      orgUnitId: input.orgUnitId,
      state: input.state,
      groupBy: "orgUnit",
    }),
    listTenantOrgUnits(db, {
      tenantId: input.tenantId,
      includeInactive: true,
    }),
  ]);

  return {
    tenantId: input.tenantId,
    ...summarizeTenantExecutiveRollup({
      comparisonRows,
      orgUnits: orgUnits.map((orgUnit) => ({
        id: orgUnit.id,
        unitType: orgUnit.unitType,
        displayName: orgUnit.displayName,
        parentOrgUnitId: orgUnit.parentOrgUnitId,
      })),
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

/** Returns lifecycle and engagement overview aggregates for one tenant. */
export const getTenantReportingOverview = async (
  db: SqlDatabase,
  input: GetTenantReportingOverviewInput,
): Promise<TenantReportingOverviewRecord> => {
  const aggregate = await loadReportingAggregate(db, {
    tenantId: input.tenantId,
    from: input.issuedFrom,
    to: input.issuedTo,
    badgeTemplateId: input.badgeTemplateId,
    orgUnitId: input.orgUnitId,
    state: input.state,
  });
  const engagement = engagementCountsFromAggregate(parseReportingEngagementAggregate(aggregate));

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
      issued: engagement.issuedCount,
      active: parseSqlCount(aggregate.activeCount, "active count"),
      suspended: parseSqlCount(aggregate.suspendedCount, "suspended count"),
      revoked: parseSqlCount(aggregate.revokedCount, "revoked count"),
      pendingReview: parseSqlCount(aggregate.pendingReviewCount, "pending review count"),
      claimRate: engagement.claimRate,
      shareRate: engagement.shareRate,
    },
    generatedAt: new Date().toISOString(),
  };
};
