import { buildScopedDescendantsCte } from "./tenant-org-unit-hierarchy-sql.js";
import type { SqlDatabase } from "./tenant-scope";
import {
  badgeIssuanceRuleSelectColumns,
  mapBadgeIssuanceRuleRow,
  type BadgeIssuanceRuleRow,
} from "./badge-issuance-rule-reads.js";
import type {
  BadgeIssuanceRuleRegistryCursor,
  BadgeIssuanceRuleRegistryPage,
  BadgeIssuanceRuleRegistrySort,
  ListBadgeIssuanceRuleRegistryPageInput,
} from "./badge-issuance-rule-types.js";

interface BadgeIssuanceRuleRegistryRow extends BadgeIssuanceRuleRow {
  registrySortValue: string | number;
}

interface RegistryScopeSql {
  readonly cte: string;
  readonly where: string;
  readonly beforeTenantParams: readonly string[];
  readonly afterTenantParams: readonly string[];
  readonly empty: boolean;
}

const registryScopeSql = (input: ListBadgeIssuanceRuleRegistryPageInput): RegistryScopeSql => {
  if (input.scope?.type === "org_unit") {
    return {
      cte: "",
      where: "AND rules.org_unit_id = ?",
      beforeTenantParams: [],
      afterTenantParams: [input.scope.orgUnitId],
      empty: false,
    };
  }

  if (input.scope?.type === "descendants") {
    if (input.scope.rootOrgUnitIds.length === 0) {
      return {
        cte: "",
        where: "",
        beforeTenantParams: [],
        afterTenantParams: [],
        empty: true,
      };
    }

    const rootValues = input.scope.rootOrgUnitIds.map(() => "(?)").join(", ");
    return {
      cte: buildScopedDescendantsCte(rootValues),
      where: `AND rules.org_unit_id IN (
        SELECT orgUnitId
        FROM scoped_descendants
      )`,
      beforeTenantParams: [...input.scope.rootOrgUnitIds, input.tenantId, input.tenantId],
      afterTenantParams: [],
      empty: false,
    };
  }

  return {
    cte: "",
    where: "",
    beforeTenantParams: [],
    afterTenantParams: [],
    empty: false,
  };
};

const registrySortExpression = (sort: BadgeIssuanceRuleRegistrySort): string => {
  switch (sort) {
    case "rule":
      return "LOWER(COALESCE(active_version.snapshot_name, latest_version.snapshot_name, rules.name))";
    case "badge":
      return "LOWER(COALESCE(active_version.snapshot_badge_template_title, latest_version.snapshot_badge_template_title, ''))";
    case "lms":
      return "COALESCE(active_version.snapshot_lms_provider_kind, latest_version.snapshot_lms_provider_kind, rules.lms_provider_kind)";
    case "current_version":
      return "COALESCE(active_version.version_number, 0)";
    case "latest_version":
      return "COALESCE(latest_version.version_number, 0)";
    case "updated":
      return "COALESCE(active_version.updated_at, latest_version.updated_at, rules.updated_at)";
  }
};

const registrySourceSql = (input: {
  readonly scope: RegistryScopeSql;
  readonly search: boolean;
  readonly latestStatus: boolean;
}): string => {
  return `
    FROM badge_issuance_rules AS rules
    LEFT JOIN LATERAL (
      SELECT
        versions.id,
        versions.version_number,
        versions.status,
        versions.snapshot_name,
        versions.snapshot_badge_template_title,
        versions.snapshot_lms_provider_kind,
        versions.updated_at
      FROM badge_issuance_rule_versions AS versions
      WHERE versions.tenant_id = rules.tenant_id
        AND versions.rule_id = rules.id
      ORDER BY versions.version_number DESC
      LIMIT 1
    ) AS latest_version ON TRUE
    LEFT JOIN badge_issuance_rule_versions AS active_version
      ON active_version.tenant_id = rules.tenant_id
      AND active_version.rule_id = rules.id
      AND active_version.id = rules.active_version_id
    WHERE rules.tenant_id = ?
      ${input.scope.where}
      ${
        input.search
          ? `AND POSITION(LOWER(?) IN LOWER(CONCAT_WS(
              ' ',
              COALESCE(active_version.snapshot_name, latest_version.snapshot_name, rules.name),
              COALESCE(active_version.snapshot_badge_template_title, latest_version.snapshot_badge_template_title, ''),
              COALESCE(active_version.snapshot_lms_provider_kind, latest_version.snapshot_lms_provider_kind, rules.lms_provider_kind),
              rules.id
            ))) > 0`
          : ""
      }
      ${input.latestStatus ? "AND latest_version.status = ?" : ""}
  `;
};

const registryFilterParams = (
  input: ListBadgeIssuanceRuleRegistryPageInput,
  scope: RegistryScopeSql,
): readonly unknown[] => {
  return [
    ...scope.beforeTenantParams,
    input.tenantId,
    ...scope.afterTenantParams,
    ...(input.searchQuery.length === 0 ? [] : [input.searchQuery]),
    ...(input.latestStatus === undefined ? [] : [input.latestStatus]),
  ];
};

const isNumberRegistrySort = (sort: BadgeIssuanceRuleRegistrySort): boolean => {
  return sort === "current_version" || sort === "latest_version";
};

const normalizeRegistryCursorValue = (
  sort: BadgeIssuanceRuleRegistrySort,
  value: string | number,
): string | number => {
  if (!isNumberRegistrySort(sort)) {
    return String(value);
  }

  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error(`Invalid numeric badge rule registry cursor for sort "${sort}"`);
  }

  return parsed;
};

const registryCursorFromRow = (
  row: BadgeIssuanceRuleRegistryRow,
  sort: BadgeIssuanceRuleRegistrySort,
): BadgeIssuanceRuleRegistryCursor => {
  return {
    value: normalizeRegistryCursorValue(sort, row.registrySortValue),
    ruleId: row.id,
  };
};

/** Lists one stable keyset-paginated page of tenant-scoped governed badge rules. */
export const listBadgeIssuanceRuleRegistryPage = async (
  db: SqlDatabase,
  input: ListBadgeIssuanceRuleRegistryPageInput,
): Promise<BadgeIssuanceRuleRegistryPage> => {
  if (!Number.isInteger(input.limit) || input.limit < 1 || input.limit > 100) {
    throw new Error("Badge rule registry page limit must be between 1 and 100");
  }

  const scope = registryScopeSql(input);
  if (scope.empty) {
    return { rules: [], totalCount: 0, previousCursor: null, nextCursor: null };
  }

  const sourceSql = registrySourceSql({
    scope,
    search: input.searchQuery.length > 0,
    latestStatus: input.latestStatus !== undefined,
  });
  const filterParams = registryFilterParams(input, scope);
  const countNeedsVersionJoins = input.searchQuery.length > 0 || input.latestStatus !== undefined;
  const countSourceSql = countNeedsVersionJoins
    ? sourceSql
    : `
        FROM badge_issuance_rules AS rules
        WHERE rules.tenant_id = ?
          ${scope.where}
      `;
  const countParams = countNeedsVersionJoins
    ? filterParams
    : [...scope.beforeTenantParams, input.tenantId, ...scope.afterTenantParams];
  const countRow = await db
    .prepare(`${scope.cte} SELECT COUNT(*) AS totalCount ${countSourceSql}`)
    .bind(...countParams)
    .first<{ totalCount: number | string }>();
  const totalCount = Number(countRow?.totalCount ?? 0);
  const sortExpression = registrySortExpression(input.sort);
  const isBefore = input.cursor?.position === "before";
  const queryDirection = isBefore
    ? input.direction === "asc"
      ? "DESC"
      : "ASC"
    : input.direction.toUpperCase();
  const cursorOperator = input.cursor === undefined ? null : isBefore ? ">" : "<";
  const normalizedOperator =
    cursorOperator === null || input.direction === "desc"
      ? cursorOperator
      : cursorOperator === ">"
        ? "<"
        : ">";
  const cursorSql =
    input.cursor === undefined
      ? ""
      : `AND (
          ${sortExpression} ${normalizedOperator} ?
          OR (${sortExpression} = ? AND rules.id ${normalizedOperator} ?)
        )`;
  const cursorValue =
    input.cursor === undefined
      ? null
      : normalizeRegistryCursorValue(input.sort, input.cursor.boundary.value);
  const cursorParams =
    input.cursor === undefined ? [] : [cursorValue, cursorValue, input.cursor.boundary.ruleId];
  const result = await db
    .prepare(
      `
        ${scope.cte}
        SELECT
          ${badgeIssuanceRuleSelectColumns("rules")},
          ${sortExpression} AS registrySortValue
        ${sourceSql}
        ${cursorSql}
        ORDER BY ${sortExpression} ${queryDirection}, rules.id ${queryDirection}
        LIMIT ?
      `,
    )
    .bind(...filterParams, ...cursorParams, input.limit + 1)
    .all<BadgeIssuanceRuleRegistryRow>();
  const hasMoreInQueryDirection = result.results.length > input.limit;
  const boundedRows = result.results.slice(0, input.limit);
  const pageRows = isBefore ? boundedRows.reverse() : boundedRows;
  const firstRow = pageRows[0];
  const lastRow = pageRows.at(-1);

  let previousCursor: BadgeIssuanceRuleRegistryCursor | null = null;
  let nextCursor: BadgeIssuanceRuleRegistryCursor | null = null;

  if (input.cursor?.position === "after") {
    previousCursor =
      firstRow === undefined ? input.cursor.boundary : registryCursorFromRow(firstRow, input.sort);
    nextCursor =
      hasMoreInQueryDirection && lastRow !== undefined
        ? registryCursorFromRow(lastRow, input.sort)
        : null;
  } else if (input.cursor?.position === "before") {
    previousCursor =
      hasMoreInQueryDirection && firstRow !== undefined
        ? registryCursorFromRow(firstRow, input.sort)
        : null;
    nextCursor =
      lastRow === undefined ? input.cursor.boundary : registryCursorFromRow(lastRow, input.sort);
  } else if (hasMoreInQueryDirection && lastRow !== undefined) {
    nextCursor = registryCursorFromRow(lastRow, input.sort);
  }

  return {
    rules: pageRows.map((row) => mapBadgeIssuanceRuleRow(row)),
    totalCount,
    previousCursor,
    nextCursor,
  };
};
