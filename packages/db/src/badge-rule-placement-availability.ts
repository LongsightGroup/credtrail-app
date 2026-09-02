import type { ReplaceBadgeRulePlacementAvailabilityRequest } from "@credtrail/validation";

import { createAuditLog } from "./audit-logs.js";
import {
  badgeIssuanceRuleSelectColumns,
  mapBadgeIssuanceRuleRow,
  type BadgeIssuanceRuleRow,
} from "./badge-issuance-rule-reads.js";
import type { BadgeIssuanceRuleRecord } from "./badge-issuance-rule-types.js";
import { ORG_ANCESTORS_WITH_DEPTH_CTE } from "./tenant-org-unit-hierarchy-sql.js";
import type { TenantMembershipRole } from "./tenant-memberships.js";
import {
  findTenantLmsCourseContextByIdentity,
  type TenantLmsCourseContextRecord,
} from "./lti-course-contexts.js";
import { createPrefixedId } from "./shared-helpers.js";
import { runSqlTransaction, type SqlDatabase } from "./tenant-scope.js";

interface BadgeRulePlacementAvailabilityRecordBase {
  readonly id: string;
  readonly tenantId: string;
  readonly ruleId: string;
  readonly createdByUserId: string | null;
  readonly updatedByUserId: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

/** Parsed persisted placement policy for one stable rule identity. */
export type BadgeRulePlacementAvailabilityRecord = BadgeRulePlacementAvailabilityRecordBase &
  (
    | {
        readonly scope: "selected_courses";
        readonly rootOrgUnitId: null;
        readonly courseContextIds: readonly string[];
      }
    | {
        readonly scope: "org_unit_subtree";
        readonly rootOrgUnitId: string;
        readonly courseContextIds: readonly [];
      }
    | {
        readonly scope: "tenant";
        readonly rootOrgUnitId: null;
        readonly courseContextIds: readonly [];
      }
  );

/** Exhaustive placement-authorization outcome for one rule and exact LMS context. */
export type BadgeRulePlacementAuthorizationResult =
  | {
      readonly status: "allowed";
      readonly availability: BadgeRulePlacementAvailabilityRecord;
      readonly courseContext: TenantLmsCourseContextRecord;
    }
  | { readonly status: "no_policy" }
  | { readonly status: "course_context_not_found" }
  | { readonly status: "course_unmapped" }
  | { readonly status: "org_unit_inactive" }
  | { readonly status: "outside_availability" };

/** Outcome of replacing one rule's current placement policy. */
export type ReplaceBadgeRulePlacementAvailabilityResult =
  | {
      readonly status: "updated" | "unchanged";
      readonly availability: BadgeRulePlacementAvailabilityRecord;
    }
  | { readonly status: "not_authorized" }
  | { readonly status: "rule_not_found" }
  | { readonly status: "rule_not_active" }
  | { readonly status: "course_context_not_found" }
  | { readonly status: "org_unit_not_found" }
  | { readonly status: "org_unit_inactive" }
  | { readonly status: "org_unit_not_course" };

/** Outcome of removing one rule's current placement policy. */
export type RemoveBadgeRulePlacementAvailabilityResult =
  | { readonly status: "removed" | "unchanged" }
  | { readonly status: "not_authorized" }
  | { readonly status: "rule_not_found" };

/** Counts why otherwise active rules were excluded from a course picker. */
export interface BadgeRulePlacementAvailabilityExclusionCounts {
  readonly noPolicy: number;
  readonly courseContextNotFound: number;
  readonly courseUnmapped: number;
  readonly orgUnitInactive: number;
  readonly outsideAvailability: number;
}

/** Available active rules plus typed exclusion counts for one exact LMS context. */
export interface ListActiveBadgeRulesAvailableForContextResult {
  readonly rules: readonly BadgeIssuanceRuleRecord[];
  readonly exclusionCounts: BadgeRulePlacementAvailabilityExclusionCounts;
}

interface BadgeRulePlacementAvailabilityRow {
  readonly id: string;
  readonly tenantId: string;
  readonly ruleId: string;
  readonly scopeType: string;
  readonly rootOrgUnitId: string | null;
  readonly createdByUserId: string | null;
  readonly updatedByUserId: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

interface CourseContextTargetRow {
  readonly courseContextId: string;
}

interface LockedRuleRow {
  readonly id: string;
  readonly isUsable: boolean | number;
}

interface OrgUnitAvailabilityRow {
  readonly id: string;
  readonly unitType: string;
  readonly isActive: boolean | number;
}

interface OrgAncestorRow {
  readonly orgUnitId: string;
  readonly depth: number | string;
  readonly isActive: boolean | number;
}

interface MutableExclusionCounts {
  noPolicy: number;
  courseContextNotFound: number;
  courseUnmapped: number;
  orgUnitInactive: number;
  outsideAvailability: number;
}

const AVAILABILITY_SELECT_COLUMNS = `
  id,
  tenant_id AS tenantId,
  rule_id AS ruleId,
  scope_type AS scopeType,
  root_org_unit_id AS rootOrgUnitId,
  created_by_user_id AS createdByUserId,
  updated_by_user_id AS updatedByUserId,
  created_at AS createdAt,
  updated_at AS updatedAt
`;

const canManageAvailability = (role: TenantMembershipRole): boolean => {
  return role === "owner" || role === "admin";
};

const requireStoredText = (value: string, field: string, recordId: string): string => {
  const normalized = value.trim();

  if (normalized.length === 0) {
    throw new Error(`Rule placement availability "${recordId}" has an empty ${field}`);
  }

  return normalized;
};

const loadCourseContextIds = async (
  db: SqlDatabase,
  availability: BadgeRulePlacementAvailabilityRow,
): Promise<readonly string[]> => {
  const result = await db
    .prepare(
      `
      SELECT course_context_id AS courseContextId
      FROM badge_rule_placement_available_courses
      WHERE tenant_id = ?
        AND availability_id = ?
      ORDER BY course_context_id ASC
    `,
    )
    .bind(availability.tenantId, availability.id)
    .all<CourseContextTargetRow>();

  return result.results.map((row) =>
    requireStoredText(row.courseContextId, "course context ID", availability.id),
  );
};

const parseAvailabilityRow = async (
  db: SqlDatabase,
  row: BadgeRulePlacementAvailabilityRow,
): Promise<BadgeRulePlacementAvailabilityRecord> => {
  const base: BadgeRulePlacementAvailabilityRecordBase = {
    id: requireStoredText(row.id, "ID", row.id),
    tenantId: requireStoredText(row.tenantId, "tenant ID", row.id),
    ruleId: requireStoredText(row.ruleId, "rule ID", row.id),
    createdByUserId: row.createdByUserId,
    updatedByUserId: row.updatedByUserId,
    createdAt: requireStoredText(row.createdAt, "created timestamp", row.id),
    updatedAt: requireStoredText(row.updatedAt, "updated timestamp", row.id),
  };
  const courseContextIds = await loadCourseContextIds(db, row);

  switch (row.scopeType) {
    case "selected_courses": {
      if (row.rootOrgUnitId !== null || courseContextIds.length === 0) {
        throw new Error(`Rule placement availability "${row.id}" has invalid selected courses`);
      }

      return {
        ...base,
        scope: "selected_courses",
        rootOrgUnitId: null,
        courseContextIds,
      };
    }
    case "org_unit_subtree": {
      if (row.rootOrgUnitId === null || courseContextIds.length > 0) {
        throw new Error(`Rule placement availability "${row.id}" has invalid org-unit scope`);
      }

      return {
        ...base,
        scope: "org_unit_subtree",
        rootOrgUnitId: requireStoredText(row.rootOrgUnitId, "root org unit ID", row.id),
        courseContextIds: [],
      };
    }
    case "tenant": {
      if (row.rootOrgUnitId !== null || courseContextIds.length > 0) {
        throw new Error(`Rule placement availability "${row.id}" has invalid tenant scope`);
      }

      return {
        ...base,
        scope: "tenant",
        rootOrgUnitId: null,
        courseContextIds: [],
      };
    }
    default:
      throw new Error(`Rule placement availability "${row.id}" has an unknown scope`);
  }
};

const findAvailabilityRow = async (
  db: SqlDatabase,
  input: { readonly tenantId: string; readonly ruleId: string; readonly forUpdate?: boolean },
): Promise<BadgeRulePlacementAvailabilityRow | null> => {
  const lockClause = input.forUpdate === true ? "FOR UPDATE" : "";

  return db
    .prepare(
      `
      SELECT
        ${AVAILABILITY_SELECT_COLUMNS}
      FROM badge_rule_placement_availabilities
      WHERE tenant_id = ?
        AND rule_id = ?
      LIMIT 1
      ${lockClause}
    `,
    )
    .bind(input.tenantId, input.ruleId)
    .first<BadgeRulePlacementAvailabilityRow>();
};

const availabilityMatchesRequest = (
  current: BadgeRulePlacementAvailabilityRecord,
  requested: ReplaceBadgeRulePlacementAvailabilityRequest,
): boolean => {
  switch (requested.scope) {
    case "selected_courses": {
      if (current.scope !== "selected_courses") {
        return false;
      }

      const requestedIds = [...requested.courseContextIds].sort((left, right) =>
        left.localeCompare(right),
      );
      return (
        requestedIds.length === current.courseContextIds.length &&
        requestedIds.every(
          (courseContextId, index) => courseContextId === current.courseContextIds[index],
        )
      );
    }
    case "org_unit_subtree":
      return (
        current.scope === "org_unit_subtree" && current.rootOrgUnitId === requested.rootOrgUnitId
      );
    case "tenant":
      return current.scope === "tenant";
  }
};

const summarizeAvailability = (
  availability: BadgeRulePlacementAvailabilityRecord | null,
): {
  readonly scope: BadgeRulePlacementAvailabilityRecord["scope"] | null;
  readonly rootOrgUnitId: string | null;
  readonly selectedCourseCount: number;
} => {
  if (availability === null) {
    return { scope: null, rootOrgUnitId: null, selectedCourseCount: 0 };
  }

  return {
    scope: availability.scope,
    rootOrgUnitId: availability.rootOrgUnitId,
    selectedCourseCount: availability.courseContextIds.length,
  };
};

const lockRule = async (
  db: SqlDatabase,
  input: { readonly tenantId: string; readonly ruleId: string; readonly evaluatedAt: string },
): Promise<LockedRuleRow | null> => {
  return db
    .prepare(
      `
      SELECT
        rules.id,
        CASE WHEN
          active_version.status = 'active'
          AND (
            active_version.effective_starts_at IS NULL
            OR active_version.effective_starts_at::TIMESTAMPTZ <= ?::TIMESTAMPTZ
          )
          AND (
            active_version.expires_at IS NULL
            OR active_version.expires_at::TIMESTAMPTZ > ?::TIMESTAMPTZ
          )
        THEN 1 ELSE 0 END AS isUsable
      FROM badge_issuance_rules AS rules
      LEFT JOIN badge_issuance_rule_versions AS active_version
        ON active_version.tenant_id = rules.tenant_id
        AND active_version.rule_id = rules.id
        AND active_version.id = rules.active_version_id
      WHERE rules.tenant_id = ?
        AND rules.id = ?
      LIMIT 1
      FOR UPDATE OF rules
    `,
    )
    .bind(input.evaluatedAt, input.evaluatedAt, input.tenantId, input.ruleId)
    .first<LockedRuleRow>();
};

const validateRequestedReferences = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly availability: ReplaceBadgeRulePlacementAvailabilityRequest;
  },
): Promise<
  | { readonly status: "valid"; readonly courseContextIds: readonly string[] }
  | { readonly status: "course_context_not_found" }
  | { readonly status: "org_unit_not_found" }
  | { readonly status: "org_unit_inactive" }
  | { readonly status: "org_unit_not_course" }
> => {
  switch (input.availability.scope) {
    case "selected_courses": {
      const courseContextIds = [...input.availability.courseContextIds].sort((left, right) =>
        left.localeCompare(right),
      );

      if (
        courseContextIds.length === 0 ||
        courseContextIds.some((courseContextId) => courseContextId.trim().length === 0) ||
        new Set(courseContextIds).size !== courseContextIds.length
      ) {
        throw new Error("Parsed selected-course availability is empty, blank, or duplicated");
      }

      const placeholders = courseContextIds.map(() => "?").join(", ");
      const result = await db
        .prepare(
          `
          SELECT id
          FROM tenant_lms_course_contexts
          WHERE tenant_id = ?
            AND id IN (${placeholders})
        `,
        )
        .bind(input.tenantId, ...courseContextIds)
        .all<{ readonly id: string }>();

      if (result.results.length !== courseContextIds.length) {
        return { status: "course_context_not_found" };
      }

      return { status: "valid", courseContextIds };
    }
    case "org_unit_subtree": {
      const orgUnit = await db
        .prepare(
          `
          SELECT
            id,
            unit_type AS unitType,
            is_active AS isActive
          FROM tenant_org_units
          WHERE tenant_id = ?
            AND id = ?
          LIMIT 1
        `,
        )
        .bind(input.tenantId, input.availability.rootOrgUnitId)
        .first<OrgUnitAvailabilityRow>();

      if (orgUnit === null) {
        return { status: "org_unit_not_found" };
      }

      if (orgUnit.unitType === "course") {
        return { status: "org_unit_not_course" };
      }

      if (!["institution", "college", "department", "program"].includes(orgUnit.unitType)) {
        throw new Error(`Org unit "${orgUnit.id}" has an unknown type`);
      }

      if (orgUnit.isActive !== true && orgUnit.isActive !== 1) {
        return { status: "org_unit_inactive" };
      }

      return { status: "valid", courseContextIds: [] };
    }
    case "tenant":
      return { status: "valid", courseContextIds: [] };
  }
};

/** Finds the current placement-availability policy for one tenant-owned rule. */
export const findBadgeRulePlacementAvailability = async (
  db: SqlDatabase,
  input: { readonly tenantId: string; readonly ruleId: string },
): Promise<BadgeRulePlacementAvailabilityRecord | null> => {
  const row = await findAvailabilityRow(db, input);
  return row === null ? null : parseAvailabilityRow(db, row);
};

/** Lists every current placement-availability policy in one tenant. */
export const listBadgeRulePlacementAvailabilities = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<readonly BadgeRulePlacementAvailabilityRecord[]> => {
  const result = await db
    .prepare(
      `
      SELECT
        ${AVAILABILITY_SELECT_COLUMNS}
      FROM badge_rule_placement_availabilities
      WHERE tenant_id = ?
      ORDER BY created_at ASC, id ASC
    `,
    )
    .bind(tenantId)
    .all<BadgeRulePlacementAvailabilityRow>();
  const policies: BadgeRulePlacementAvailabilityRecord[] = [];

  // Preserve bounded pressure on the shared database adapter while parsing child rows.
  for (const row of result.results) {
    policies.push(await parseAvailabilityRow(db, row));
  }

  return policies;
};

/** Atomically replaces one rule's placement policy and audits only a real change. */
export const replaceBadgeRulePlacementAvailability = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly ruleId: string;
    readonly availability: ReplaceBadgeRulePlacementAvailabilityRequest;
    readonly actorUserId: string;
    readonly actorRole: TenantMembershipRole;
    readonly evaluatedAt?: string | undefined;
  },
): Promise<ReplaceBadgeRulePlacementAvailabilityResult> => {
  if (!canManageAvailability(input.actorRole)) {
    return { status: "not_authorized" };
  }

  return runSqlTransaction(db, async (transactionDb) => {
    const evaluatedAt = input.evaluatedAt ?? new Date().toISOString();
    const rule = await lockRule(transactionDb, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      evaluatedAt,
    });

    if (rule === null) {
      return { status: "rule_not_found" };
    }

    if (rule.isUsable !== true && rule.isUsable !== 1) {
      return { status: "rule_not_active" };
    }

    const references = await validateRequestedReferences(transactionDb, input);

    if (references.status !== "valid") {
      return references;
    }

    const currentRow = await findAvailabilityRow(transactionDb, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      forUpdate: true,
    });
    const current =
      currentRow === null ? null : await parseAvailabilityRow(transactionDb, currentRow);

    if (current !== null && availabilityMatchesRequest(current, input.availability)) {
      return { status: "unchanged", availability: current };
    }

    const availabilityId = current?.id ?? createPrefixedId("brpa");
    const nowIso = new Date().toISOString();
    const rootOrgUnitId =
      input.availability.scope === "org_unit_subtree" ? input.availability.rootOrgUnitId : null;

    await transactionDb
      .prepare(
        `
        INSERT INTO badge_rule_placement_availabilities (
          id,
          tenant_id,
          rule_id,
          scope_type,
          root_org_unit_id,
          created_by_user_id,
          updated_by_user_id,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (tenant_id, rule_id)
        DO UPDATE SET
          scope_type = excluded.scope_type,
          root_org_unit_id = excluded.root_org_unit_id,
          updated_by_user_id = excluded.updated_by_user_id,
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        availabilityId,
        input.tenantId,
        input.ruleId,
        input.availability.scope,
        rootOrgUnitId,
        input.actorUserId,
        input.actorUserId,
        nowIso,
        nowIso,
      )
      .run();

    await transactionDb
      .prepare(
        `
        DELETE FROM badge_rule_placement_available_courses
        WHERE tenant_id = ?
          AND availability_id = ?
      `,
      )
      .bind(input.tenantId, availabilityId)
      .run();

    if (references.courseContextIds.length > 0) {
      const valuesSql = references.courseContextIds.map(() => "(?, ?, ?, ?)").join(", ");
      const params = references.courseContextIds.flatMap((courseContextId) => [
        input.tenantId,
        availabilityId,
        courseContextId,
        nowIso,
      ]);

      await transactionDb
        .prepare(
          `
          INSERT INTO badge_rule_placement_available_courses (
            tenant_id,
            availability_id,
            course_context_id,
            created_at
          )
          VALUES ${valuesSql}
        `,
        )
        .bind(...params)
        .run();
    }

    const updated = await findBadgeRulePlacementAvailability(transactionDb, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
    });

    if (updated === null) {
      throw new Error(`Unable to replace placement availability for rule "${input.ruleId}"`);
    }

    await createAuditLog(transactionDb, {
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      action: "badge_rule.placement_availability_updated",
      targetType: "badge_issuance_rule",
      targetId: input.ruleId,
      metadata: {
        actorRole: input.actorRole,
        availabilityId: updated.id,
        ruleId: input.ruleId,
        previous: summarizeAvailability(current),
        current: summarizeAvailability(updated),
      },
    });

    return { status: "updated", availability: updated };
  });
};

/** Atomically removes one rule's placement policy without deleting placement history. */
export const removeBadgeRulePlacementAvailability = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly ruleId: string;
    readonly actorUserId: string;
    readonly actorRole: TenantMembershipRole;
  },
): Promise<RemoveBadgeRulePlacementAvailabilityResult> => {
  if (!canManageAvailability(input.actorRole)) {
    return { status: "not_authorized" };
  }

  return runSqlTransaction(db, async (transactionDb) => {
    const rule = await transactionDb
      .prepare(
        `
        SELECT id
        FROM badge_issuance_rules
        WHERE tenant_id = ?
          AND id = ?
        LIMIT 1
        FOR UPDATE
      `,
      )
      .bind(input.tenantId, input.ruleId)
      .first<{ readonly id: string }>();

    if (rule === null) {
      return { status: "rule_not_found" };
    }

    const currentRow = await findAvailabilityRow(transactionDb, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      forUpdate: true,
    });

    if (currentRow === null) {
      return { status: "unchanged" };
    }

    const current = await parseAvailabilityRow(transactionDb, currentRow);

    await transactionDb
      .prepare(
        `
        DELETE FROM badge_rule_placement_availabilities
        WHERE tenant_id = ?
          AND rule_id = ?
      `,
      )
      .bind(input.tenantId, input.ruleId)
      .run();

    await createAuditLog(transactionDb, {
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      action: "badge_rule.placement_availability_removed",
      targetType: "badge_issuance_rule",
      targetId: input.ruleId,
      metadata: {
        actorRole: input.actorRole,
        availabilityId: current.id,
        ruleId: input.ruleId,
        previous: summarizeAvailability(current),
        current: summarizeAvailability(null),
      },
    });

    return { status: "removed" };
  });
};

/** Resolves placement availability for one rule and exact tenant/LMS/context identity. */
export const resolveBadgeRulePlacementAvailabilityForContext = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly ruleId: string;
    readonly lmsConnectionId: string;
    readonly contextId: string;
  },
): Promise<BadgeRulePlacementAuthorizationResult> => {
  const courseContext = await findTenantLmsCourseContextByIdentity(db, input);

  if (courseContext === null) {
    return { status: "course_context_not_found" };
  }

  const availability = await findBadgeRulePlacementAvailability(db, input);

  if (availability === null) {
    return { status: "no_policy" };
  }

  switch (availability.scope) {
    case "selected_courses":
      return availability.courseContextIds.includes(courseContext.id)
        ? { status: "allowed", availability, courseContext }
        : { status: "outside_availability" };
    case "tenant":
      return { status: "allowed", availability, courseContext };
    case "org_unit_subtree": {
      if (courseContext.courseOrgUnitId === null) {
        return { status: "course_unmapped" };
      }

      const ancestors = await db
        .prepare(
          `
          ${ORG_ANCESTORS_WITH_DEPTH_CTE}
          SELECT
            org_ancestors.orgUnitId,
            org_ancestors.depth,
            org_units.is_active AS isActive
          FROM org_ancestors
          INNER JOIN tenant_org_units AS org_units
            ON org_units.tenant_id = ?
            AND org_units.id = org_ancestors.orgUnitId
          ORDER BY org_ancestors.depth ASC
        `,
        )
        .bind(input.tenantId, courseContext.courseOrgUnitId, input.tenantId, input.tenantId)
        .all<OrgAncestorRow>();
      const root = ancestors.results.find(
        (ancestor) => ancestor.orgUnitId === availability.rootOrgUnitId,
      );

      if (root === undefined) {
        return { status: "outside_availability" };
      }

      const rootDepth = Number(root.depth);
      const hasInactivePath = ancestors.results.some(
        (ancestor) =>
          Number(ancestor.depth) <= rootDepth &&
          ancestor.isActive !== true &&
          ancestor.isActive !== 1,
      );

      return hasInactivePath
        ? { status: "org_unit_inactive" }
        : { status: "allowed", availability, courseContext };
    }
  }
};

/** Lists usable rules whose current policy allows one exact tenant LMS context. */
export const listActiveBadgeRulesAvailableForContext = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly lmsConnectionId: string;
    readonly contextId: string;
    readonly evaluatedAt?: string | undefined;
  },
): Promise<ListActiveBadgeRulesAvailableForContextResult> => {
  const evaluatedAt = input.evaluatedAt ?? new Date().toISOString();
  const candidates = await db
    .prepare(
      `
      SELECT
        ${badgeIssuanceRuleSelectColumns("rules")}
      FROM badge_issuance_rules AS rules
      INNER JOIN badge_issuance_rule_versions AS active_version
        ON active_version.tenant_id = rules.tenant_id
        AND active_version.rule_id = rules.id
        AND active_version.id = rules.active_version_id
      WHERE rules.tenant_id = ?
        AND rules.lms_connection_id = ?
        AND active_version.status = 'active'
        AND (
          active_version.effective_starts_at IS NULL
          OR active_version.effective_starts_at::TIMESTAMPTZ <= ?::TIMESTAMPTZ
        )
        AND (
          active_version.expires_at IS NULL
          OR active_version.expires_at::TIMESTAMPTZ > ?::TIMESTAMPTZ
        )
      ORDER BY rules.name ASC, rules.id ASC
    `,
    )
    .bind(input.tenantId, input.lmsConnectionId, evaluatedAt, evaluatedAt)
    .all<BadgeIssuanceRuleRow>();
  const rules: BadgeIssuanceRuleRecord[] = [];
  const exclusionCounts: MutableExclusionCounts = {
    noPolicy: 0,
    courseContextNotFound: 0,
    courseUnmapped: 0,
    orgUnitInactive: 0,
    outsideAvailability: 0,
  };

  // Keep database work serialized through the shared adapter instead of opening an unbounded fan-out.
  for (const row of candidates.results) {
    const rule = mapBadgeIssuanceRuleRow(row);
    const authorization = await resolveBadgeRulePlacementAvailabilityForContext(db, {
      tenantId: input.tenantId,
      ruleId: rule.id,
      lmsConnectionId: input.lmsConnectionId,
      contextId: input.contextId,
    });

    switch (authorization.status) {
      case "allowed":
        rules.push(rule);
        break;
      case "no_policy":
        exclusionCounts.noPolicy += 1;
        break;
      case "course_context_not_found":
        exclusionCounts.courseContextNotFound += 1;
        break;
      case "course_unmapped":
        exclusionCounts.courseUnmapped += 1;
        break;
      case "org_unit_inactive":
        exclusionCounts.orgUnitInactive += 1;
        break;
      case "outside_availability":
        exclusionCounts.outsideAvailability += 1;
        break;
    }
  }

  return { rules, exclusionCounts };
};
