import { createPrefixedId } from "./shared-helpers.js";
import { runSqlTransaction, type SqlDatabase } from "./tenant-scope.js";

/** Exact tenant-owned identity for one LMS course context. */
export interface TenantLmsCourseContextRecord {
  readonly id: string;
  readonly tenantId: string;
  readonly lmsConnectionId: string;
  readonly contextId: string;
  readonly displayName: string;
  readonly courseCode: string | null;
  readonly courseOrgUnitId: string | null;
  readonly createdByUserId: string | null;
  readonly firstSeenAt: string | null;
  readonly lastSeenAt: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

/** Catalog evidence used to create or refresh one exact LMS course context. */
export interface UpsertCatalogLmsCourseContextInput {
  readonly tenantId: string;
  readonly lmsConnectionId: string;
  readonly contextId: string;
  readonly displayName: string;
  readonly courseCode?: string | null | undefined;
  readonly createdByUserId: string;
}

/** Verified launch evidence used to observe one exact LMS course context. */
export interface ObserveVerifiedLtiCourseContextInput {
  readonly tenantId: string;
  readonly lmsConnectionId: string;
  readonly contextId: string;
  readonly displayName: string;
  readonly courseCode?: string | null | undefined;
  readonly observedAt?: string | undefined;
}

/** Outcome of assigning an LMS course context to an explicit course org unit. */
export type AssignLmsCourseContextOrgUnitResult =
  | {
      readonly status: "assigned" | "unchanged";
      readonly courseContext: TenantLmsCourseContextRecord;
    }
  | { readonly status: "course_context_not_found" }
  | { readonly status: "org_unit_not_found" }
  | { readonly status: "org_unit_inactive" }
  | { readonly status: "org_unit_not_course" }
  | {
      readonly status: "mapping_conflict";
      readonly existingCourseOrgUnitId: string;
    };

interface TenantLmsCourseContextRow {
  readonly id: string;
  readonly tenantId: string;
  readonly lmsConnectionId: string;
  readonly contextId: string;
  readonly displayName: string;
  readonly courseCode: string | null;
  readonly courseOrgUnitId: string | null;
  readonly createdByUserId: string | null;
  readonly firstSeenAt: string | null;
  readonly lastSeenAt: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

interface CourseOrgUnitRow {
  readonly id: string;
  readonly unitType: string;
  readonly isActive: boolean | number;
}

const COURSE_CONTEXT_SELECT_COLUMNS = `
  id,
  tenant_id AS tenantId,
  lms_connection_id AS lmsConnectionId,
  context_id AS contextId,
  display_name AS displayName,
  course_code AS courseCode,
  course_org_unit_id AS courseOrgUnitId,
  created_by_user_id AS createdByUserId,
  first_seen_at AS firstSeenAt,
  last_seen_at AS lastSeenAt,
  created_at AS createdAt,
  updated_at AS updatedAt
`;

const requireNonEmpty = (value: string, field: string): string => {
  const normalized = value.trim();

  if (normalized.length === 0) {
    throw new Error(`LMS course context has an empty ${field}`);
  }

  return normalized;
};

const normalizeOptionalText = (value: string | null | undefined): string | null => {
  if (value === undefined || value === null) {
    return null;
  }

  const normalized = value.trim();
  return normalized.length === 0 ? null : normalized;
};

const parseTimestamp = (value: string, field: string, rowId: string): number => {
  const timestamp = Date.parse(value);

  if (!Number.isFinite(timestamp)) {
    throw new Error(`LMS course context "${rowId}" has an invalid ${field}`);
  }

  return timestamp;
};

const mapTenantLmsCourseContextRow = (
  row: TenantLmsCourseContextRow,
): TenantLmsCourseContextRecord => {
  const id = requireNonEmpty(row.id, "ID");
  const firstSeenTimestamp =
    row.firstSeenAt === null ? null : parseTimestamp(row.firstSeenAt, "first-seen timestamp", id);
  const lastSeenTimestamp =
    row.lastSeenAt === null ? null : parseTimestamp(row.lastSeenAt, "last-seen timestamp", id);

  if ((firstSeenTimestamp === null) !== (lastSeenTimestamp === null)) {
    throw new Error(`LMS course context "${id}" has contradictory verified timestamps`);
  }

  if (
    firstSeenTimestamp !== null &&
    lastSeenTimestamp !== null &&
    firstSeenTimestamp > lastSeenTimestamp
  ) {
    throw new Error(`LMS course context "${id}" has a last-seen timestamp before first-seen`);
  }

  return {
    id,
    tenantId: requireNonEmpty(row.tenantId, "tenant ID"),
    lmsConnectionId: requireNonEmpty(row.lmsConnectionId, "LMS connection ID"),
    contextId: requireNonEmpty(row.contextId, "context ID"),
    displayName: requireNonEmpty(row.displayName, "display name"),
    courseCode: normalizeOptionalText(row.courseCode),
    courseOrgUnitId: normalizeOptionalText(row.courseOrgUnitId),
    createdByUserId: normalizeOptionalText(row.createdByUserId),
    firstSeenAt: row.firstSeenAt,
    lastSeenAt: row.lastSeenAt,
    createdAt: requireNonEmpty(row.createdAt, "created timestamp"),
    updatedAt: requireNonEmpty(row.updatedAt, "updated timestamp"),
  };
};

const findCourseContextForUpdate = async (
  db: SqlDatabase,
  input: { readonly tenantId: string; readonly courseContextId: string },
): Promise<TenantLmsCourseContextRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        ${COURSE_CONTEXT_SELECT_COLUMNS}
      FROM tenant_lms_course_contexts
      WHERE tenant_id = ?
        AND id = ?
      LIMIT 1
      FOR UPDATE
    `,
    )
    .bind(input.tenantId, input.courseContextId)
    .first<TenantLmsCourseContextRow>();

  return row === null ? null : mapTenantLmsCourseContextRow(row);
};

/** Finds one LMS course context by tenant-owned record identity. */
export const findTenantLmsCourseContextById = async (
  db: SqlDatabase,
  input: { readonly tenantId: string; readonly courseContextId: string },
): Promise<TenantLmsCourseContextRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        ${COURSE_CONTEXT_SELECT_COLUMNS}
      FROM tenant_lms_course_contexts
      WHERE tenant_id = ?
        AND id = ?
      LIMIT 1
    `,
    )
    .bind(input.tenantId, input.courseContextId)
    .first<TenantLmsCourseContextRow>();

  return row === null ? null : mapTenantLmsCourseContextRow(row);
};

/** Finds one exact course identity under a tenant LMS connection. */
export const findTenantLmsCourseContextByIdentity = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly lmsConnectionId: string;
    readonly contextId: string;
  },
): Promise<TenantLmsCourseContextRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        ${COURSE_CONTEXT_SELECT_COLUMNS}
      FROM tenant_lms_course_contexts
      WHERE tenant_id = ?
        AND lms_connection_id = ?
        AND context_id = ?
      LIMIT 1
    `,
    )
    .bind(input.tenantId, input.lmsConnectionId, input.contextId)
    .first<TenantLmsCourseContextRow>();

  return row === null ? null : mapTenantLmsCourseContextRow(row);
};

/** Lists tenant-owned course contexts, optionally within one LMS connection. */
export const listTenantLmsCourseContexts = async (
  db: SqlDatabase,
  input: { readonly tenantId: string; readonly lmsConnectionId?: string | undefined },
): Promise<readonly TenantLmsCourseContextRecord[]> => {
  const connectionClause = input.lmsConnectionId === undefined ? "" : "AND lms_connection_id = ?";
  const params =
    input.lmsConnectionId === undefined
      ? [input.tenantId]
      : [input.tenantId, input.lmsConnectionId];
  const result = await db
    .prepare(
      `
      SELECT
        ${COURSE_CONTEXT_SELECT_COLUMNS}
      FROM tenant_lms_course_contexts
      WHERE tenant_id = ?
        ${connectionClause}
      ORDER BY display_name ASC, context_id ASC, id ASC
    `,
    )
    .bind(...params)
    .all<TenantLmsCourseContextRow>();

  return result.results.map(mapTenantLmsCourseContextRow);
};

/** Stores catalog metadata without manufacturing verified launch timestamps. */
export const upsertCatalogLmsCourseContext = async (
  db: SqlDatabase,
  input: UpsertCatalogLmsCourseContextInput,
): Promise<TenantLmsCourseContextRecord> => {
  const id = createPrefixedId("lctx");
  const contextId = requireNonEmpty(input.contextId, "context ID");
  const displayName = requireNonEmpty(input.displayName, "display name");
  const courseCode = normalizeOptionalText(input.courseCode);
  const nowIso = new Date().toISOString();

  await db
    .prepare(
      `
      INSERT INTO tenant_lms_course_contexts (
        id,
        tenant_id,
        lms_connection_id,
        context_id,
        display_name,
        course_code,
        course_org_unit_id,
        created_by_user_id,
        first_seen_at,
        last_seen_at,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, NULL, ?, NULL, NULL, ?, ?)
      ON CONFLICT (tenant_id, lms_connection_id, context_id)
      DO UPDATE SET
        display_name = excluded.display_name,
        course_code = excluded.course_code,
        created_by_user_id = COALESCE(
          tenant_lms_course_contexts.created_by_user_id,
          excluded.created_by_user_id
        ),
        updated_at = excluded.updated_at
    `,
    )
    .bind(
      id,
      input.tenantId,
      input.lmsConnectionId,
      contextId,
      displayName,
      courseCode,
      input.createdByUserId,
      nowIso,
      nowIso,
    )
    .run();

  const courseContext = await findTenantLmsCourseContextByIdentity(db, {
    tenantId: input.tenantId,
    lmsConnectionId: input.lmsConnectionId,
    contextId,
  });

  if (courseContext === null) {
    throw new Error(`Unable to store LMS catalog course context "${contextId}"`);
  }

  return courseContext;
};

/** Records verified LTI launch evidence with monotonic first/last-seen timestamps. */
export const observeVerifiedLtiCourseContext = async (
  db: SqlDatabase,
  input: ObserveVerifiedLtiCourseContextInput,
): Promise<TenantLmsCourseContextRecord> => {
  const id = createPrefixedId("lctx");
  const contextId = requireNonEmpty(input.contextId, "context ID");
  const displayName = requireNonEmpty(input.displayName, "display name");
  const courseCode = normalizeOptionalText(input.courseCode);
  const observedAt = input.observedAt ?? new Date().toISOString();
  parseTimestamp(observedAt, "observed timestamp", id);
  const updatedAt = new Date().toISOString();

  await db
    .prepare(
      `
      INSERT INTO tenant_lms_course_contexts (
        id,
        tenant_id,
        lms_connection_id,
        context_id,
        display_name,
        course_code,
        course_org_unit_id,
        created_by_user_id,
        first_seen_at,
        last_seen_at,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?)
      ON CONFLICT (tenant_id, lms_connection_id, context_id)
      DO UPDATE SET
        display_name = excluded.display_name,
        course_code = excluded.course_code,
        first_seen_at = CASE
          WHEN tenant_lms_course_contexts.first_seen_at IS NULL THEN excluded.first_seen_at
          WHEN tenant_lms_course_contexts.first_seen_at::TIMESTAMPTZ > excluded.first_seen_at::TIMESTAMPTZ
            THEN excluded.first_seen_at
          ELSE tenant_lms_course_contexts.first_seen_at
        END,
        last_seen_at = CASE
          WHEN tenant_lms_course_contexts.last_seen_at IS NULL THEN excluded.last_seen_at
          WHEN tenant_lms_course_contexts.last_seen_at::TIMESTAMPTZ < excluded.last_seen_at::TIMESTAMPTZ
            THEN excluded.last_seen_at
          ELSE tenant_lms_course_contexts.last_seen_at
        END,
        updated_at = excluded.updated_at
    `,
    )
    .bind(
      id,
      input.tenantId,
      input.lmsConnectionId,
      contextId,
      displayName,
      courseCode,
      observedAt,
      observedAt,
      updatedAt,
      updatedAt,
    )
    .run();

  const courseContext = await findTenantLmsCourseContextByIdentity(db, {
    tenantId: input.tenantId,
    lmsConnectionId: input.lmsConnectionId,
    contextId,
  });

  if (courseContext === null) {
    throw new Error(`Unable to observe verified LTI course context "${contextId}"`);
  }

  return courseContext;
};

/** Assigns an exact context to one active same-tenant course org unit without remapping. */
export const assignLmsCourseContextOrgUnit = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly courseContextId: string;
    readonly courseOrgUnitId: string;
  },
): Promise<AssignLmsCourseContextOrgUnitResult> => {
  return runSqlTransaction(db, async (transactionDb) => {
    const courseContext = await findCourseContextForUpdate(transactionDb, input);

    if (courseContext === null) {
      return { status: "course_context_not_found" };
    }

    const orgUnit = await transactionDb
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
      .bind(input.tenantId, input.courseOrgUnitId)
      .first<CourseOrgUnitRow>();

    if (orgUnit === null) {
      return { status: "org_unit_not_found" };
    }

    if (orgUnit.unitType !== "course") {
      return { status: "org_unit_not_course" };
    }

    if (orgUnit.isActive !== true && orgUnit.isActive !== 1) {
      return { status: "org_unit_inactive" };
    }

    if (courseContext.courseOrgUnitId === input.courseOrgUnitId) {
      return { status: "unchanged", courseContext };
    }

    if (courseContext.courseOrgUnitId !== null) {
      return {
        status: "mapping_conflict",
        existingCourseOrgUnitId: courseContext.courseOrgUnitId,
      };
    }

    const nowIso = new Date().toISOString();
    await transactionDb
      .prepare(
        `
        UPDATE tenant_lms_course_contexts
        SET course_org_unit_id = ?,
            updated_at = ?
        WHERE tenant_id = ?
          AND id = ?
          AND course_org_unit_id IS NULL
      `,
      )
      .bind(input.courseOrgUnitId, nowIso, input.tenantId, input.courseContextId)
      .run();

    const assigned = await findTenantLmsCourseContextById(transactionDb, input);

    if (assigned === null) {
      throw new Error(`Unable to assign LMS course context "${input.courseContextId}"`);
    }

    return { status: "assigned", courseContext: assigned };
  });
};
