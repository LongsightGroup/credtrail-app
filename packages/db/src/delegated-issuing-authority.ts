import { findBadgeTemplateById } from "./badge-templates";
import { assertValidIsoTimestamp, createPrefixedId } from "./shared-helpers";
import { findTenantMembership } from "./tenant-memberships";
import {
  ensureTenantOrgUnitsTable,
  findTenantOrgUnitById,
  isMissingTenantOrgUnitsTableError,
} from "./tenant-org-units";
import type { SqlDatabase, SqlQueryResult, SqlRunResult } from "./tenant-scope";

export type DelegatedIssuingAuthorityAction = "issue_badge" | "revoke_badge" | "manage_lifecycle";

export type DelegatedIssuingAuthorityGrantStatus = "scheduled" | "active" | "expired" | "revoked";

export interface DelegatedIssuingAuthorityGrantRecord {
  id: string;
  tenantId: string;
  delegateUserId: string;
  delegatedByUserId: string | null;
  orgUnitId: string;
  allowedActions: DelegatedIssuingAuthorityAction[];
  badgeTemplateIds: string[];
  startsAt: string;
  endsAt: string;
  revokedAt: string | null;
  revokedByUserId: string | null;
  revokedReason: string | null;
  status: DelegatedIssuingAuthorityGrantStatus;
  createdAt: string;
  updatedAt: string;
}

export type DelegatedIssuingAuthorityGrantEventType = "granted" | "revoked" | "expired";

export interface DelegatedIssuingAuthorityGrantEventRecord {
  id: string;
  tenantId: string;
  grantId: string;
  eventType: DelegatedIssuingAuthorityGrantEventType;
  actorUserId: string | null;
  detailsJson: string | null;
  occurredAt: string;
  createdAt: string;
}

export interface CreateDelegatedIssuingAuthorityGrantInput {
  tenantId: string;
  delegateUserId: string;
  delegatedByUserId?: string | undefined;
  orgUnitId: string;
  allowedActions: readonly DelegatedIssuingAuthorityAction[];
  badgeTemplateIds?: readonly string[] | undefined;
  startsAt: string;
  endsAt: string;
  reason?: string | undefined;
}

export interface ListDelegatedIssuingAuthorityGrantsInput {
  tenantId: string;
  delegateUserId?: string | undefined;
  includeRevoked?: boolean | undefined;
  includeExpired?: boolean | undefined;
  nowIso?: string | undefined;
}

export interface RevokeDelegatedIssuingAuthorityGrantInput {
  tenantId: string;
  grantId: string;
  revokedByUserId?: string | undefined;
  revokedReason?: string | undefined;
  revokedAt: string;
}

export interface RevokeDelegatedIssuingAuthorityGrantResult {
  status: "revoked" | "already_revoked";
  grant: DelegatedIssuingAuthorityGrantRecord;
}

export interface ListDelegatedIssuingAuthorityGrantEventsInput {
  tenantId: string;
  grantId: string;
  limit?: number | undefined;
}

export interface ResolveDelegatedIssuingAuthorityInput {
  tenantId: string;
  userId: string;
  orgUnitId: string;
  badgeTemplateId: string;
  requiredAction: DelegatedIssuingAuthorityAction;
  atIso?: string | undefined;
}

interface DelegatedIssuingAuthorityGrantRow {
  id: string;
  tenantId: string;
  delegateUserId: string;
  delegatedByUserId: string | null;
  orgUnitId: string;
  allowedActionsJson: string;
  startsAt: string;
  endsAt: string;
  revokedAt: string | null;
  revokedByUserId: string | null;
  revokedReason: string | null;
  createdAt: string;
  updatedAt: string;
}

interface DelegatedIssuingAuthorityGrantBadgeTemplateRow {
  grantId: string;
  badgeTemplateId: string;
}

interface DelegatedIssuingAuthorityGrantEventRow {
  id: string;
  tenantId: string;
  grantId: string;
  eventType: DelegatedIssuingAuthorityGrantEventType;
  actorUserId: string | null;
  detailsJson: string | null;
  occurredAt: string;
  createdAt: string;
}

const isMissingDelegatedIssuingAuthorityTablesError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  const tableMissing =
    error.message.includes("delegated_issuing_authority_grants") ||
    error.message.includes("delegated_issuing_authority_grant_badge_templates") ||
    error.message.includes("delegated_issuing_authority_grant_events");

  if (!tableMissing) {
    return false;
  }

  return (
    error.message.includes("no such table") ||
    error.message.includes("relation") ||
    error.message.includes("does not exist")
  );
};

const ensureDelegatedIssuingAuthorityTables = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS delegated_issuing_authority_grants (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        delegate_user_id TEXT NOT NULL,
        delegated_by_user_id TEXT,
        org_unit_id TEXT NOT NULL,
        allowed_actions_json TEXT NOT NULL,
        starts_at TEXT NOT NULL,
        ends_at TEXT NOT NULL,
        revoked_at TEXT,
        revoked_by_user_id TEXT,
        revoked_reason TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CHECK (starts_at < ends_at),
        UNIQUE (tenant_id, id),
        FOREIGN KEY (tenant_id, delegate_user_id) REFERENCES memberships (tenant_id, user_id) ON DELETE CASCADE,
        FOREIGN KEY (delegated_by_user_id) REFERENCES users (id) ON DELETE SET NULL,
        FOREIGN KEY (tenant_id, org_unit_id) REFERENCES tenant_org_units (tenant_id, id) ON DELETE CASCADE,
        FOREIGN KEY (revoked_by_user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS delegated_issuing_authority_grant_badge_templates (
        tenant_id TEXT NOT NULL,
        grant_id TEXT NOT NULL,
        badge_template_id TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (tenant_id, grant_id, badge_template_id),
        FOREIGN KEY (tenant_id, grant_id)
          REFERENCES delegated_issuing_authority_grants (tenant_id, id) ON DELETE CASCADE,
        FOREIGN KEY (tenant_id, badge_template_id)
          REFERENCES badge_templates (tenant_id, id) ON DELETE CASCADE
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS delegated_issuing_authority_grant_events (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        grant_id TEXT NOT NULL,
        event_type TEXT NOT NULL CHECK (event_type IN ('granted', 'revoked', 'expired')),
        actor_user_id TEXT,
        details_json TEXT,
        occurred_at TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (tenant_id, grant_id)
          REFERENCES delegated_issuing_authority_grants (tenant_id, id) ON DELETE CASCADE,
        FOREIGN KEY (actor_user_id)
          REFERENCES users (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_delegated_grants_delegate_active
        ON delegated_issuing_authority_grants (tenant_id, delegate_user_id, revoked_at, starts_at, ends_at)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_delegated_grants_delegate_org
        ON delegated_issuing_authority_grants (tenant_id, delegate_user_id, org_unit_id)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_delegated_grants_org_unit
        ON delegated_issuing_authority_grants (tenant_id, org_unit_id)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_delegated_grant_badge_templates_template
        ON delegated_issuing_authority_grant_badge_templates (tenant_id, badge_template_id)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_delegated_grant_events_grant
        ON delegated_issuing_authority_grant_events (tenant_id, grant_id, occurred_at DESC)
    `,
    )
    .run();
};

const DELEGATED_ISSUING_AUTHORITY_ACTIONS = new Set<DelegatedIssuingAuthorityAction>([
  "issue_badge",
  "revoke_badge",
  "manage_lifecycle",
]);

const normalizeDelegatedIssuingAuthorityActions = (
  actions: readonly DelegatedIssuingAuthorityAction[],
): DelegatedIssuingAuthorityAction[] => {
  const normalized = Array.from(new Set(actions));

  if (normalized.length === 0) {
    throw new Error("Delegated issuing authority grant must include at least one allowed action");
  }

  for (const action of normalized) {
    if (!DELEGATED_ISSUING_AUTHORITY_ACTIONS.has(action)) {
      throw new Error(`Unsupported delegated issuing authority action: ${action}`);
    }
  }

  return normalized.sort();
};

const parseDelegatedIssuingAuthorityActionsJson = (
  rawJson: string,
): DelegatedIssuingAuthorityAction[] => {
  let parsed: unknown;

  try {
    parsed = JSON.parse(rawJson) as unknown;
  } catch {
    throw new Error("delegated_issuing_authority_grants.allowed_actions_json must be valid JSON");
  }

  if (!Array.isArray(parsed)) {
    throw new Error("delegated_issuing_authority_grants.allowed_actions_json must be a JSON array");
  }

  const parsedArray = parsed as unknown[];
  const parsedActions: DelegatedIssuingAuthorityAction[] = [];

  for (const candidate of parsedArray) {
    if (
      typeof candidate !== "string" ||
      (candidate !== "issue_badge" &&
        candidate !== "revoke_badge" &&
        candidate !== "manage_lifecycle")
    ) {
      throw new Error(
        `delegated_issuing_authority_grants.allowed_actions_json contains unsupported action: ${String(candidate)}`,
      );
    }

    parsedActions.push(candidate);
  }

  return normalizeDelegatedIssuingAuthorityActions(parsedActions);
};

const normalizeDelegatedIssuingAuthorityBadgeTemplateIds = (
  badgeTemplateIds: readonly string[] | undefined,
): string[] => {
  if (badgeTemplateIds === undefined) {
    return [];
  }

  const normalized = Array.from(new Set(badgeTemplateIds));
  return normalized.sort();
};

const delegatedIssuingAuthorityGrantStatusForRecord = (
  grant: {
    startsAt: string;
    endsAt: string;
    revokedAt: string | null;
  },
  nowIso: string,
): DelegatedIssuingAuthorityGrantStatus => {
  if (grant.revokedAt !== null) {
    return "revoked";
  }

  const nowMs = assertValidIsoTimestamp(nowIso, "nowIso");
  const startsAtMs = assertValidIsoTimestamp(grant.startsAt, "startsAt");
  const endsAtMs = assertValidIsoTimestamp(grant.endsAt, "endsAt");

  if (nowMs < startsAtMs) {
    return "scheduled";
  }

  if (nowMs > endsAtMs) {
    return "expired";
  }

  return "active";
};

const mapDelegatedIssuingAuthorityGrantEventRow = (
  row: DelegatedIssuingAuthorityGrantEventRow,
): DelegatedIssuingAuthorityGrantEventRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    grantId: row.grantId,
    eventType: row.eventType,
    actorUserId: row.actorUserId,
    detailsJson: row.detailsJson,
    occurredAt: row.occurredAt,
    createdAt: row.createdAt,
  };
};

const isOrgUnitWithinDelegatedAuthorityScope = async (
  db: SqlDatabase,
  tenantId: string,
  targetOrgUnitId: string,
  scopedOrgUnitId: string,
): Promise<boolean> => {
  const statement = (): Promise<{ id: string } | null> =>
    db
      .prepare(
        `
        WITH RECURSIVE org_ancestors AS (
          SELECT id, parent_org_unit_id AS parentOrgUnitId
          FROM tenant_org_units
          WHERE tenant_id = ?
            AND id = ?

          UNION ALL

          SELECT parent.id, parent.parent_org_unit_id AS parentOrgUnitId
          FROM tenant_org_units parent
          INNER JOIN org_ancestors
            ON org_ancestors.parentOrgUnitId = parent.id
          WHERE parent.tenant_id = ?
        )
        SELECT id
        FROM org_ancestors
        WHERE id = ?
        LIMIT 1
      `,
      )
      .bind(tenantId, targetOrgUnitId, tenantId, scopedOrgUnitId)
      .first<{ id: string }>();

  let row: { id: string } | null;

  try {
    row = await statement();
  } catch (error: unknown) {
    if (!isMissingTenantOrgUnitsTableError(error)) {
      throw error;
    }

    await ensureTenantOrgUnitsTable(db);
    row = await statement();
  }

  return row !== null;
};

const listDelegatedIssuingAuthorityGrantBadgeTemplateIds = async (
  db: SqlDatabase,
  tenantId: string,
  grantId: string,
): Promise<string[]> => {
  const listStatement = (): Promise<
    SqlQueryResult<DelegatedIssuingAuthorityGrantBadgeTemplateRow>
  > =>
    db
      .prepare(
        `
        SELECT
          grant_id AS grantId,
          badge_template_id AS badgeTemplateId
        FROM delegated_issuing_authority_grant_badge_templates
        WHERE tenant_id = ?
          AND grant_id = ?
        ORDER BY badge_template_id ASC
      `,
      )
      .bind(tenantId, grantId)
      .all<DelegatedIssuingAuthorityGrantBadgeTemplateRow>();

  let result: SqlQueryResult<DelegatedIssuingAuthorityGrantBadgeTemplateRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingDelegatedIssuingAuthorityTablesError(error)) {
      throw error;
    }

    await ensureDelegatedIssuingAuthorityTables(db);
    result = await listStatement();
  }

  return result.results.map((row) => row.badgeTemplateId);
};

const mapDelegatedIssuingAuthorityGrantRow = async (
  db: SqlDatabase,
  row: DelegatedIssuingAuthorityGrantRow,
  nowIso: string,
): Promise<DelegatedIssuingAuthorityGrantRecord> => {
  const badgeTemplateIds = await listDelegatedIssuingAuthorityGrantBadgeTemplateIds(
    db,
    row.tenantId,
    row.id,
  );

  return {
    id: row.id,
    tenantId: row.tenantId,
    delegateUserId: row.delegateUserId,
    delegatedByUserId: row.delegatedByUserId,
    orgUnitId: row.orgUnitId,
    allowedActions: parseDelegatedIssuingAuthorityActionsJson(row.allowedActionsJson),
    badgeTemplateIds,
    startsAt: row.startsAt,
    endsAt: row.endsAt,
    revokedAt: row.revokedAt,
    revokedByUserId: row.revokedByUserId,
    revokedReason: row.revokedReason,
    status: delegatedIssuingAuthorityGrantStatusForRecord(row, nowIso),
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const findDelegatedIssuingAuthorityGrantRowById = async (
  db: SqlDatabase,
  tenantId: string,
  grantId: string,
): Promise<DelegatedIssuingAuthorityGrantRow | null> => {
  const findStatement = (): Promise<DelegatedIssuingAuthorityGrantRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          delegate_user_id AS delegateUserId,
          delegated_by_user_id AS delegatedByUserId,
          org_unit_id AS orgUnitId,
          allowed_actions_json AS allowedActionsJson,
          starts_at AS startsAt,
          ends_at AS endsAt,
          revoked_at AS revokedAt,
          revoked_by_user_id AS revokedByUserId,
          revoked_reason AS revokedReason,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM delegated_issuing_authority_grants
        WHERE tenant_id = ?
          AND id = ?
        LIMIT 1
      `,
      )
      .bind(tenantId, grantId)
      .first<DelegatedIssuingAuthorityGrantRow>();

  let row: DelegatedIssuingAuthorityGrantRow | null;

  try {
    row = await findStatement();
  } catch (error: unknown) {
    if (!isMissingDelegatedIssuingAuthorityTablesError(error)) {
      throw error;
    }

    await ensureDelegatedIssuingAuthorityTables(db);
    row = await findStatement();
  }

  return row;
};

const createDelegatedIssuingAuthorityGrantEvent = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    grantId: string;
    eventType: DelegatedIssuingAuthorityGrantEventType;
    actorUserId: string | null;
    detailsJson: string | null;
    occurredAt: string;
  },
): Promise<DelegatedIssuingAuthorityGrantEventRecord> => {
  const eventId = createPrefixedId("dage");
  const nowIso = new Date().toISOString();
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO delegated_issuing_authority_grant_events (
          id,
          tenant_id,
          grant_id,
          event_type,
          actor_user_id,
          details_json,
          occurred_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        eventId,
        input.tenantId,
        input.grantId,
        input.eventType,
        input.actorUserId,
        input.detailsJson,
        input.occurredAt,
        nowIso,
      )
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingDelegatedIssuingAuthorityTablesError(error)) {
      throw error;
    }

    await ensureDelegatedIssuingAuthorityTables(db);
    await insertStatement();
  }

  return {
    id: eventId,
    tenantId: input.tenantId,
    grantId: input.grantId,
    eventType: input.eventType,
    actorUserId: input.actorUserId,
    detailsJson: input.detailsJson,
    occurredAt: input.occurredAt,
    createdAt: nowIso,
  };
};

const recordExpiredDelegatedIssuingAuthorityGrantEvents = async (
  db: SqlDatabase,
  tenantId: string,
  nowIso: string,
): Promise<void> => {
  const listStatement = (): Promise<SqlQueryResult<{ grantId: string; endsAt: string }>> =>
    db
      .prepare(
        `
        SELECT
          grants.id AS grantId,
          grants.ends_at AS endsAt
        FROM delegated_issuing_authority_grants grants
        WHERE grants.tenant_id = ?
          AND grants.revoked_at IS NULL
          AND grants.ends_at < ?
          AND NOT EXISTS (
            SELECT 1
            FROM delegated_issuing_authority_grant_events events
            WHERE events.tenant_id = grants.tenant_id
              AND events.grant_id = grants.id
              AND events.event_type = 'expired'
          )
      `,
      )
      .bind(tenantId, nowIso)
      .all<{ grantId: string; endsAt: string }>();

  let result: SqlQueryResult<{ grantId: string; endsAt: string }>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingDelegatedIssuingAuthorityTablesError(error)) {
      throw error;
    }

    await ensureDelegatedIssuingAuthorityTables(db);
    result = await listStatement();
  }

  for (const row of result.results) {
    await createDelegatedIssuingAuthorityGrantEvent(db, {
      tenantId,
      grantId: row.grantId,
      eventType: "expired",
      actorUserId: null,
      detailsJson: null,
      occurredAt: row.endsAt,
    });
  }
};

const hasDelegatedGrantTemplateScopeOverlap = (
  candidateTemplateIds: readonly string[],
  existingTemplateIds: readonly string[],
): boolean => {
  if (candidateTemplateIds.length === 0 || existingTemplateIds.length === 0) {
    return true;
  }

  const existing = new Set(existingTemplateIds);

  for (const templateId of candidateTemplateIds) {
    if (existing.has(templateId)) {
      return true;
    }
  }

  return false;
};

const hasDelegatedGrantActionOverlap = (
  candidateActions: readonly DelegatedIssuingAuthorityAction[],
  existingActions: readonly DelegatedIssuingAuthorityAction[],
): boolean => {
  const existing = new Set(existingActions);

  for (const action of candidateActions) {
    if (existing.has(action)) {
      return true;
    }
  }

  return false;
};

export const findDelegatedIssuingAuthorityGrantById = async (
  db: SqlDatabase,
  tenantId: string,
  grantId: string,
  nowIso = new Date().toISOString(),
): Promise<DelegatedIssuingAuthorityGrantRecord | null> => {
  await recordExpiredDelegatedIssuingAuthorityGrantEvents(db, tenantId, nowIso);

  const row = await findDelegatedIssuingAuthorityGrantRowById(db, tenantId, grantId);
  return row === null ? null : mapDelegatedIssuingAuthorityGrantRow(db, row, nowIso);
};

export const createDelegatedIssuingAuthorityGrant = async (
  db: SqlDatabase,
  input: CreateDelegatedIssuingAuthorityGrantInput,
): Promise<DelegatedIssuingAuthorityGrantRecord> => {
  const startsAtMs = assertValidIsoTimestamp(input.startsAt, "startsAt");
  const endsAtMs = assertValidIsoTimestamp(input.endsAt, "endsAt");

  if (endsAtMs <= startsAtMs) {
    throw new Error("endsAt must be after startsAt");
  }

  const allowedActions = normalizeDelegatedIssuingAuthorityActions(input.allowedActions);
  const badgeTemplateIds = normalizeDelegatedIssuingAuthorityBadgeTemplateIds(
    input.badgeTemplateIds,
  );

  const membership = await findTenantMembership(db, input.tenantId, input.delegateUserId);

  if (membership === null) {
    throw new Error(
      `Membership not found for tenant ${input.tenantId} and user ${input.delegateUserId}`,
    );
  }

  const scopedOrgUnit = await findTenantOrgUnitById(db, input.tenantId, input.orgUnitId);

  if (scopedOrgUnit === null) {
    throw new Error(`Org unit ${input.orgUnitId} not found for tenant ${input.tenantId}`);
  }

  if (!scopedOrgUnit.isActive) {
    throw new Error(`Org unit ${input.orgUnitId} is inactive for tenant ${input.tenantId}`);
  }

  for (const badgeTemplateId of badgeTemplateIds) {
    const template = await findBadgeTemplateById(db, input.tenantId, badgeTemplateId);

    if (template === null) {
      throw new Error(`Badge template ${badgeTemplateId} not found for tenant ${input.tenantId}`);
    }

    const templateInScope = await isOrgUnitWithinDelegatedAuthorityScope(
      db,
      input.tenantId,
      template.ownerOrgUnitId,
      input.orgUnitId,
    );

    if (!templateInScope) {
      throw new Error(
        `Badge template ${badgeTemplateId} is outside delegated org-unit scope ${input.orgUnitId} for tenant ${input.tenantId}`,
      );
    }
  }

  const conflictingStatement = (): Promise<SqlQueryResult<DelegatedIssuingAuthorityGrantRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          delegate_user_id AS delegateUserId,
          delegated_by_user_id AS delegatedByUserId,
          org_unit_id AS orgUnitId,
          allowed_actions_json AS allowedActionsJson,
          starts_at AS startsAt,
          ends_at AS endsAt,
          revoked_at AS revokedAt,
          revoked_by_user_id AS revokedByUserId,
          revoked_reason AS revokedReason,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM delegated_issuing_authority_grants
        WHERE tenant_id = ?
          AND delegate_user_id = ?
          AND org_unit_id = ?
          AND revoked_at IS NULL
          AND starts_at < ?
          AND ends_at > ?
      `,
      )
      .bind(input.tenantId, input.delegateUserId, input.orgUnitId, input.endsAt, input.startsAt)
      .all<DelegatedIssuingAuthorityGrantRow>();

  let conflicts: SqlQueryResult<DelegatedIssuingAuthorityGrantRow>;

  try {
    conflicts = await conflictingStatement();
  } catch (error: unknown) {
    if (!isMissingDelegatedIssuingAuthorityTablesError(error)) {
      throw error;
    }

    await ensureDelegatedIssuingAuthorityTables(db);
    conflicts = await conflictingStatement();
  }

  for (const existing of conflicts.results) {
    const existingActions = parseDelegatedIssuingAuthorityActionsJson(existing.allowedActionsJson);

    if (!hasDelegatedGrantActionOverlap(allowedActions, existingActions)) {
      continue;
    }

    const existingTemplateIds = await listDelegatedIssuingAuthorityGrantBadgeTemplateIds(
      db,
      input.tenantId,
      existing.id,
    );

    if (hasDelegatedGrantTemplateScopeOverlap(badgeTemplateIds, existingTemplateIds)) {
      throw new Error(
        `Delegated issuing authority grant conflicts with existing grant ${existing.id}`,
      );
    }
  }

  const grantId = createPrefixedId("dag");
  const nowIso = new Date().toISOString();
  const insertGrantStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO delegated_issuing_authority_grants (
          id,
          tenant_id,
          delegate_user_id,
          delegated_by_user_id,
          org_unit_id,
          allowed_actions_json,
          starts_at,
          ends_at,
          revoked_at,
          revoked_by_user_id,
          revoked_reason,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?)
      `,
      )
      .bind(
        grantId,
        input.tenantId,
        input.delegateUserId,
        input.delegatedByUserId ?? null,
        input.orgUnitId,
        JSON.stringify(allowedActions),
        input.startsAt,
        input.endsAt,
        nowIso,
        nowIso,
      )
      .run();

  try {
    await insertGrantStatement();
  } catch (error: unknown) {
    if (!isMissingDelegatedIssuingAuthorityTablesError(error)) {
      throw error;
    }

    await ensureDelegatedIssuingAuthorityTables(db);
    await insertGrantStatement();
  }

  if (badgeTemplateIds.length > 0) {
    for (const badgeTemplateId of badgeTemplateIds) {
      const insertTemplateScopeStatement = (): Promise<SqlRunResult> =>
        db
          .prepare(
            `
            INSERT INTO delegated_issuing_authority_grant_badge_templates (
              tenant_id,
              grant_id,
              badge_template_id,
              created_at
            )
            VALUES (?, ?, ?, ?)
          `,
          )
          .bind(input.tenantId, grantId, badgeTemplateId, nowIso)
          .run();

      try {
        await insertTemplateScopeStatement();
      } catch (error: unknown) {
        if (!isMissingDelegatedIssuingAuthorityTablesError(error)) {
          throw error;
        }

        await ensureDelegatedIssuingAuthorityTables(db);
        await insertTemplateScopeStatement();
      }
    }
  }

  const detailsJson = input.reason === undefined ? null : JSON.stringify({ reason: input.reason });

  await createDelegatedIssuingAuthorityGrantEvent(db, {
    tenantId: input.tenantId,
    grantId,
    eventType: "granted",
    actorUserId: input.delegatedByUserId ?? null,
    detailsJson,
    occurredAt: nowIso,
  });

  const created = await findDelegatedIssuingAuthorityGrantById(db, input.tenantId, grantId, nowIso);

  if (created === null) {
    throw new Error(`Unable to load delegated issuing authority grant ${grantId} after insert`);
  }

  return created;
};

export const listDelegatedIssuingAuthorityGrants = async (
  db: SqlDatabase,
  input: ListDelegatedIssuingAuthorityGrantsInput,
): Promise<DelegatedIssuingAuthorityGrantRecord[]> => {
  const nowIso = input.nowIso ?? new Date().toISOString();
  await recordExpiredDelegatedIssuingAuthorityGrantEvents(db, input.tenantId, nowIso);

  const query =
    input.delegateUserId === undefined
      ? `
        SELECT
          id,
          tenant_id AS tenantId,
          delegate_user_id AS delegateUserId,
          delegated_by_user_id AS delegatedByUserId,
          org_unit_id AS orgUnitId,
          allowed_actions_json AS allowedActionsJson,
          starts_at AS startsAt,
          ends_at AS endsAt,
          revoked_at AS revokedAt,
          revoked_by_user_id AS revokedByUserId,
          revoked_reason AS revokedReason,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM delegated_issuing_authority_grants
        WHERE tenant_id = ?
        ORDER BY created_at DESC
      `
      : `
        SELECT
          id,
          tenant_id AS tenantId,
          delegate_user_id AS delegateUserId,
          delegated_by_user_id AS delegatedByUserId,
          org_unit_id AS orgUnitId,
          allowed_actions_json AS allowedActionsJson,
          starts_at AS startsAt,
          ends_at AS endsAt,
          revoked_at AS revokedAt,
          revoked_by_user_id AS revokedByUserId,
          revoked_reason AS revokedReason,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM delegated_issuing_authority_grants
        WHERE tenant_id = ?
          AND delegate_user_id = ?
        ORDER BY created_at DESC
      `;

  const listStatement = (): Promise<SqlQueryResult<DelegatedIssuingAuthorityGrantRow>> =>
    input.delegateUserId === undefined
      ? db.prepare(query).bind(input.tenantId).all<DelegatedIssuingAuthorityGrantRow>()
      : db
          .prepare(query)
          .bind(input.tenantId, input.delegateUserId)
          .all<DelegatedIssuingAuthorityGrantRow>();

  let result: SqlQueryResult<DelegatedIssuingAuthorityGrantRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingDelegatedIssuingAuthorityTablesError(error)) {
      throw error;
    }

    await ensureDelegatedIssuingAuthorityTables(db);
    result = await listStatement();
  }

  const mapped: DelegatedIssuingAuthorityGrantRecord[] = [];

  for (const row of result.results) {
    const record = await mapDelegatedIssuingAuthorityGrantRow(db, row, nowIso);
    mapped.push(record);
  }

  return mapped.filter((record) => {
    if (input.includeRevoked !== true && record.status === "revoked") {
      return false;
    }

    if (input.includeExpired !== true && record.status === "expired") {
      return false;
    }

    return true;
  });
};

export const revokeDelegatedIssuingAuthorityGrant = async (
  db: SqlDatabase,
  input: RevokeDelegatedIssuingAuthorityGrantInput,
): Promise<RevokeDelegatedIssuingAuthorityGrantResult> => {
  assertValidIsoTimestamp(input.revokedAt, "revokedAt");

  const existing = await findDelegatedIssuingAuthorityGrantById(
    db,
    input.tenantId,
    input.grantId,
    input.revokedAt,
  );

  if (existing === null) {
    throw new Error(
      `Delegated issuing authority grant ${input.grantId} not found for tenant ${input.tenantId}`,
    );
  }

  if (existing.revokedAt !== null) {
    return {
      status: "already_revoked",
      grant: existing,
    };
  }

  const nowIso = new Date().toISOString();
  const revokeStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE delegated_issuing_authority_grants
        SET revoked_at = ?,
            revoked_by_user_id = ?,
            revoked_reason = ?,
            updated_at = ?
        WHERE tenant_id = ?
          AND id = ?
          AND revoked_at IS NULL
      `,
      )
      .bind(
        input.revokedAt,
        input.revokedByUserId ?? null,
        input.revokedReason ?? null,
        nowIso,
        input.tenantId,
        input.grantId,
      )
      .run();

  let result: SqlRunResult;

  try {
    result = await revokeStatement();
  } catch (error: unknown) {
    if (!isMissingDelegatedIssuingAuthorityTablesError(error)) {
      throw error;
    }

    await ensureDelegatedIssuingAuthorityTables(db);
    result = await revokeStatement();
  }

  if ((result.meta.rowsWritten ?? 0) > 0) {
    const detailsJson =
      input.revokedReason === undefined ? null : JSON.stringify({ reason: input.revokedReason });

    await createDelegatedIssuingAuthorityGrantEvent(db, {
      tenantId: input.tenantId,
      grantId: input.grantId,
      eventType: "revoked",
      actorUserId: input.revokedByUserId ?? null,
      detailsJson,
      occurredAt: input.revokedAt,
    });
  }

  const grant = await findDelegatedIssuingAuthorityGrantById(
    db,
    input.tenantId,
    input.grantId,
    input.revokedAt,
  );

  if (grant === null) {
    throw new Error(
      `Unable to load delegated issuing authority grant ${input.grantId} after revoke`,
    );
  }

  return {
    status: (result.meta.rowsWritten ?? 0) > 0 ? "revoked" : "already_revoked",
    grant,
  };
};

export const listDelegatedIssuingAuthorityGrantEvents = async (
  db: SqlDatabase,
  input: ListDelegatedIssuingAuthorityGrantEventsInput,
): Promise<DelegatedIssuingAuthorityGrantEventRecord[]> => {
  await recordExpiredDelegatedIssuingAuthorityGrantEvents(
    db,
    input.tenantId,
    new Date().toISOString(),
  );

  const limit =
    input.limit === undefined ? 100 : Math.max(1, Math.min(500, Math.trunc(input.limit)));
  const listStatement = (): Promise<SqlQueryResult<DelegatedIssuingAuthorityGrantEventRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          grant_id AS grantId,
          event_type AS eventType,
          actor_user_id AS actorUserId,
          details_json AS detailsJson,
          occurred_at AS occurredAt,
          created_at AS createdAt
        FROM delegated_issuing_authority_grant_events
        WHERE tenant_id = ?
          AND grant_id = ?
        ORDER BY occurred_at DESC, created_at DESC
        LIMIT ?
      `,
      )
      .bind(input.tenantId, input.grantId, limit)
      .all<DelegatedIssuingAuthorityGrantEventRow>();

  let result: SqlQueryResult<DelegatedIssuingAuthorityGrantEventRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingDelegatedIssuingAuthorityTablesError(error)) {
      throw error;
    }

    await ensureDelegatedIssuingAuthorityTables(db);
    result = await listStatement();
  }

  return result.results.map((row) => mapDelegatedIssuingAuthorityGrantEventRow(row));
};

export const findActiveDelegatedIssuingAuthorityGrantForAction = async (
  db: SqlDatabase,
  input: ResolveDelegatedIssuingAuthorityInput,
): Promise<DelegatedIssuingAuthorityGrantRecord | null> => {
  const atIso = input.atIso ?? new Date().toISOString();
  assertValidIsoTimestamp(atIso, "atIso");
  await recordExpiredDelegatedIssuingAuthorityGrantEvents(db, input.tenantId, atIso);

  const listStatement = (): Promise<SqlQueryResult<DelegatedIssuingAuthorityGrantRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          delegate_user_id AS delegateUserId,
          delegated_by_user_id AS delegatedByUserId,
          org_unit_id AS orgUnitId,
          allowed_actions_json AS allowedActionsJson,
          starts_at AS startsAt,
          ends_at AS endsAt,
          revoked_at AS revokedAt,
          revoked_by_user_id AS revokedByUserId,
          revoked_reason AS revokedReason,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM delegated_issuing_authority_grants
        WHERE tenant_id = ?
          AND delegate_user_id = ?
          AND revoked_at IS NULL
          AND starts_at <= ?
          AND ends_at >= ?
        ORDER BY starts_at ASC, created_at ASC
      `,
      )
      .bind(input.tenantId, input.userId, atIso, atIso)
      .all<DelegatedIssuingAuthorityGrantRow>();

  let result: SqlQueryResult<DelegatedIssuingAuthorityGrantRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingDelegatedIssuingAuthorityTablesError(error)) {
      throw error;
    }

    await ensureDelegatedIssuingAuthorityTables(db);
    result = await listStatement();
  }

  for (const row of result.results) {
    const grant = await mapDelegatedIssuingAuthorityGrantRow(db, row, atIso);

    if (!grant.allowedActions.includes(input.requiredAction)) {
      continue;
    }

    const orgUnitAllowed = await isOrgUnitWithinDelegatedAuthorityScope(
      db,
      input.tenantId,
      input.orgUnitId,
      grant.orgUnitId,
    );

    if (!orgUnitAllowed) {
      continue;
    }

    if (
      grant.badgeTemplateIds.length > 0 &&
      !grant.badgeTemplateIds.includes(input.badgeTemplateId)
    ) {
      continue;
    }

    return grant;
  }

  return null;
};

export const hasDelegatedIssuingAuthorityAccess = async (
  db: SqlDatabase,
  input: ResolveDelegatedIssuingAuthorityInput,
): Promise<boolean> => {
  const grant = await findActiveDelegatedIssuingAuthorityGrantForAction(db, input);
  return grant !== null;
};
