import { normalizeLtiIssuer } from "./lti";
import { createAuditLog } from "./audit-logs";
import { runSqlTransaction, type SqlDatabase, type SqlRunResult } from "./tenant-scope";
import type { TenantMembershipRole } from "./tenant-memberships";

interface LtiResourceLinkPlacementRecordBase {
  id: string;
  tenantId: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  contextId: string | null;
  resourceLinkId: string;
  badgeTemplateId: string;
  ruleId: string | null;
  createdByUserId: string | null;
  lastSeenAt: string;
  createdAt: string;
  updatedAt: string;
}

export type LtiResourceLinkPlacementRecord = LtiResourceLinkPlacementRecordBase &
  (
    | {
        status: "active";
        retiredAt: null;
        retiredByUserId: null;
      }
    | {
        status: "retired";
        retiredAt: string;
        retiredByUserId: string;
      }
  );

export interface UpsertLtiResourceLinkPlacementInput {
  id?: string | undefined;
  tenantId: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  contextId?: string | null | undefined;
  resourceLinkId: string;
  badgeTemplateId: string;
  ruleId?: string | null | undefined;
  createdByUserId?: string | null;
}

export interface ListLtiResourceLinkPlacementsForContextInput {
  tenantId: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  contextId: string;
  includeRetired?: boolean | undefined;
}

interface LtiResourceLinkPlacementRow {
  id: string;
  tenantId: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  contextId: string | null;
  resourceLinkId: string;
  badgeTemplateId: string;
  ruleId: string | null;
  createdByUserId: string | null;
  status: string;
  lastSeenAt: string;
  retiredAt: string | null;
  retiredByUserId: string | null;
  createdAt: string;
  updatedAt: string;
}

export type RetireLtiResourceLinkPlacementResult =
  | {
      status: "retired";
      placement: LtiResourceLinkPlacementRecord;
    }
  | {
      status: "already_retired";
      placement: LtiResourceLinkPlacementRecord;
    }
  | {
      status: "not_found";
    };

export interface LtiResourceLinkPlacementRuleState {
  ruleId: string;
  isActive: boolean;
}

const ltiResourceLinkPlacementSelectColumns = (): string => `
  id,
  tenant_id AS tenantId,
  issuer,
  client_id AS clientId,
  deployment_id AS deploymentId,
  context_id AS contextId,
  resource_link_id AS resourceLinkId,
  badge_template_id AS badgeTemplateId,
  rule_id AS ruleId,
  created_by_user_id AS createdByUserId,
  status,
  last_seen_at AS lastSeenAt,
  retired_at AS retiredAt,
  retired_by_user_id AS retiredByUserId,
  created_at AS createdAt,
  updated_at AS updatedAt
`;

const mapLtiResourceLinkPlacementRow = (
  row: LtiResourceLinkPlacementRow,
): LtiResourceLinkPlacementRecord => {
  const base = {
    id: row.id,
    tenantId: row.tenantId,
    issuer: row.issuer,
    clientId: row.clientId,
    deploymentId: row.deploymentId,
    contextId: row.contextId,
    resourceLinkId: row.resourceLinkId,
    badgeTemplateId: row.badgeTemplateId,
    ruleId: row.ruleId,
    createdByUserId: row.createdByUserId,
    lastSeenAt: row.lastSeenAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };

  if (row.lastSeenAt.length === 0) {
    throw new Error(`LTI resource-link placement "${row.id}" has no last-seen timestamp`);
  }

  if (row.status === "active" && row.retiredAt === null && row.retiredByUserId === null) {
    return {
      ...base,
      status: "active",
      retiredAt: null,
      retiredByUserId: null,
    };
  }

  if (
    row.status === "retired" &&
    row.retiredAt !== null &&
    row.retiredByUserId !== null &&
    row.retiredAt.length > 0 &&
    row.retiredByUserId.length > 0
  ) {
    return {
      ...base,
      status: "retired",
      retiredAt: row.retiredAt,
      retiredByUserId: row.retiredByUserId,
    };
  }

  throw new Error(`LTI resource-link placement "${row.id}" has an invalid lifecycle state`);
};

/** Locks and returns one exact placement identity inside an existing transaction. */
export const findLtiResourceLinkPlacementForUpdateWithinTransaction = async (
  db: SqlDatabase,
  input: {
    issuer: string;
    clientId: string;
    deploymentId: string;
    resourceLinkId: string;
  },
): Promise<LtiResourceLinkPlacementRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        ${ltiResourceLinkPlacementSelectColumns()}
      FROM lti_resource_link_placements
      WHERE issuer = ?
        AND client_id = ?
        AND deployment_id = ?
        AND resource_link_id = ?
      LIMIT 1
      FOR UPDATE
    `,
    )
    .bind(input.issuer, input.clientId, input.deploymentId, input.resourceLinkId)
    .first<LtiResourceLinkPlacementRow>();

  return row === null ? null : mapLtiResourceLinkPlacementRow(row);
};

/** Upserts verified placement evidence inside an existing transaction. */
export const upsertLtiResourceLinkPlacementWithinTransaction = async (
  db: SqlDatabase,
  input: UpsertLtiResourceLinkPlacementInput,
): Promise<LtiResourceLinkPlacementRecord> => {
  const normalizedIssuer = normalizeLtiIssuer(input.issuer);
  const nowIso = new Date().toISOString();
  const id = input.id ?? `lti_place_${crypto.randomUUID().replace(/-/g, "")}`;
  const previous = await findLtiResourceLinkPlacementForUpdateWithinTransaction(db, {
    issuer: normalizedIssuer,
    clientId: input.clientId,
    deploymentId: input.deploymentId,
    resourceLinkId: input.resourceLinkId,
  });

  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
          INSERT INTO lti_resource_link_placements (
            id,
            tenant_id,
            issuer,
            client_id,
            deployment_id,
            context_id,
            resource_link_id,
            badge_template_id,
            rule_id,
            created_by_user_id,
            status,
            last_seen_at,
            retired_at,
            retired_by_user_id,
            created_at,
            updated_at
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, NULL, NULL, ?, ?)
          ON CONFLICT (issuer, client_id, deployment_id, resource_link_id)
          DO UPDATE SET
            context_id = excluded.context_id,
            badge_template_id = excluded.badge_template_id,
            rule_id = COALESCE(excluded.rule_id, lti_resource_link_placements.rule_id),
            created_by_user_id = COALESCE(excluded.created_by_user_id, lti_resource_link_placements.created_by_user_id),
            status = 'active',
            last_seen_at = excluded.last_seen_at,
            retired_at = NULL,
            retired_by_user_id = NULL,
            updated_at = excluded.updated_at
          WHERE lti_resource_link_placements.tenant_id = excluded.tenant_id
        `,
      )
      .bind(
        id,
        input.tenantId,
        normalizedIssuer,
        input.clientId,
        input.deploymentId,
        input.contextId ?? null,
        input.resourceLinkId,
        input.badgeTemplateId,
        input.ruleId ?? null,
        input.createdByUserId ?? null,
        nowIso,
        nowIso,
        nowIso,
      )
      .run();

  await upsertStatement();

  const placement = await findLtiResourceLinkPlacement(db, {
    issuer: normalizedIssuer,
    clientId: input.clientId,
    deploymentId: input.deploymentId,
    resourceLinkId: input.resourceLinkId,
  });

  if (placement === null) {
    throw new Error(`Unable to upsert LTI resource-link placement "${input.resourceLinkId}"`);
  }

  if (placement.tenantId !== input.tenantId) {
    throw new Error("LTI resource-link placement belongs to another tenant");
  }

  if (previous?.status === "retired") {
    await createAuditLog(db, {
      tenantId: placement.tenantId,
      ...(input.createdByUserId === undefined || input.createdByUserId === null
        ? {}
        : { actorUserId: input.createdByUserId }),
      action: "lti.resource_link_placement_reactivated",
      targetType: "lti_resource_link_placement",
      targetId: placement.id,
      metadata: {
        ruleId: placement.ruleId,
        contextId: placement.contextId,
        previousStatus: previous.status,
      },
    });
  }

  return placement;
};

export const upsertLtiResourceLinkPlacement = async (
  db: SqlDatabase,
  input: UpsertLtiResourceLinkPlacementInput,
): Promise<LtiResourceLinkPlacementRecord> => {
  return runSqlTransaction(db, (transactionDb) =>
    upsertLtiResourceLinkPlacementWithinTransaction(transactionDb, input),
  );
};

export const findLtiResourceLinkPlacement = async (
  db: SqlDatabase,
  input: {
    issuer: string;
    clientId: string;
    deploymentId: string;
    resourceLinkId: string;
  },
): Promise<LtiResourceLinkPlacementRecord | null> => {
  const normalizedIssuer = normalizeLtiIssuer(input.issuer);
  const findStatement = (): Promise<LtiResourceLinkPlacementRow | null> =>
    db
      .prepare(
        `
        SELECT
          ${ltiResourceLinkPlacementSelectColumns()}
        FROM lti_resource_link_placements
        WHERE issuer = ?
          AND client_id = ?
          AND deployment_id = ?
          AND resource_link_id = ?
        LIMIT 1
      `,
      )
      .bind(normalizedIssuer, input.clientId, input.deploymentId, input.resourceLinkId)
      .first<LtiResourceLinkPlacementRow>();

  const row = await findStatement();

  return row === null ? null : mapLtiResourceLinkPlacementRow(row);
};

export const findLtiResourceLinkPlacementForRule = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    ruleId: string;
  },
): Promise<LtiResourceLinkPlacementRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        ${ltiResourceLinkPlacementSelectColumns()}
      FROM lti_resource_link_placements
      WHERE tenant_id = ?
        AND rule_id = ?
        AND status = 'active'
      ORDER BY last_seen_at DESC, created_at DESC
      LIMIT 1
    `,
    )
    .bind(input.tenantId, input.ruleId)
    .first<LtiResourceLinkPlacementRow>();

  return row === null ? null : mapLtiResourceLinkPlacementRow(row);
};

export const listLtiResourceLinkPlacementsForRule = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    ruleId: string;
  },
): Promise<LtiResourceLinkPlacementRecord[]> => {
  const result = await db
    .prepare(
      `
      SELECT
        ${ltiResourceLinkPlacementSelectColumns()}
      FROM lti_resource_link_placements
      WHERE tenant_id = ?
        AND rule_id = ?
      ORDER BY last_seen_at DESC, created_at DESC, id DESC
    `,
    )
    .bind(input.tenantId, input.ruleId)
    .all<LtiResourceLinkPlacementRow>();

  return result.results.map((row) => mapLtiResourceLinkPlacementRow(row));
};

/** Resolves whether linked rules currently point to an active version. */
export const listLtiResourceLinkPlacementRuleStates = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    ruleIds: readonly string[];
  },
): Promise<LtiResourceLinkPlacementRuleState[]> => {
  const ruleIds = Array.from(new Set(input.ruleIds.filter((ruleId) => ruleId.length > 0)));

  if (ruleIds.length === 0) {
    return [];
  }

  const placeholders = ruleIds.map(() => "?").join(", ");
  const result = await db
    .prepare(
      `
      SELECT
        rules.id AS ruleId,
        CASE WHEN active_version.status = 'active' THEN 1 ELSE 0 END AS isActive
      FROM badge_issuance_rules AS rules
      LEFT JOIN badge_issuance_rule_versions AS active_version
        ON active_version.tenant_id = rules.tenant_id
        AND active_version.rule_id = rules.id
        AND active_version.id = rules.active_version_id
      WHERE rules.tenant_id = ?
        AND rules.id IN (${placeholders})
    `,
    )
    .bind(input.tenantId, ...ruleIds)
    .all<{ ruleId: string; isActive: boolean | number }>();

  return result.results.map((row) => ({
    ruleId: row.ruleId,
    isActive: row.isActive === true || row.isActive === 1,
  }));
};

export const listLtiResourceLinkPlacementsForContext = async (
  db: SqlDatabase,
  input: ListLtiResourceLinkPlacementsForContextInput,
): Promise<LtiResourceLinkPlacementRecord[]> => {
  const normalizedIssuer = normalizeLtiIssuer(input.issuer);
  const statusClause = input.includeRetired === true ? "" : "AND status = 'active'";
  const result = await db
    .prepare(
      `
        SELECT
          ${ltiResourceLinkPlacementSelectColumns()}
        FROM lti_resource_link_placements
        WHERE tenant_id = ?
          AND issuer = ?
          AND client_id = ?
          AND deployment_id = ?
          AND context_id = ?
          ${statusClause}
        ORDER BY last_seen_at DESC, created_at DESC, id DESC
      `,
    )
    .bind(input.tenantId, normalizedIssuer, input.clientId, input.deploymentId, input.contextId)
    .all<LtiResourceLinkPlacementRow>();

  return result.results.map((row) => mapLtiResourceLinkPlacementRow(row));
};

/** Retires one tenant/rule-owned placement and records the real transition once. */
export const retireLtiResourceLinkPlacement = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    ruleId: string;
    placementId: string;
    actorUserId: string;
    actorRole: TenantMembershipRole;
  },
): Promise<RetireLtiResourceLinkPlacementResult> => {
  return runSqlTransaction(db, async (transactionDb) => {
    const row = await transactionDb
      .prepare(
        `
        SELECT
          ${ltiResourceLinkPlacementSelectColumns()}
        FROM lti_resource_link_placements
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
        LIMIT 1
        FOR UPDATE
      `,
      )
      .bind(input.tenantId, input.ruleId, input.placementId)
      .first<LtiResourceLinkPlacementRow>();

    if (row === null) {
      return { status: "not_found" };
    }

    const placement = mapLtiResourceLinkPlacementRow(row);

    if (placement.status === "retired") {
      return { status: "already_retired", placement };
    }

    const nowIso = new Date().toISOString();
    await transactionDb
      .prepare(
        `
        UPDATE lti_resource_link_placements
        SET status = 'retired',
            retired_at = ?,
            retired_by_user_id = ?,
            updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
          AND status = 'active'
      `,
      )
      .bind(nowIso, input.actorUserId, nowIso, input.tenantId, input.ruleId, input.placementId)
      .run();

    await createAuditLog(transactionDb, {
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      action: "lti.resource_link_placement_retired",
      targetType: "lti_resource_link_placement",
      targetId: placement.id,
      metadata: {
        role: input.actorRole,
        ruleId: placement.ruleId,
        contextId: placement.contextId,
        previousStatus: placement.status,
      },
    });

    const retired = await transactionDb
      .prepare(
        `
        SELECT
          ${ltiResourceLinkPlacementSelectColumns()}
        FROM lti_resource_link_placements
        WHERE tenant_id = ?
          AND id = ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, input.placementId)
      .first<LtiResourceLinkPlacementRow>();

    if (retired === null) {
      throw new Error(`Unable to retire LTI resource-link placement "${input.placementId}"`);
    }

    return {
      status: "retired",
      placement: mapLtiResourceLinkPlacementRow(retired),
    };
  });
};
