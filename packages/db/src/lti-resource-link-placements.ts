import { normalizeLtiIssuer } from "./lti";
import type { SqlDatabase, SqlRunResult } from "./tenant-scope";

export interface LtiResourceLinkPlacementRecord {
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
  createdAt: string;
  updatedAt: string;
}

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
  createdAt: string;
  updatedAt: string;
}

const mapLtiResourceLinkPlacementRow = (
  row: LtiResourceLinkPlacementRow,
): LtiResourceLinkPlacementRecord => {
  return {
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
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

export const upsertLtiResourceLinkPlacement = async (
  db: SqlDatabase,
  input: UpsertLtiResourceLinkPlacementInput,
): Promise<LtiResourceLinkPlacementRecord> => {
  const nowIso = new Date().toISOString();
  const id = input.id ?? `lti_place_${crypto.randomUUID().replace(/-/g, "")}`;
  const normalizedIssuer = normalizeLtiIssuer(input.issuer);

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
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (issuer, client_id, deployment_id, resource_link_id)
        DO UPDATE SET
          tenant_id = excluded.tenant_id,
          context_id = excluded.context_id,
          badge_template_id = excluded.badge_template_id,
          rule_id = COALESCE(excluded.rule_id, lti_resource_link_placements.rule_id),
          created_by_user_id = COALESCE(excluded.created_by_user_id, lti_resource_link_placements.created_by_user_id),
          updated_at = excluded.updated_at
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

  return placement;
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
          created_at AS createdAt,
          updated_at AS updatedAt
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
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM lti_resource_link_placements
      WHERE tenant_id = ?
        AND rule_id = ?
      ORDER BY updated_at DESC, created_at DESC
      LIMIT 1
    `,
    )
    .bind(input.tenantId, input.ruleId)
    .first<LtiResourceLinkPlacementRow>();

  return row === null ? null : mapLtiResourceLinkPlacementRow(row);
};

export const listLtiResourceLinkPlacementsForContext = async (
  db: SqlDatabase,
  input: ListLtiResourceLinkPlacementsForContextInput,
): Promise<LtiResourceLinkPlacementRecord[]> => {
  const normalizedIssuer = normalizeLtiIssuer(input.issuer);
  const result = await db
    .prepare(
      `
        SELECT
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
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM lti_resource_link_placements
        WHERE tenant_id = ?
          AND issuer = ?
          AND client_id = ?
          AND deployment_id = ?
          AND context_id = ?
        ORDER BY created_at DESC, id DESC
      `,
    )
    .bind(input.tenantId, normalizedIssuer, input.clientId, input.deploymentId, input.contextId)
    .all<LtiResourceLinkPlacementRow>();

  return result.results.map((row) => mapLtiResourceLinkPlacementRow(row));
};
