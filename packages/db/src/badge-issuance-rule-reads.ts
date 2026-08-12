import type { SqlDatabase, SqlQueryResult } from "./tenant-scope";
import {
  BADGE_RULE_LIST_ORG_UNIT_SCOPE_ROLES,
  listTenantMembershipOrgUnitScopes,
  type TenantMembershipRole,
} from "./tenant-memberships";
import { buildScopedDescendantsCte } from "./tenant-org-unit-hierarchy-sql.js";
import type {
  BadgeIssuanceRuleLmsProviderKind,
  BadgeIssuanceRuleRecord,
  ListBadgeIssuanceRulesInput,
} from "./badge-issuance-rule-types.js";

interface BadgeIssuanceRuleRow {
  id: string;
  tenantId: string;
  name: string;
  description: string | null;
  badgeTemplateId: string;
  orgUnitId: string;
  ownerOrgUnitId: string;
  lmsProviderKind: BadgeIssuanceRuleLmsProviderKind;
  lmsConnectionId: string | null;
  activeVersionId: string | null;
  createdByUserId: string | null;
  createdAt: string;
  updatedAt: string;
}
const BADGE_ISSUANCE_RULE_SELECT_COLUMNS = `
  id,
  tenant_id AS tenantId,
  name,
  description,
  badge_template_id AS badgeTemplateId,
  org_unit_id AS orgUnitId,
  owner_org_unit_id AS ownerOrgUnitId,
  lms_provider_kind AS lmsProviderKind,
  lms_connection_id AS lmsConnectionId,
  active_version_id AS activeVersionId,
  created_by_user_id AS createdByUserId,
  created_at AS createdAt,
  updated_at AS updatedAt
`;
const mapBadgeIssuanceRuleRow = (row: BadgeIssuanceRuleRow): BadgeIssuanceRuleRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    name: row.name,
    description: row.description,
    badgeTemplateId: row.badgeTemplateId,
    orgUnitId: row.orgUnitId,
    ownerOrgUnitId: row.ownerOrgUnitId,
    lmsProviderKind: row.lmsProviderKind,
    lmsConnectionId: row.lmsConnectionId,
    activeVersionId: row.activeVersionId,
    createdByUserId: row.createdByUserId,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};
const listBadgeIssuanceRulesByOrgUnitIds = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly orgUnitIds: readonly string[];
  },
): Promise<BadgeIssuanceRuleRecord[]> => {
  if (input.orgUnitIds.length === 0) {
    return [];
  }

  const placeholders = input.orgUnitIds.map(() => "?").join(", ");
  const result = await db
    .prepare(
      `
      SELECT
        ${BADGE_ISSUANCE_RULE_SELECT_COLUMNS}
      FROM badge_issuance_rules
      WHERE tenant_id = ?
        AND org_unit_id IN (${placeholders})
      ORDER BY created_at DESC, id DESC
    `,
    )
    .bind(input.tenantId, ...input.orgUnitIds)
    .all<BadgeIssuanceRuleRow>();

  return result.results.map((row) => mapBadgeIssuanceRuleRow(row));
};

const listBadgeIssuanceRulesByDescendantRoots = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly rootOrgUnitIds: readonly string[];
  },
): Promise<BadgeIssuanceRuleRecord[]> => {
  if (input.rootOrgUnitIds.length === 0) {
    return [];
  }

  const rootValues = input.rootOrgUnitIds.map(() => "(?)").join(", ");
  const result = await db
    .prepare(
      `
      ${buildScopedDescendantsCte(rootValues)}
      SELECT
        ${BADGE_ISSUANCE_RULE_SELECT_COLUMNS}
      FROM badge_issuance_rules
      WHERE tenant_id = ?
        AND org_unit_id IN (
          SELECT orgUnitId
          FROM scoped_descendants
        )
      ORDER BY created_at DESC, id DESC
    `,
    )
    .bind(...input.rootOrgUnitIds, input.tenantId, input.tenantId, input.tenantId)
    .all<BadgeIssuanceRuleRow>();

  return result.results.map((row) => mapBadgeIssuanceRuleRow(row));
};

export const resolveListBadgeIssuanceRulesInput = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly userId: string;
    readonly membershipRole: TenantMembershipRole;
  },
): Promise<ListBadgeIssuanceRulesInput> => {
  if (input.membershipRole === "owner" || input.membershipRole === "admin") {
    return { tenantId: input.tenantId };
  }

  const scopes = await listTenantMembershipOrgUnitScopes(db, {
    tenantId: input.tenantId,
    userId: input.userId,
  });

  if (scopes.length === 0) {
    return {
      tenantId: input.tenantId,
      scope: {
        type: "descendants",
        rootOrgUnitIds: [],
      },
    };
  }

  const allowedScopeRoles = BADGE_RULE_LIST_ORG_UNIT_SCOPE_ROLES[input.membershipRole];
  const rootOrgUnitIds = Array.from(
    new Set(
      scopes
        .filter((scope) => allowedScopeRoles.includes(scope.role))
        .map((scope) => scope.orgUnitId),
    ),
  ).sort((left, right) => left.localeCompare(right));

  if (rootOrgUnitIds.length === 0) {
    return {
      tenantId: input.tenantId,
      scope: {
        type: "descendants",
        rootOrgUnitIds: [],
      },
    };
  }

  return {
    tenantId: input.tenantId,
    scope: {
      type: "descendants",
      rootOrgUnitIds,
    },
  };
};

export const findBadgeIssuanceRuleById = async (
  db: SqlDatabase,
  tenantId: string,
  ruleId: string,
): Promise<BadgeIssuanceRuleRecord | null> => {
  const lookupStatement = (): Promise<BadgeIssuanceRuleRow | null> =>
    db
      .prepare(
        `
        SELECT
          ${BADGE_ISSUANCE_RULE_SELECT_COLUMNS}
        FROM badge_issuance_rules
        WHERE tenant_id = ?
          AND id = ?
        LIMIT 1
      `,
      )
      .bind(tenantId, ruleId)
      .first<BadgeIssuanceRuleRow>();

  const row = await lookupStatement();

  return row === null ? null : mapBadgeIssuanceRuleRow(row);
};

export const listBadgeIssuanceRules = async (
  db: SqlDatabase,
  input: ListBadgeIssuanceRulesInput,
): Promise<BadgeIssuanceRuleRecord[]> => {
  if (input.scope?.type === "org_unit") {
    return listBadgeIssuanceRulesByOrgUnitIds(db, {
      tenantId: input.tenantId,
      orgUnitIds: [input.scope.orgUnitId],
    });
  }

  if (input.scope?.type === "descendants") {
    return listBadgeIssuanceRulesByDescendantRoots(db, {
      tenantId: input.tenantId,
      rootOrgUnitIds: input.scope.rootOrgUnitIds,
    });
  }

  const listStatement = (): Promise<SqlQueryResult<BadgeIssuanceRuleRow>> =>
    db
      .prepare(
        `
        SELECT
          ${BADGE_ISSUANCE_RULE_SELECT_COLUMNS}
        FROM badge_issuance_rules
        WHERE tenant_id = ?
        ORDER BY created_at DESC, id DESC
      `,
      )
      .bind(input.tenantId)
      .all<BadgeIssuanceRuleRow>();

  const result = await listStatement();

  return result.results.map((row) => mapBadgeIssuanceRuleRow(row));
};
