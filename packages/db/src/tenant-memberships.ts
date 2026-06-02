import { findTenantOrgUnitById } from "./tenant-org-units";
import type { SqlDatabase, SqlQueryResult, SqlRunResult } from "./tenant-scope";
import type { TenantPlanTier } from "./tenants";

export type TenantMembershipRole = "owner" | "admin" | "issuer" | "viewer";

export const TENANT_MEMBERSHIP_ROLE_RANK: Record<TenantMembershipRole, number> = {
  viewer: 0,
  issuer: 1,
  admin: 2,
  owner: 3,
};

export const isTenantMembershipRole = (value: unknown): value is TenantMembershipRole => {
  return (
    typeof value === "string" &&
    Object.prototype.hasOwnProperty.call(TENANT_MEMBERSHIP_ROLE_RANK, value)
  );
};

export const tenantMembershipRoleSatisfiesMinimumRole = (
  actorRole: TenantMembershipRole,
  requiredRole: TenantMembershipRole,
): boolean => {
  return TENANT_MEMBERSHIP_ROLE_RANK[actorRole] >= TENANT_MEMBERSHIP_ROLE_RANK[requiredRole];
};

export interface TenantMembershipRecord {
  tenantId: string;
  userId: string;
  role: TenantMembershipRole;
  createdAt: string;
  updatedAt: string;
}

export interface TenantMemberRecord extends TenantMembershipRecord {
  email: string;
}

export interface TenantMembershipRoleCounts {
  owner: number;
  admin: number;
  issuer: number;
  viewer: number;
}

export interface AccessibleTenantContextRecord {
  tenantId: string;
  tenantSlug: string;
  tenantDisplayName: string;
  tenantPlanTier: TenantPlanTier;
  membershipRole: TenantMembershipRole;
}

export interface UpsertTenantMembershipRoleInput {
  tenantId: string;
  userId: string;
  role: TenantMembershipRole;
}

export interface UpsertTenantMembershipRoleResult {
  membership: TenantMembershipRecord;
  previousRole: TenantMembershipRole | null;
  changed: boolean;
}

export interface EnsureTenantMembershipResult {
  membership: TenantMembershipRecord;
  created: boolean;
}

export type TenantMembershipOrgUnitScopeRole = "admin" | "issuer" | "viewer";

export interface TenantMembershipOrgUnitScopeRecord {
  tenantId: string;
  userId: string;
  orgUnitId: string;
  role: TenantMembershipOrgUnitScopeRole;
  createdByUserId: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertTenantMembershipOrgUnitScopeInput {
  tenantId: string;
  userId: string;
  orgUnitId: string;
  role: TenantMembershipOrgUnitScopeRole;
  createdByUserId?: string | undefined;
}

export interface UpsertTenantMembershipOrgUnitScopeResult {
  scope: TenantMembershipOrgUnitScopeRecord;
  previousRole: TenantMembershipOrgUnitScopeRole | null;
  changed: boolean;
}

export interface ListTenantMembershipOrgUnitScopesInput {
  tenantId: string;
  userId?: string | undefined;
}

export interface RemoveTenantMembershipOrgUnitScopeInput {
  tenantId: string;
  userId: string;
  orgUnitId: string;
}

export interface CheckTenantMembershipOrgUnitAccessInput {
  tenantId: string;
  userId: string;
  orgUnitId: string;
  requiredRole: TenantMembershipOrgUnitScopeRole;
}

interface TenantMembershipRow {
  tenantId: string;
  userId: string;
  role: TenantMembershipRole;
  createdAt: string;
  updatedAt: string;
}

interface TenantMemberRow extends TenantMembershipRow {
  email: string;
}

interface TenantMembershipRoleCountRow {
  role: TenantMembershipRole;
  totalCount: number | string;
}

interface AccessibleTenantContextRow {
  tenantId: string;
  tenantSlug: string;
  tenantDisplayName: string;
  tenantPlanTier: TenantPlanTier;
  membershipRole: TenantMembershipRole;
}

interface TenantMembershipOrgUnitScopeRow {
  tenantId: string;
  userId: string;
  orgUnitId: string;
  role: TenantMembershipOrgUnitScopeRole;
  createdByUserId: string | null;
  createdAt: string;
  updatedAt: string;
}

const TENANT_MEMBERSHIP_ORG_UNIT_SCOPE_ROLE_PRIORITY: Record<
  TenantMembershipOrgUnitScopeRole,
  number
> = {
  viewer: 1,
  issuer: 2,
  admin: 3,
};

export const ensureTenantMembership = async (
  db: SqlDatabase,
  tenantId: string,
  userId: string,
): Promise<EnsureTenantMembershipResult> => {
  const existing = await findTenantMembership(db, tenantId, userId);

  if (existing !== null) {
    return {
      membership: existing,
      created: false,
    };
  }

  const upserted = await upsertTenantMembershipRole(db, {
    tenantId,
    userId,
    role: "viewer",
  });

  return {
    membership: upserted.membership,
    created: true,
  };
};

export const findTenantMembership = async (
  db: SqlDatabase,
  tenantId: string,
  userId: string,
): Promise<TenantMembershipRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        tenant_id AS tenantId,
        user_id AS userId,
        role,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM memberships
      WHERE tenant_id = ?
        AND user_id = ?
      LIMIT 1
    `,
    )
    .bind(tenantId, userId)
    .first<TenantMembershipRow>();

  if (row === null) {
    return null;
  }

  return mapTenantMembershipRow(row);
};

export const listTenantMembers = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<TenantMemberRecord[]> => {
  const result = await db
    .prepare(
      `
      SELECT
        memberships.tenant_id AS tenantId,
        memberships.user_id AS userId,
        users.email AS email,
        memberships.role AS role,
        memberships.created_at AS createdAt,
        memberships.updated_at AS updatedAt
      FROM memberships
      INNER JOIN users
        ON users.id = memberships.user_id
      WHERE memberships.tenant_id = ?
      ORDER BY
        CASE memberships.role
          WHEN 'owner' THEN 0
          WHEN 'admin' THEN 1
          WHEN 'issuer' THEN 2
          ELSE 3
        END,
        lower(users.email),
        memberships.user_id
    `,
    )
    .bind(tenantId)
    .all<TenantMemberRow>();

  return result.results.map(mapTenantMemberRow);
};

export const countTenantMembershipsByRole = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<TenantMembershipRoleCounts> => {
  const result = await db
    .prepare(
      `
      SELECT
        role,
        COUNT(*) AS totalCount
      FROM memberships
      WHERE tenant_id = ?
      GROUP BY role
    `,
    )
    .bind(tenantId)
    .all<TenantMembershipRoleCountRow>();

  const counts: TenantMembershipRoleCounts = {
    owner: 0,
    admin: 0,
    issuer: 0,
    viewer: 0,
  };

  for (const row of result.results) {
    const totalCount = Number.parseInt(String(row.totalCount), 10);
    counts[row.role] = Number.isFinite(totalCount) ? totalCount : 0;
  }

  return counts;
};

export const removeTenantMembership = async (
  db: SqlDatabase,
  tenantId: string,
  userId: string,
): Promise<boolean> => {
  const result = await db
    .prepare(
      `
      DELETE FROM memberships
      WHERE tenant_id = ?
        AND user_id = ?
    `,
    )
    .bind(tenantId, userId)
    .run();

  return (result.meta.rowsWritten ?? 0) > 0;
};

export const listAccessibleTenantContextsForUser = async (
  db: SqlDatabase,
  userId: string,
): Promise<AccessibleTenantContextRecord[]> => {
  const result = await db
    .prepare(
      `
      SELECT
        memberships.tenant_id AS tenantId,
        tenants.slug AS tenantSlug,
        tenants.display_name AS tenantDisplayName,
        tenants.plan_tier AS tenantPlanTier,
        memberships.role AS membershipRole
      FROM memberships
      INNER JOIN tenants
        ON tenants.id = memberships.tenant_id
      WHERE memberships.user_id = ?
        AND tenants.is_active = 1
      ORDER BY lower(tenants.display_name), tenants.slug, memberships.tenant_id
    `,
    )
    .bind(userId)
    .all<AccessibleTenantContextRow>();

  return result.results.map(mapAccessibleTenantContextRow);
};

export const upsertTenantMembershipRole = async (
  db: SqlDatabase,
  input: UpsertTenantMembershipRoleInput,
): Promise<UpsertTenantMembershipRoleResult> => {
  const existing = await findTenantMembership(db, input.tenantId, input.userId);
  const nowIso = new Date().toISOString();

  await db
    .prepare(
      `
      INSERT INTO memberships (
        tenant_id,
        user_id,
        role,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT (tenant_id, user_id)
      DO UPDATE SET
        role = excluded.role,
        updated_at = excluded.updated_at
    `,
    )
    .bind(input.tenantId, input.userId, input.role, nowIso, nowIso)
    .run();

  const membership = await findTenantMembership(db, input.tenantId, input.userId);

  if (membership === null) {
    throw new Error(
      `Unable to upsert membership role for tenant "${input.tenantId}" and user "${input.userId}"`,
    );
  }

  return {
    membership,
    previousRole: existing?.role ?? null,
    changed: existing?.role !== membership.role,
  };
};

const mapTenantMembershipRow = (row: TenantMembershipRow): TenantMembershipRecord => {
  return {
    tenantId: row.tenantId,
    userId: row.userId,
    role: row.role,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapTenantMemberRow = (row: TenantMemberRow): TenantMemberRecord => {
  return {
    ...mapTenantMembershipRow(row),
    email: row.email,
  };
};

const mapAccessibleTenantContextRow = (
  row: AccessibleTenantContextRow,
): AccessibleTenantContextRecord => {
  return {
    tenantId: row.tenantId,
    tenantSlug: row.tenantSlug,
    tenantDisplayName: row.tenantDisplayName,
    tenantPlanTier: row.tenantPlanTier,
    membershipRole: row.membershipRole,
  };
};

const mapTenantMembershipOrgUnitScopeRow = (
  row: TenantMembershipOrgUnitScopeRow,
): TenantMembershipOrgUnitScopeRecord => {
  return {
    tenantId: row.tenantId,
    userId: row.userId,
    orgUnitId: row.orgUnitId,
    role: row.role,
    createdByUserId: row.createdByUserId,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const findTenantMembershipOrgUnitScope = async (
  db: SqlDatabase,
  tenantId: string,
  userId: string,
  orgUnitId: string,
): Promise<TenantMembershipOrgUnitScopeRecord | null> => {
  const findStatement = (): Promise<TenantMembershipOrgUnitScopeRow | null> =>
    db
      .prepare(
        `
        SELECT
          tenant_id AS tenantId,
          user_id AS userId,
          org_unit_id AS orgUnitId,
          role,
          created_by_user_id AS createdByUserId,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM tenant_membership_org_unit_scopes
        WHERE tenant_id = ?
          AND user_id = ?
          AND org_unit_id = ?
        LIMIT 1
      `,
      )
      .bind(tenantId, userId, orgUnitId)
      .first<TenantMembershipOrgUnitScopeRow>();

  const row = await findStatement();

  return row === null ? null : mapTenantMembershipOrgUnitScopeRow(row);
};

export const upsertTenantMembershipOrgUnitScope = async (
  db: SqlDatabase,
  input: UpsertTenantMembershipOrgUnitScopeInput,
): Promise<UpsertTenantMembershipOrgUnitScopeResult> => {
  const membership = await findTenantMembership(db, input.tenantId, input.userId);

  if (membership === null) {
    throw new Error(`Membership not found for tenant ${input.tenantId} and user ${input.userId}`);
  }

  const orgUnit = await findTenantOrgUnitById(db, input.tenantId, input.orgUnitId);

  if (orgUnit === null) {
    throw new Error(`Org unit ${input.orgUnitId} not found for tenant ${input.tenantId}`);
  }

  const previous = await findTenantMembershipOrgUnitScope(
    db,
    input.tenantId,
    input.userId,
    input.orgUnitId,
  );
  const nowIso = new Date().toISOString();

  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO tenant_membership_org_unit_scopes (
          tenant_id,
          user_id,
          org_unit_id,
          role,
          created_by_user_id,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (tenant_id, user_id, org_unit_id)
        DO UPDATE SET
          role = excluded.role,
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        input.tenantId,
        input.userId,
        input.orgUnitId,
        input.role,
        input.createdByUserId ?? null,
        nowIso,
        nowIso,
      )
      .run();

  await upsertStatement();

  const scope = await findTenantMembershipOrgUnitScope(
    db,
    input.tenantId,
    input.userId,
    input.orgUnitId,
  );

  if (scope === null) {
    throw new Error(
      `Unable to upsert org-unit scope for tenant ${input.tenantId}, user ${input.userId}, org unit ${input.orgUnitId}`,
    );
  }

  return {
    scope,
    previousRole: previous?.role ?? null,
    changed: previous?.role !== scope.role,
  };
};

export const listTenantMembershipOrgUnitScopes = async (
  db: SqlDatabase,
  input: ListTenantMembershipOrgUnitScopesInput,
): Promise<TenantMembershipOrgUnitScopeRecord[]> => {
  const query =
    input.userId === undefined
      ? `
        SELECT
          tenant_id AS tenantId,
          user_id AS userId,
          org_unit_id AS orgUnitId,
          role,
          created_by_user_id AS createdByUserId,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM tenant_membership_org_unit_scopes
        WHERE tenant_id = ?
        ORDER BY user_id ASC, org_unit_id ASC
      `
      : `
        SELECT
          tenant_id AS tenantId,
          user_id AS userId,
          org_unit_id AS orgUnitId,
          role,
          created_by_user_id AS createdByUserId,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM tenant_membership_org_unit_scopes
        WHERE tenant_id = ?
          AND user_id = ?
        ORDER BY org_unit_id ASC
      `;

  const listStatement = (): Promise<SqlQueryResult<TenantMembershipOrgUnitScopeRow>> =>
    input.userId === undefined
      ? db.prepare(query).bind(input.tenantId).all<TenantMembershipOrgUnitScopeRow>()
      : db.prepare(query).bind(input.tenantId, input.userId).all<TenantMembershipOrgUnitScopeRow>();

  const result = await listStatement();

  return result.results.map((row) => mapTenantMembershipOrgUnitScopeRow(row));
};

export const removeTenantMembershipOrgUnitScope = async (
  db: SqlDatabase,
  input: RemoveTenantMembershipOrgUnitScopeInput,
): Promise<boolean> => {
  const deleteStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        DELETE FROM tenant_membership_org_unit_scopes
        WHERE tenant_id = ?
          AND user_id = ?
          AND org_unit_id = ?
      `,
      )
      .bind(input.tenantId, input.userId, input.orgUnitId)
      .run();

  const result = await deleteStatement();

  return (result.meta.rowsWritten ?? 0) > 0;
};

export const hasTenantMembershipOrgUnitScopeAssignments = async (
  db: SqlDatabase,
  tenantId: string,
  userId: string,
): Promise<boolean> => {
  const countStatement = (): Promise<{ totalCount: number | string } | null> =>
    db
      .prepare(
        `
        SELECT COUNT(*) AS totalCount
        FROM tenant_membership_org_unit_scopes
        WHERE tenant_id = ?
          AND user_id = ?
      `,
      )
      .bind(tenantId, userId)
      .first<{ totalCount: number | string }>();

  const row = await countStatement();

  const totalCount = Number.parseInt(String(row?.totalCount ?? 0), 10);
  return Number.isFinite(totalCount) && totalCount > 0;
};

export const hasTenantMembershipOrgUnitAccess = async (
  db: SqlDatabase,
  input: CheckTenantMembershipOrgUnitAccessInput,
): Promise<boolean> => {
  const requiredRolePriority = TENANT_MEMBERSHIP_ORG_UNIT_SCOPE_ROLE_PRIORITY[input.requiredRole];
  const accessStatement = (): Promise<{ orgUnitId: string } | null> =>
    db
      .prepare(
        `
        WITH RECURSIVE org_ancestors AS (
          SELECT id, parent_org_unit_id AS parentOrgUnitId, 0 AS depth
          FROM tenant_org_units
          WHERE tenant_id = ?
            AND id = ?

          UNION ALL

          SELECT parent.id, parent.parent_org_unit_id AS parentOrgUnitId, org_ancestors.depth + 1
          FROM tenant_org_units parent
          INNER JOIN org_ancestors
            ON org_ancestors.parentOrgUnitId = parent.id
          WHERE parent.tenant_id = ?
        )
        SELECT
          scopes.org_unit_id AS orgUnitId
        FROM tenant_membership_org_unit_scopes scopes
        INNER JOIN org_ancestors
          ON org_ancestors.id = scopes.org_unit_id
        WHERE scopes.tenant_id = ?
          AND scopes.user_id = ?
          AND CASE scopes.role
                WHEN 'admin' THEN 3
                WHEN 'issuer' THEN 2
                ELSE 1
              END >= ?
        ORDER BY
          CASE scopes.role
            WHEN 'admin' THEN 3
            WHEN 'issuer' THEN 2
            ELSE 1
          END DESC,
          org_ancestors.depth ASC
        LIMIT 1
      `,
      )
      .bind(
        input.tenantId,
        input.orgUnitId,
        input.tenantId,
        input.tenantId,
        input.userId,
        requiredRolePriority,
      )
      .first<{ orgUnitId: string }>();

  const row = await accessStatement();

  return row !== null;
};
