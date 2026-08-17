import type { SqlDatabase } from "./tenant-scope";
import { ensureTenantDefaultBadgeRuleApprovalPolicy } from "./badge-rule-approval-policies";

export type TenantPlanTier = "free" | "team" | "institution" | "enterprise";

export interface TenantRecord {
  id: string;
  slug: string;
  displayName: string;
  planTier: TenantPlanTier;
  issuerDomain: string;
  didWeb: string;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertTenantInput {
  id: string;
  slug: string;
  displayName: string;
  planTier: TenantPlanTier;
  issuerDomain: string;
  didWeb: string;
  isActive?: boolean | undefined;
}

interface TenantRow {
  id: string;
  slug: string;
  displayName: string;
  planTier: TenantPlanTier;
  issuerDomain: string;
  didWeb: string;
  isActive: number | boolean;
  createdAt: string;
  updatedAt: string;
}

const mapTenantRow = (row: TenantRow): TenantRecord => {
  return {
    id: row.id,
    slug: row.slug,
    displayName: row.displayName,
    planTier: row.planTier,
    issuerDomain: row.issuerDomain,
    didWeb: row.didWeb,
    isActive: row.isActive === 1 || row.isActive === true,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

export const upsertTenant = async (
  db: SqlDatabase,
  input: UpsertTenantInput,
): Promise<TenantRecord> => {
  const nowIso = new Date().toISOString();
  const isActive = input.isActive ?? true;

  await db
    .prepare(
      `
      INSERT INTO tenants (
        id,
        slug,
        display_name,
        plan_tier,
        issuer_domain,
        did_web,
        is_active,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (id)
      DO UPDATE SET
        slug = excluded.slug,
        display_name = excluded.display_name,
        plan_tier = excluded.plan_tier,
        issuer_domain = excluded.issuer_domain,
        did_web = excluded.did_web,
        is_active = excluded.is_active,
        updated_at = excluded.updated_at
    `,
    )
    .bind(
      input.id,
      input.slug,
      input.displayName,
      input.planTier,
      input.issuerDomain,
      input.didWeb,
      isActive ? 1 : 0,
      nowIso,
      nowIso,
    )
    .run();

  const row = await db
    .prepare(
      `
      SELECT
        id,
        slug,
        display_name AS displayName,
        plan_tier AS planTier,
        issuer_domain AS issuerDomain,
        did_web AS didWeb,
        is_active AS isActive,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM tenants
      WHERE id = ?
      LIMIT 1
    `,
    )
    .bind(input.id)
    .first<TenantRow>();

  if (row === null) {
    throw new Error(`Unable to upsert tenant "${input.id}"`);
  }

  await ensureTenantDefaultBadgeRuleApprovalPolicy(db, input.id);

  return mapTenantRow(row);
};

export const findTenantById = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<TenantRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        id,
        slug,
        display_name AS displayName,
        plan_tier AS planTier,
        issuer_domain AS issuerDomain,
        did_web AS didWeb,
        is_active AS isActive,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM tenants
      WHERE id = ?
      LIMIT 1
    `,
    )
    .bind(tenantId)
    .first<TenantRow>();

  return row === null ? null : mapTenantRow(row);
};

export const listActiveTenants = async (db: SqlDatabase): Promise<TenantRecord[]> => {
  const result = await db
    .prepare(
      `
      SELECT
        id,
        slug,
        display_name AS displayName,
        plan_tier AS planTier,
        issuer_domain AS issuerDomain,
        did_web AS didWeb,
        is_active AS isActive,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM tenants
      WHERE is_active = 1
      ORDER BY created_at ASC, id ASC
    `,
    )
    .all<TenantRow>();

  return result.results.map(mapTenantRow);
};
