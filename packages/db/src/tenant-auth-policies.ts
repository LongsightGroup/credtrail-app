import { createPrefixedId } from "./shared-helpers";
import type { SqlDatabase } from "./tenant-scope";
export * from "./tenant-break-glass-accounts";
export * from "./tenant-canvas-gradebook-integrations";

export type TenantLoginMode = "local" | "hybrid" | "sso_required";

export type TenantAuthPolicyEnforceForRoles = "all_users" | "admins_only";

export interface TenantAuthPolicyRecord {
  tenantId: string;
  loginMode: TenantLoginMode;
  breakGlassEnabled: boolean;
  localMfaRequired: boolean;
  defaultProviderId: string | null;
  enforceForRoles: TenantAuthPolicyEnforceForRoles;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertTenantAuthPolicyInput {
  tenantId: string;
  loginMode: TenantLoginMode;
  breakGlassEnabled?: boolean | undefined;
  localMfaRequired?: boolean | undefined;
  defaultProviderId?: string | null | undefined;
  enforceForRoles?: TenantAuthPolicyEnforceForRoles | undefined;
}

export type TenantAuthProviderProtocol = "oidc";

export interface TenantAuthProviderRecord {
  id: string;
  tenantId: string;
  protocol: TenantAuthProviderProtocol;
  label: string;
  enabled: boolean;
  isDefault: boolean;
  configJson: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateTenantAuthProviderInput {
  id?: string | undefined;
  tenantId: string;
  protocol: TenantAuthProviderProtocol;
  label: string;
  enabled?: boolean | undefined;
  isDefault?: boolean | undefined;
  configJson: string;
}

export interface UpdateTenantAuthProviderInput {
  tenantId: string;
  providerId: string;
  protocol: TenantAuthProviderProtocol;
  label: string;
  enabled?: boolean | undefined;
  isDefault?: boolean | undefined;
  configJson: string;
}

interface TenantAuthPolicyRow {
  tenantId: string;
  loginMode: TenantLoginMode;
  breakGlassEnabled: number | boolean;
  localMfaRequired: number | boolean;
  defaultProviderId: string | null;
  enforceForRoles: TenantAuthPolicyEnforceForRoles;
  createdAt: string;
  updatedAt: string;
}

interface TenantAuthProviderRow {
  id: string;
  tenantId: string;
  protocol: TenantAuthProviderProtocol;
  label: string;
  enabled: number | boolean;
  isDefault: number | boolean;
  configJson: string;
  createdAt: string;
  updatedAt: string;
}

const mapTenantAuthPolicyRow = (row: TenantAuthPolicyRow): TenantAuthPolicyRecord => {
  return {
    tenantId: row.tenantId,
    loginMode: row.loginMode,
    breakGlassEnabled: row.breakGlassEnabled === 1 || row.breakGlassEnabled === true,
    localMfaRequired: row.localMfaRequired === 1 || row.localMfaRequired === true,
    defaultProviderId: row.defaultProviderId,
    enforceForRoles: "all_users",
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapTenantAuthProviderRow = (row: TenantAuthProviderRow): TenantAuthProviderRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    protocol: row.protocol,
    label: row.label,
    enabled: row.enabled === 1 || row.enabled === true,
    isDefault: row.isDefault === 1 || row.isDefault === true,
    configJson: row.configJson,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const buildDefaultTenantAuthPolicy = (
  tenantId: string,
  nowIso: string = new Date().toISOString(),
): TenantAuthPolicyRecord => {
  return {
    tenantId,
    loginMode: "local",
    breakGlassEnabled: false,
    localMfaRequired: false,
    defaultProviderId: null,
    enforceForRoles: "all_users",
    createdAt: nowIso,
    updatedAt: nowIso,
  };
};

export const findTenantAuthPolicy = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<TenantAuthPolicyRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        tenant_id AS tenantId,
        login_mode AS loginMode,
        break_glass_enabled AS breakGlassEnabled,
        local_mfa_required AS localMfaRequired,
        default_provider_id AS defaultProviderId,
        enforce_for_roles AS enforceForRoles,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM tenant_auth_policies
      WHERE tenant_id = ?
      LIMIT 1
    `,
    )
    .bind(tenantId)
    .first<TenantAuthPolicyRow>();

  return row === null ? null : mapTenantAuthPolicyRow(row);
};

export const resolveTenantAuthPolicy = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<TenantAuthPolicyRecord> => {
  const policy = await findTenantAuthPolicy(db, tenantId);
  return policy ?? buildDefaultTenantAuthPolicy(tenantId);
};

export const upsertTenantAuthPolicy = async (
  db: SqlDatabase,
  input: UpsertTenantAuthPolicyInput,
): Promise<TenantAuthPolicyRecord> => {
  const nowIso = new Date().toISOString();
  await db
    .prepare(
      `
      INSERT INTO tenant_auth_policies (
        tenant_id,
        login_mode,
        break_glass_enabled,
        local_mfa_required,
        default_provider_id,
        enforce_for_roles,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (tenant_id)
      DO UPDATE SET
        login_mode = excluded.login_mode,
        break_glass_enabled = excluded.break_glass_enabled,
        local_mfa_required = excluded.local_mfa_required,
        default_provider_id = excluded.default_provider_id,
        enforce_for_roles = excluded.enforce_for_roles,
        updated_at = excluded.updated_at
    `,
    )
    .bind(
      input.tenantId,
      input.loginMode,
      input.breakGlassEnabled === true ? 1 : 0,
      input.localMfaRequired === true ? 1 : 0,
      input.defaultProviderId ?? null,
      "all_users",
      nowIso,
      nowIso,
    )
    .run();

  const policy = await findTenantAuthPolicy(db, input.tenantId);

  if (policy === null) {
    throw new Error(`Unable to upsert auth policy for tenant "${input.tenantId}"`);
  }

  return policy;
};

export const listTenantAuthProviders = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<TenantAuthProviderRecord[]> => {
  const result = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        protocol,
        label,
        enabled,
        is_default AS isDefault,
        config_json AS configJson,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM tenant_auth_providers
      WHERE tenant_id = ?
      ORDER BY is_default DESC, created_at ASC, id ASC
    `,
    )
    .bind(tenantId)
    .all<TenantAuthProviderRow>();

  return result.results.map((row) => mapTenantAuthProviderRow(row));
};

export const findTenantAuthProviderById = async (
  db: SqlDatabase,
  tenantId: string,
  providerId: string,
): Promise<TenantAuthProviderRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        protocol,
        label,
        enabled,
        is_default AS isDefault,
        config_json AS configJson,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM tenant_auth_providers
      WHERE tenant_id = ?
        AND id = ?
      LIMIT 1
    `,
    )
    .bind(tenantId, providerId)
    .first<TenantAuthProviderRow>();

  return row === null ? null : mapTenantAuthProviderRow(row);
};

export const createTenantAuthProvider = async (
  db: SqlDatabase,
  input: CreateTenantAuthProviderInput,
): Promise<TenantAuthProviderRecord> => {
  const id = input.id ?? createPrefixedId("tap");
  const nowIso = new Date().toISOString();
  const enabled = input.enabled ?? true;
  const isDefault = input.isDefault ?? false;

  if (isDefault) {
    await db
      .prepare(
        `
        UPDATE tenant_auth_providers
        SET
          is_default = 0,
          updated_at = ?
        WHERE tenant_id = ?
          AND is_default = 1
      `,
      )
      .bind(nowIso, input.tenantId)
      .run();
  }

  await db
    .prepare(
      `
      INSERT INTO tenant_auth_providers (
        id,
        tenant_id,
        protocol,
        label,
        enabled,
        is_default,
        config_json,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
    )
    .bind(
      id,
      input.tenantId,
      input.protocol,
      input.label,
      enabled ? 1 : 0,
      isDefault ? 1 : 0,
      input.configJson,
      nowIso,
      nowIso,
    )
    .run();

  const provider = await findTenantAuthProviderById(db, input.tenantId, id);

  if (provider === null) {
    throw new Error(`Unable to create auth provider "${id}"`);
  }

  return provider;
};

export const updateTenantAuthProvider = async (
  db: SqlDatabase,
  input: UpdateTenantAuthProviderInput,
): Promise<TenantAuthProviderRecord | null> => {
  const nowIso = new Date().toISOString();
  const enabled = input.enabled ?? true;
  const isDefault = input.isDefault ?? false;

  if (isDefault) {
    await db
      .prepare(
        `
        UPDATE tenant_auth_providers
        SET
          is_default = 0,
          updated_at = ?
        WHERE tenant_id = ?
          AND id <> ?
          AND is_default = 1
      `,
      )
      .bind(nowIso, input.tenantId, input.providerId)
      .run();
  }

  const result = await db
    .prepare(
      `
      UPDATE tenant_auth_providers
      SET
        protocol = ?,
        label = ?,
        enabled = ?,
        is_default = ?,
        config_json = ?,
        updated_at = ?
      WHERE tenant_id = ?
        AND id = ?
    `,
    )
    .bind(
      input.protocol,
      input.label,
      enabled ? 1 : 0,
      isDefault ? 1 : 0,
      input.configJson,
      nowIso,
      input.tenantId,
      input.providerId,
    )
    .run();

  if ((result.meta.rowsWritten ?? 0) === 0) {
    return null;
  }

  return findTenantAuthProviderById(db, input.tenantId, input.providerId);
};

export const deleteTenantAuthProvider = async (
  db: SqlDatabase,
  tenantId: string,
  providerId: string,
): Promise<boolean> => {
  const result = await db
    .prepare(
      `
      DELETE FROM tenant_auth_providers
      WHERE tenant_id = ?
        AND id = ?
    `,
    )
    .bind(tenantId, providerId)
    .run();

  if ((result.meta.rowsWritten ?? 0) === 0) {
    return false;
  }

  await db
    .prepare(
      `
      UPDATE tenant_auth_policies
      SET
        default_provider_id = NULL,
        updated_at = ?
      WHERE tenant_id = ?
        AND default_provider_id = ?
    `,
    )
    .bind(new Date().toISOString(), tenantId, providerId)
    .run();

  return true;
};
