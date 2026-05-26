import { createPrefixedId } from "./shared-helpers";
import type { SqlDatabase, SqlQueryResult, SqlRunResult } from "./tenant-scope";
export * from "./tenant-break-glass-accounts";
export * from "./tenant-canvas-gradebook-integrations";

export type TenantLoginMode = "local" | "hybrid" | "sso_required";

export type TenantAuthPolicyEnforceForRoles = "all_users" | "admins_only";

export const HOSTED_ENTERPRISE_OIDC_ONLY_ERROR =
  "Hosted enterprise sign-in currently supports OIDC providers only. Legacy SAML compatibility remains available for visibility and cleanup.";

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

export type TenantAuthProviderProtocol = "oidc" | "saml";

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

export interface TenantSsoSamlConfigurationRecord {
  tenantId: string;
  idpEntityId: string;
  ssoLoginUrl: string;
  idpCertificatePem: string;
  idpMetadataUrl: string | null;
  spEntityId: string;
  assertionConsumerServiceUrl: string;
  nameIdFormat: string | null;
  enforced: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertTenantSsoSamlConfigurationInput {
  tenantId: string;
  idpEntityId: string;
  ssoLoginUrl: string;
  idpCertificatePem: string;
  idpMetadataUrl?: string | undefined;
  spEntityId: string;
  assertionConsumerServiceUrl: string;
  nameIdFormat?: string | undefined;
  enforced?: boolean | undefined;
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

interface TenantSsoSamlConfigurationRow {
  tenantId: string;
  idpEntityId: string;
  ssoLoginUrl: string;
  idpCertificatePem: string;
  idpMetadataUrl: string | null;
  spEntityId: string;
  assertionConsumerServiceUrl: string;
  nameIdFormat: string | null;
  enforced: number | boolean;
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

const mapTenantSsoSamlConfigurationRow = (
  row: TenantSsoSamlConfigurationRow,
): TenantSsoSamlConfigurationRecord => {
  return {
    tenantId: row.tenantId,
    idpEntityId: row.idpEntityId,
    ssoLoginUrl: row.ssoLoginUrl,
    idpCertificatePem: row.idpCertificatePem,
    idpMetadataUrl: row.idpMetadataUrl,
    spEntityId: row.spEntityId,
    assertionConsumerServiceUrl: row.assertionConsumerServiceUrl,
    nameIdFormat: row.nameIdFormat,
    enforced: row.enforced === 1 || row.enforced === true,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const buildLegacyTenantAuthProviderId = (tenantId: string): string => {
  return `${tenantId}:provider:saml-default`;
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

const buildLegacyTenantAuthPolicy = (
  configuration: TenantSsoSamlConfigurationRecord,
): TenantAuthPolicyRecord => {
  return {
    tenantId: configuration.tenantId,
    loginMode: configuration.enforced ? "sso_required" : "hybrid",
    breakGlassEnabled: false,
    localMfaRequired: false,
    defaultProviderId: buildLegacyTenantAuthProviderId(configuration.tenantId),
    enforceForRoles: "all_users",
    createdAt: configuration.createdAt,
    updatedAt: configuration.updatedAt,
  };
};

const buildLegacyTenantAuthProvider = (
  configuration: TenantSsoSamlConfigurationRecord,
): TenantAuthProviderRecord => {
  return {
    id: buildLegacyTenantAuthProviderId(configuration.tenantId),
    tenantId: configuration.tenantId,
    protocol: "saml",
    label: "Legacy SAML (compatibility only)",
    enabled: true,
    isDefault: true,
    configJson: JSON.stringify({
      idpEntityId: configuration.idpEntityId,
      ssoLoginUrl: configuration.ssoLoginUrl,
      idpCertificatePem: configuration.idpCertificatePem,
      idpMetadataUrl: configuration.idpMetadataUrl,
      spEntityId: configuration.spEntityId,
      assertionConsumerServiceUrl: configuration.assertionConsumerServiceUrl,
      nameIdFormat: configuration.nameIdFormat,
      enforced: configuration.enforced,
    }),
    createdAt: configuration.createdAt,
    updatedAt: configuration.updatedAt,
  };
};

export const isHostedEnterpriseAuthProviderSupported = (
  provider: Pick<TenantAuthProviderRecord, "protocol">,
): boolean => {
  return provider.protocol === "oidc";
};

const assertHostedEnterpriseAuthProviderWritable = (protocol: TenantAuthProviderProtocol): void => {
  if (protocol !== "oidc") {
    throw new Error(HOSTED_ENTERPRISE_OIDC_ONLY_ERROR);
  }
};

export const findTenantAuthPolicy = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<TenantAuthPolicyRecord | null> => {
  const lookupStatement = (): Promise<TenantAuthPolicyRow | null> =>
    db
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

  const row = await lookupStatement();

  if (row !== null) {
    return mapTenantAuthPolicyRow(row);
  }

  const legacyConfiguration = await findTenantSsoSamlConfiguration(db, tenantId);
  return legacyConfiguration === null ? null : buildLegacyTenantAuthPolicy(legacyConfiguration);
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
  const upsertStatement = (): Promise<SqlRunResult> =>
    db
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

  await upsertStatement();

  const policy = await findTenantAuthPolicy(db, input.tenantId);

  if (policy === null) {
    throw new Error(`Unable to upsert auth policy for tenant "${input.tenantId}"`);
  }

  return policy;
};

const hydrateLegacyTenantAuthProvider = async (
  db: SqlDatabase,
  provider: TenantAuthProviderRecord,
): Promise<TenantAuthProviderRecord> => {
  if (provider.protocol !== "saml") {
    return provider;
  }

  if (provider.id !== buildLegacyTenantAuthProviderId(provider.tenantId)) {
    return provider;
  }

  const legacyConfiguration = await findTenantSsoSamlConfiguration(db, provider.tenantId);

  if (legacyConfiguration === null) {
    return provider;
  }

  const hydratedProvider = buildLegacyTenantAuthProvider(legacyConfiguration);
  return {
    ...hydratedProvider,
    label: provider.label,
    enabled: provider.enabled,
    isDefault: provider.isDefault,
  };
};

export const listTenantAuthProviders = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<TenantAuthProviderRecord[]> => {
  const listStatement = (): Promise<SqlQueryResult<TenantAuthProviderRow>> =>
    db
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

  const result = await listStatement();

  if (result.results.length === 0) {
    const legacyConfiguration = await findTenantSsoSamlConfiguration(db, tenantId);
    return legacyConfiguration === null ? [] : [buildLegacyTenantAuthProvider(legacyConfiguration)];
  }

  return Promise.all(
    result.results.map(async (row) =>
      hydrateLegacyTenantAuthProvider(db, mapTenantAuthProviderRow(row)),
    ),
  );
};

export const findTenantAuthProviderById = async (
  db: SqlDatabase,
  tenantId: string,
  providerId: string,
): Promise<TenantAuthProviderRecord | null> => {
  const lookupStatement = (): Promise<TenantAuthProviderRow | null> =>
    db
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

  const row = await lookupStatement();

  if (row !== null) {
    return hydrateLegacyTenantAuthProvider(db, mapTenantAuthProviderRow(row));
  }

  if (providerId !== buildLegacyTenantAuthProviderId(tenantId)) {
    return null;
  }

  const legacyConfiguration = await findTenantSsoSamlConfiguration(db, tenantId);
  return legacyConfiguration === null ? null : buildLegacyTenantAuthProvider(legacyConfiguration);
};

export const createTenantAuthProvider = async (
  db: SqlDatabase,
  input: CreateTenantAuthProviderInput,
): Promise<TenantAuthProviderRecord> => {
  assertHostedEnterpriseAuthProviderWritable(input.protocol);
  const id = input.id ?? createPrefixedId("tap");
  const nowIso = new Date().toISOString();
  const enabled = input.enabled ?? true;
  const isDefault = input.isDefault ?? false;

  const clearDefaultStatement = (): Promise<SqlRunResult> =>
    db
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

  const insertStatement = (): Promise<SqlRunResult> =>
    db
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

  if (isDefault) {
    await clearDefaultStatement();
  }

  await insertStatement();

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
  assertHostedEnterpriseAuthProviderWritable(input.protocol);
  const nowIso = new Date().toISOString();
  const enabled = input.enabled ?? true;
  const isDefault = input.isDefault ?? false;

  const clearDefaultStatement = (): Promise<SqlRunResult> =>
    db
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

  const updateStatement = (): Promise<SqlRunResult> =>
    db
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

  if (isDefault) {
    await clearDefaultStatement();
  }

  const result = await updateStatement();

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
  const deleteStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        DELETE FROM tenant_auth_providers
        WHERE tenant_id = ?
          AND id = ?
      `,
      )
      .bind(tenantId, providerId)
      .run();

  const result = await deleteStatement();

  if ((result.meta.rowsWritten ?? 0) === 0) {
    return false;
  }

  const clearPolicyDefaultStatement = (): Promise<SqlRunResult> =>
    db
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

  await clearPolicyDefaultStatement();

  return true;
};

export const findTenantSsoSamlConfiguration = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<TenantSsoSamlConfigurationRecord | null> => {
  const lookupStatement = (): Promise<TenantSsoSamlConfigurationRow | null> =>
    db
      .prepare(
        `
        SELECT
          tenant_id AS tenantId,
          idp_entity_id AS idpEntityId,
          sso_login_url AS ssoLoginUrl,
          idp_certificate_pem AS idpCertificatePem,
          idp_metadata_url AS idpMetadataUrl,
          sp_entity_id AS spEntityId,
          assertion_consumer_service_url AS assertionConsumerServiceUrl,
          name_id_format AS nameIdFormat,
          enforced,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM tenant_sso_saml_configurations
        WHERE tenant_id = ?
        LIMIT 1
      `,
      )
      .bind(tenantId)
      .first<TenantSsoSamlConfigurationRow>();

  const row = await lookupStatement();

  return row === null ? null : mapTenantSsoSamlConfigurationRow(row);
};

export const upsertTenantSsoSamlConfiguration = async (
  db: SqlDatabase,
  input: UpsertTenantSsoSamlConfigurationInput,
): Promise<TenantSsoSamlConfigurationRecord> => {
  const nowIso = new Date().toISOString();
  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO tenant_sso_saml_configurations (
          tenant_id,
          idp_entity_id,
          sso_login_url,
          idp_certificate_pem,
          idp_metadata_url,
          sp_entity_id,
          assertion_consumer_service_url,
          name_id_format,
          enforced,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (tenant_id)
        DO UPDATE SET
          idp_entity_id = excluded.idp_entity_id,
          sso_login_url = excluded.sso_login_url,
          idp_certificate_pem = excluded.idp_certificate_pem,
          idp_metadata_url = excluded.idp_metadata_url,
          sp_entity_id = excluded.sp_entity_id,
          assertion_consumer_service_url = excluded.assertion_consumer_service_url,
          name_id_format = excluded.name_id_format,
          enforced = excluded.enforced,
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        input.tenantId,
        input.idpEntityId,
        input.ssoLoginUrl,
        input.idpCertificatePem,
        input.idpMetadataUrl ?? null,
        input.spEntityId,
        input.assertionConsumerServiceUrl,
        input.nameIdFormat ?? null,
        input.enforced === true ? 1 : 0,
        nowIso,
        nowIso,
      )
      .run();

  await upsertStatement();

  const configuration = await findTenantSsoSamlConfiguration(db, input.tenantId);

  if (configuration === null) {
    throw new Error(`Unable to upsert SAML SSO configuration for tenant "${input.tenantId}"`);
  }

  return configuration;
};

export const deleteTenantSsoSamlConfiguration = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<boolean> => {
  const deleteStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        DELETE FROM tenant_sso_saml_configurations
        WHERE tenant_id = ?
      `,
      )
      .bind(tenantId)
      .run();

  const result = await deleteStatement();

  return (result.meta.rowsWritten ?? 0) > 0;
};
