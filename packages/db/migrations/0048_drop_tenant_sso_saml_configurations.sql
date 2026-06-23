-- Remove unused SAML enterprise SSO configuration and restrict auth providers to OIDC.

DELETE FROM tenant_auth_providers
WHERE protocol = 'saml';

UPDATE tenant_auth_policies
SET
  default_provider_id = NULL,
  updated_at = CURRENT_TIMESTAMP
WHERE default_provider_id IS NOT NULL
  AND default_provider_id NOT IN (
    SELECT id
    FROM tenant_auth_providers
  );

DROP TABLE IF EXISTS tenant_sso_saml_configurations;

PRAGMA foreign_keys = OFF;

CREATE TABLE tenant_auth_providers_oidc_only (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  protocol TEXT NOT NULL CHECK (protocol IN ('oidc')),
  label TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  is_default INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0, 1)),
  config_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
);

INSERT INTO tenant_auth_providers_oidc_only (
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
SELECT
  id,
  tenant_id,
  protocol,
  label,
  enabled,
  is_default,
  config_json,
  created_at,
  updated_at
FROM tenant_auth_providers
WHERE protocol = 'oidc';

DROP TABLE tenant_auth_providers;

ALTER TABLE tenant_auth_providers_oidc_only RENAME TO tenant_auth_providers;

CREATE INDEX IF NOT EXISTS idx_tenant_auth_providers_tenant
  ON tenant_auth_providers (tenant_id, created_at DESC, id DESC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_auth_providers_default_per_tenant
  ON tenant_auth_providers (tenant_id)
  WHERE is_default = 1;

PRAGMA foreign_keys = ON;
