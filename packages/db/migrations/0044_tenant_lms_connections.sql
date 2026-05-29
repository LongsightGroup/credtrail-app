-- Generic tenant LMS gradebook connections used by rule creation and evaluation.

CREATE TABLE IF NOT EXISTS tenant_lms_connections (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  provider_kind TEXT NOT NULL CHECK (provider_kind IN ('canvas', 'sakai')),
  api_base_url TEXT NOT NULL,
  authorization_endpoint TEXT,
  token_endpoint TEXT,
  client_id TEXT,
  client_secret TEXT,
  scope TEXT,
  access_token TEXT,
  refresh_token TEXT,
  access_token_expires_at TEXT,
  refresh_token_expires_at TEXT,
  connected_at TEXT,
  lti_issuer TEXT,
  lti_client_id TEXT,
  lti_deployment_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tenant_lms_connections_tenant
  ON tenant_lms_connections (tenant_id, provider_kind, display_name);

CREATE INDEX IF NOT EXISTS idx_tenant_lms_connections_connected
  ON tenant_lms_connections (tenant_id, connected_at DESC);

INSERT INTO tenant_lms_connections (
  id,
  tenant_id,
  display_name,
  provider_kind,
  api_base_url,
  authorization_endpoint,
  token_endpoint,
  client_id,
  client_secret,
  scope,
  access_token,
  refresh_token,
  access_token_expires_at,
  refresh_token_expires_at,
  connected_at,
  created_at,
  updated_at
)
SELECT
  'lms_canvas_' || tenant_id,
  tenant_id,
  'Canvas gradebook',
  'canvas',
  api_base_url,
  authorization_endpoint,
  token_endpoint,
  client_id,
  client_secret,
  scope,
  access_token,
  refresh_token,
  access_token_expires_at,
  refresh_token_expires_at,
  connected_at,
  created_at,
  updated_at
FROM tenant_canvas_gradebook_integrations
ON CONFLICT (id) DO NOTHING;

ALTER TABLE badge_issuance_rules
  ADD COLUMN IF NOT EXISTS lms_connection_id TEXT;

CREATE INDEX IF NOT EXISTS idx_badge_issuance_rules_lms_connection
  ON badge_issuance_rules (tenant_id, lms_connection_id);

ALTER TABLE badge_issuance_rules
  ADD CONSTRAINT badge_issuance_rules_lms_connection_fkey
  FOREIGN KEY (tenant_id, lms_connection_id)
  REFERENCES tenant_lms_connections (tenant_id, id)
  ON DELETE RESTRICT;
