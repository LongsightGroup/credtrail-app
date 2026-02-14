-- Store enterprise tenant SSO/SAML identity provider configuration.

CREATE TABLE IF NOT EXISTS tenant_sso_saml_configurations (
  tenant_id TEXT PRIMARY KEY,
  idp_entity_id TEXT NOT NULL,
  sso_login_url TEXT NOT NULL,
  idp_certificate_pem TEXT NOT NULL,
  idp_metadata_url TEXT,
  sp_entity_id TEXT NOT NULL,
  assertion_consumer_service_url TEXT NOT NULL,
  name_id_format TEXT,
  enforced INTEGER NOT NULL DEFAULT 0 CHECK (enforced IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
);
