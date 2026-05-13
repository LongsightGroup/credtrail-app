CREATE TABLE IF NOT EXISTS lti_issuer_registrations (
  issuer TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  authorization_endpoint TEXT NOT NULL,
  client_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_lti_issuer_registrations_tenant
  ON lti_issuer_registrations (tenant_id);
