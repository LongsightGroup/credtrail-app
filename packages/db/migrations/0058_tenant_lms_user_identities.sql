CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_lms_connections_lti_registration
  ON tenant_lms_connections (tenant_id, lti_issuer, lti_client_id, lti_deployment_id)
  WHERE lti_issuer IS NOT NULL
    AND lti_client_id IS NOT NULL
    AND lti_deployment_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS tenant_lms_user_identities (
  tenant_id TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  provider_user_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tenant_id, connection_id, user_id),
  UNIQUE (tenant_id, connection_id, provider_user_id),
  FOREIGN KEY (tenant_id, connection_id)
    REFERENCES tenant_lms_connections (tenant_id, id)
    ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tenant_lms_user_identities_user
  ON tenant_lms_user_identities (tenant_id, user_id);
