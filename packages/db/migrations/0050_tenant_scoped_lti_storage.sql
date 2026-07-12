-- Bind all CredTrail-owned LTI protocol state to a tenant. Existing short-lived
-- nonce and dynamic-registration state is intentionally discarded: neither row
-- carries enough trusted tenant context for a safe backfill.

ALTER TABLE lti_deployments ADD COLUMN tenant_id TEXT;
UPDATE lti_deployments
SET tenant_id = (
  SELECT tenant_id
  FROM lti_issuer_registrations
  WHERE lti_issuer_registrations.issuer = lti_deployments.issuer
);

UPDATE lti_launch_sessions
SET tenant_id = (
  SELECT tenant_id
  FROM lti_issuer_registrations
  WHERE lti_issuer_registrations.issuer = lti_launch_sessions.issuer
)
WHERE tenant_id IS NULL;

CREATE TABLE lti_launch_nonces_tenant_scoped (
  tenant_id TEXT NOT NULL,
  nonce TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tenant_id, nonce),
  FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
);
DROP TABLE lti_launch_nonces;
ALTER TABLE lti_launch_nonces_tenant_scoped RENAME TO lti_launch_nonces;
CREATE INDEX idx_lti_launch_nonces_tenant_expires
  ON lti_launch_nonces (tenant_id, expires_at);

CREATE TABLE lti_dynamic_registration_sessions_tenant_scoped (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  data_json TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
);
DROP TABLE lti_dynamic_registration_sessions;
ALTER TABLE lti_dynamic_registration_sessions_tenant_scoped
  RENAME TO lti_dynamic_registration_sessions;
CREATE INDEX idx_lti_dynamic_registration_sessions_tenant_expires
  ON lti_dynamic_registration_sessions (tenant_id, expires_at);

CREATE TABLE lti_deployments_tenant_scoped (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  issuer TEXT NOT NULL,
  client_id TEXT NOT NULL,
  deployment_id TEXT NOT NULL,
  name TEXT,
  description TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
  FOREIGN KEY (issuer) REFERENCES lti_issuer_registrations (issuer) ON DELETE CASCADE,
  UNIQUE (tenant_id, issuer, client_id, deployment_id)
);
INSERT INTO lti_deployments_tenant_scoped (
  id, tenant_id, issuer, client_id, deployment_id, name, description, created_at, updated_at
)
SELECT id, tenant_id, issuer, client_id, deployment_id, name, description, created_at, updated_at
FROM lti_deployments
WHERE tenant_id IS NOT NULL;
DROP TABLE lti_deployments;
ALTER TABLE lti_deployments_tenant_scoped RENAME TO lti_deployments;
CREATE INDEX idx_lti_deployments_tenant_issuer
  ON lti_deployments (tenant_id, issuer);

CREATE TABLE lti_launch_sessions_tenant_scoped (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  issuer TEXT NOT NULL,
  client_id TEXT NOT NULL,
  deployment_id TEXT NOT NULL,
  user_id TEXT,
  data_json TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
);
INSERT INTO lti_launch_sessions_tenant_scoped (
  tenant_id, id, issuer, client_id, deployment_id, user_id, data_json, expires_at, created_at, updated_at
)
SELECT tenant_id, id, issuer, client_id, deployment_id, user_id, data_json, expires_at, created_at, updated_at
FROM lti_launch_sessions
WHERE tenant_id IS NOT NULL;
DROP TABLE lti_launch_sessions;
ALTER TABLE lti_launch_sessions_tenant_scoped RENAME TO lti_launch_sessions;
CREATE INDEX idx_lti_launch_sessions_tenant_expires
  ON lti_launch_sessions (tenant_id, expires_at);
CREATE UNIQUE INDEX idx_lti_launch_sessions_id
  ON lti_launch_sessions (id);
