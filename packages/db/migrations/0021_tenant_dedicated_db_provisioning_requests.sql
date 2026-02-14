-- Track enterprise dedicated-database provisioning workflows per tenant.

CREATE TABLE IF NOT EXISTS tenant_dedicated_db_provisioning_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  requested_by_user_id TEXT,
  target_region TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'provisioned', 'failed', 'canceled')),
  dedicated_database_url TEXT,
  notes TEXT,
  requested_at TEXT NOT NULL,
  resolved_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
  FOREIGN KEY (requested_by_user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_dedicated_db_provisioning_tenant_status
  ON tenant_dedicated_db_provisioning_requests (tenant_id, status, requested_at DESC);
