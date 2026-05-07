CREATE TABLE IF NOT EXISTS auth_magic_link_rate_limit_attempts (
  id TEXT PRIMARY KEY,
  dimension_type TEXT NOT NULL CHECK (dimension_type IN ('ip', 'tenant', 'email', 'tenant_email')),
  dimension_hash TEXT NOT NULL,
  occurred_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_magic_link_rate_limit_attempts_window
  ON auth_magic_link_rate_limit_attempts (dimension_type, dimension_hash, occurred_at);
