CREATE TABLE IF NOT EXISTS badge_issuance_rule_value_lists (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  label TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('course_ids', 'badge_template_ids')),
  values_json TEXT NOT NULL,
  created_by_user_id TEXT,
  archived_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
  FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_badge_rule_value_lists_tenant
  ON badge_issuance_rule_value_lists (tenant_id, kind, archived_at, created_at DESC);
