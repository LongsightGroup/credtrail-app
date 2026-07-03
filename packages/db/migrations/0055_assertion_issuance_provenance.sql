-- Immutable issuance provenance snapshots for per-credential evidence views.

CREATE TABLE IF NOT EXISTS assertion_issuance_provenance (
  assertion_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  source TEXT NOT NULL CHECK (
    source IN ('lti_roster', 'rule_evaluate', 'manual', 'programmatic')
  ),
  rule_id TEXT,
  version_id TEXT,
  provenance_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, assertion_id) REFERENCES assertions (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (rule_id) REFERENCES badge_issuance_rules (id) ON DELETE SET NULL,
  FOREIGN KEY (version_id) REFERENCES badge_issuance_rule_versions (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_assertion_issuance_provenance_tenant_assertion
  ON assertion_issuance_provenance (tenant_id, assertion_id);

CREATE INDEX IF NOT EXISTS idx_badge_issuance_rule_evaluations_assertion
  ON badge_issuance_rule_evaluations (tenant_id, assertion_id)
  WHERE assertion_id IS NOT NULL;
