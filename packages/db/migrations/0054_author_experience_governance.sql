-- Add author builder drafts and least-privilege approver membership role.

ALTER TABLE memberships
  DROP CONSTRAINT IF EXISTS memberships_role_check;

ALTER TABLE memberships
  ADD CONSTRAINT memberships_role_check
  CHECK (role IN ('owner', 'admin', 'issuer', 'approver', 'viewer'));

ALTER TABLE badge_rule_approval_policies
  DROP CONSTRAINT IF EXISTS badge_rule_approval_policies_steps_json_check;

ALTER TABLE badge_issuance_rule_approval_steps
  DROP CONSTRAINT IF EXISTS badge_issuance_rule_approval_steps_required_role_check;

ALTER TABLE badge_issuance_rule_approval_steps
  ADD CONSTRAINT badge_issuance_rule_approval_steps_required_role_check
  CHECK (required_role IS NULL OR required_role IN ('owner', 'admin', 'issuer', 'approver', 'viewer'));

ALTER TABLE badge_issuance_rule_approval_events
  DROP CONSTRAINT IF EXISTS badge_issuance_rule_approval_events_actor_role_check;

ALTER TABLE badge_issuance_rule_approval_events
  ADD CONSTRAINT badge_issuance_rule_approval_events_actor_role_check
  CHECK (actor_role IS NULL OR actor_role IN ('owner', 'admin', 'issuer', 'approver', 'viewer'));

ALTER TABLE badge_issuance_rule_versions
  DROP CONSTRAINT IF EXISTS badge_issuance_rule_versions_status_check;

ALTER TABLE badge_issuance_rule_versions
  ADD CONSTRAINT badge_issuance_rule_versions_status_check
  CHECK (status IN ('draft', 'pending_approval', 'approved', 'active', 'suspended', 'expired', 'rejected', 'deprecated'));

ALTER TABLE badge_issuance_rules
  DROP CONSTRAINT IF EXISTS badge_issuance_rules_tenant_id_id_key;

ALTER TABLE badge_issuance_rules
  ADD CONSTRAINT badge_issuance_rules_tenant_id_id_key
  UNIQUE (tenant_id, id);

CREATE TABLE IF NOT EXISTS badge_issuance_rule_builder_drafts (
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  rule_id TEXT,
  rule_id_key TEXT GENERATED ALWAYS AS (COALESCE(rule_id, '__new__')) STORED,
  version_id TEXT,
  current_step TEXT NOT NULL CHECK (current_step IN ('metadata', 'conditions', 'test')),
  draft_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tenant_id, user_id, rule_id_key),
  FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, user_id) REFERENCES memberships (tenant_id, user_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, rule_id) REFERENCES badge_issuance_rules (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (version_id) REFERENCES badge_issuance_rule_versions (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_badge_rule_builder_drafts_tenant_rule
  ON badge_issuance_rule_builder_drafts (tenant_id, rule_id);
