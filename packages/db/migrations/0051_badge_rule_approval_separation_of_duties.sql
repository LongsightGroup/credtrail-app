-- Enforce separation of duties and add named approval targets for badge rule governance.

ALTER TABLE badge_rule_approval_policies
  ADD COLUMN IF NOT EXISTS allow_self_certification BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE badge_issuance_rule_versions
  ADD COLUMN IF NOT EXISTS submitted_by_user_id TEXT;

ALTER TABLE badge_issuance_rule_versions
  ADD COLUMN IF NOT EXISTS submitted_at TEXT;

ALTER TABLE badge_issuance_rule_versions
  DROP CONSTRAINT IF EXISTS fk_badge_issuance_rule_versions_submitted_by;

ALTER TABLE badge_issuance_rule_versions
  ADD CONSTRAINT fk_badge_issuance_rule_versions_submitted_by
  FOREIGN KEY (submitted_by_user_id) REFERENCES users (id) ON DELETE SET NULL;

ALTER TABLE badge_issuance_rule_approval_steps
  ADD COLUMN IF NOT EXISTS target_type TEXT NOT NULL DEFAULT 'role_threshold';

ALTER TABLE badge_issuance_rule_approval_steps
  ADD COLUMN IF NOT EXISTS target_user_id TEXT;

ALTER TABLE badge_issuance_rule_approval_steps
  ADD COLUMN IF NOT EXISTS target_approver_group_id TEXT;

ALTER TABLE badge_issuance_rule_approval_steps
  ADD COLUMN IF NOT EXISTS org_unit_id TEXT;

ALTER TABLE badge_issuance_rule_approval_steps
  ALTER COLUMN required_role DROP NOT NULL;

CREATE TABLE IF NOT EXISTS badge_rule_approver_groups (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  org_unit_id TEXT,
  name TEXT NOT NULL,
  created_by_user_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (tenant_id, org_unit_id, name),
  FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, org_unit_id) REFERENCES tenant_org_units (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_badge_rule_approver_groups_tenant_org_unit
  ON badge_rule_approver_groups (tenant_id, org_unit_id);

CREATE TABLE IF NOT EXISTS badge_rule_approver_group_members (
  tenant_id TEXT NOT NULL,
  group_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  created_by_user_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (group_id, user_id),
  FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
  FOREIGN KEY (group_id) REFERENCES badge_rule_approver_groups (id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_badge_rule_approver_group_members_user
  ON badge_rule_approver_group_members (tenant_id, user_id);

ALTER TABLE badge_issuance_rule_approval_steps
  DROP CONSTRAINT IF EXISTS badge_issuance_rule_approval_steps_status_check;

ALTER TABLE badge_issuance_rule_approval_steps
  ADD CONSTRAINT badge_issuance_rule_approval_steps_status_check
  CHECK (status IN ('queued', 'pending', 'approved', 'rejected', 'changes_requested'));

ALTER TABLE badge_issuance_rule_approval_steps
  DROP CONSTRAINT IF EXISTS badge_issuance_rule_approval_steps_target_type_check;

ALTER TABLE badge_issuance_rule_approval_steps
  ADD CONSTRAINT badge_issuance_rule_approval_steps_target_type_check
  CHECK (target_type IN ('role_threshold', 'user', 'approver_group'));

ALTER TABLE badge_issuance_rule_approval_steps
  DROP CONSTRAINT IF EXISTS badge_issuance_rule_approval_steps_target_shape_check;

ALTER TABLE badge_issuance_rule_approval_steps
  ADD CONSTRAINT badge_issuance_rule_approval_steps_target_shape_check
  CHECK (
    (target_type = 'role_threshold' AND required_role IS NOT NULL AND target_user_id IS NULL AND target_approver_group_id IS NULL)
    OR (target_type = 'user' AND target_user_id IS NOT NULL AND target_approver_group_id IS NULL)
    OR (target_type = 'approver_group' AND target_user_id IS NULL AND target_approver_group_id IS NOT NULL)
  );

ALTER TABLE badge_issuance_rule_approval_steps
  DROP CONSTRAINT IF EXISTS fk_badge_rule_approval_steps_target_user;

ALTER TABLE badge_issuance_rule_approval_steps
  ADD CONSTRAINT fk_badge_rule_approval_steps_target_user
  FOREIGN KEY (target_user_id) REFERENCES users (id) ON DELETE RESTRICT;

ALTER TABLE badge_issuance_rule_approval_steps
  DROP CONSTRAINT IF EXISTS fk_badge_rule_approval_steps_target_group;

ALTER TABLE badge_issuance_rule_approval_steps
  ADD CONSTRAINT fk_badge_rule_approval_steps_target_group
  FOREIGN KEY (target_approver_group_id) REFERENCES badge_rule_approver_groups (id) ON DELETE RESTRICT;

ALTER TABLE badge_issuance_rule_approval_events
  DROP CONSTRAINT IF EXISTS badge_issuance_rule_approval_events_action_check;

ALTER TABLE badge_issuance_rule_approval_events
  ADD CONSTRAINT badge_issuance_rule_approval_events_action_check
  CHECK (action IN ('submitted', 'approved', 'rejected', 'changes_requested'));
