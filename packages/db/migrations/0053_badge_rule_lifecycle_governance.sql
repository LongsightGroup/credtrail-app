-- Add lifecycle governance for badge issuance rules.

ALTER TABLE badge_issuance_rule_versions
  DROP CONSTRAINT IF EXISTS badge_issuance_rule_versions_status_check;

ALTER TABLE badge_issuance_rule_versions
  ADD CONSTRAINT badge_issuance_rule_versions_status_check
  CHECK (status IN ('draft', 'pending_approval', 'approved', 'active', 'suspended', 'expired', 'rejected', 'deprecated'));

ALTER TABLE badge_issuance_rule_versions
  ADD COLUMN IF NOT EXISTS effective_starts_at TEXT,
  ADD COLUMN IF NOT EXISTS expires_at TEXT,
  ADD COLUMN IF NOT EXISTS expired_at TEXT,
  ADD COLUMN IF NOT EXISTS suspended_at TEXT,
  ADD COLUMN IF NOT EXISTS suspended_by_user_id TEXT,
  ADD COLUMN IF NOT EXISTS suspension_reason TEXT,
  ADD COLUMN IF NOT EXISTS recertified_at TEXT,
  ADD COLUMN IF NOT EXISTS recertification_due_at TEXT,
  ADD COLUMN IF NOT EXISTS expiry_reminder_sent_at TEXT,
  ADD COLUMN IF NOT EXISTS recertification_reminder_sent_at TEXT;

ALTER TABLE badge_issuance_rule_versions
  DROP CONSTRAINT IF EXISTS fk_badge_issuance_rule_versions_suspended_by;

ALTER TABLE badge_issuance_rule_versions
  ADD CONSTRAINT fk_badge_issuance_rule_versions_suspended_by
  FOREIGN KEY (suspended_by_user_id) REFERENCES users (id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_badge_issuance_rule_versions_lifecycle_due
  ON badge_issuance_rule_versions (tenant_id, status, expires_at, recertification_due_at);

ALTER TABLE badge_rule_approval_policies
  ADD COLUMN IF NOT EXISTS recertification_interval_months INTEGER;

ALTER TABLE badge_rule_approval_policies
  DROP CONSTRAINT IF EXISTS badge_rule_approval_policies_recertification_interval_check;

ALTER TABLE badge_rule_approval_policies
  ADD CONSTRAINT badge_rule_approval_policies_recertification_interval_check
  CHECK (recertification_interval_months IS NULL OR recertification_interval_months BETWEEN 1 AND 120);

CREATE TABLE IF NOT EXISTS badge_rule_recertification_reviews (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  version_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
  due_at TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  requested_by_user_id TEXT,
  decided_by_user_id TEXT,
  decided_at TEXT,
  decision_comment TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (tenant_id, version_id, due_at),
  FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
  FOREIGN KEY (rule_id) REFERENCES badge_issuance_rules (id) ON DELETE CASCADE,
  FOREIGN KEY (version_id) REFERENCES badge_issuance_rule_versions (id) ON DELETE CASCADE,
  FOREIGN KEY (requested_by_user_id) REFERENCES users (id) ON DELETE SET NULL,
  FOREIGN KEY (decided_by_user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_badge_rule_recertification_reviews_pending
  ON badge_rule_recertification_reviews (tenant_id, status, due_at);

ALTER TABLE job_queue_messages
  DROP CONSTRAINT IF EXISTS job_queue_messages_job_type_check;

ALTER TABLE job_queue_messages
  ADD CONSTRAINT job_queue_messages_job_type_check
  CHECK (
    job_type IN (
      'issue_badge',
      'revoke_badge',
      'rebuild_verification_cache',
      'import_migration_batch',
      'import_learner_record_batch',
      'generate_badge_template_image',
      'process_badge_rule_lifecycle',
      'process_end_of_term_badge_rule'
    )
  );
