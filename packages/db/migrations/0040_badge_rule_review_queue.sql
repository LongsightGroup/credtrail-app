-- Review queue state for badge-rule evaluations that require human decisions.

ALTER TABLE badge_issuance_rule_evaluations
  ADD COLUMN IF NOT EXISTS review_status TEXT
    CHECK (review_status IS NULL OR review_status IN ('pending', 'resolved'));

ALTER TABLE badge_issuance_rule_evaluations
  ADD COLUMN IF NOT EXISTS review_decision TEXT
    CHECK (review_decision IS NULL OR review_decision IN ('issue', 'dismiss'));

ALTER TABLE badge_issuance_rule_evaluations
  ADD COLUMN IF NOT EXISTS review_comment TEXT;

ALTER TABLE badge_issuance_rule_evaluations
  ADD COLUMN IF NOT EXISTS reviewed_by_user_id TEXT;

ALTER TABLE badge_issuance_rule_evaluations
  ADD COLUMN IF NOT EXISTS reviewed_at TEXT;

CREATE INDEX IF NOT EXISTS idx_badge_issuance_rule_evaluations_review_queue
  ON badge_issuance_rule_evaluations (tenant_id, review_status, evaluated_at DESC);
