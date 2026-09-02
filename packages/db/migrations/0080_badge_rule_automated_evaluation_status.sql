-- Persist one safe, current automated-evaluation outcome per governed rule version.

CREATE TABLE badge_rule_automated_evaluation_status (
  tenant_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  version_id TEXT NOT NULL,
  command_id TEXT NOT NULL,
  trigger_kind TEXT NOT NULL
    CHECK (trigger_kind IN ('activation', 'hourly', 'expiry', 'manual')),
  status TEXT NOT NULL
    CHECK (status IN ('queued', 'running', 'succeeded', 'retrying', 'failed', 'noop')),
  queued_at TEXT NOT NULL,
  started_at TEXT,
  completed_at TEXT,
  candidate_learner_count INTEGER CHECK (candidate_learner_count >= 0),
  matched_learner_count INTEGER CHECK (matched_learner_count >= 0),
  issue_jobs_enqueued INTEGER CHECK (issue_jobs_enqueued >= 0),
  learners_missing_email INTEGER CHECK (learners_missing_email >= 0),
  learners_already_issued INTEGER CHECK (learners_already_issued >= 0),
  learners_unavailable INTEGER CHECK (learners_unavailable >= 0),
  learner_identity_conflicts INTEGER CHECK (learner_identity_conflicts >= 0),
  reason_tag TEXT CHECK (
    reason_tag IS NULL OR reason_tag IN (
      'rule_or_version_not_found',
      'instructor_confirmation_required',
      'rule_version_inactive',
      'rule_version_changed',
      'learner_evaluation_unavailable'
    )
  ),
  failure_tag TEXT CHECK (
    failure_tag IS NULL OR failure_tag IN (
      'invalid_command',
      'provider_unavailable',
      'processing_error'
    )
  ),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, version_id),
  UNIQUE (tenant_id, command_id),
  FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, rule_id) REFERENCES badge_issuance_rules (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, rule_id, version_id) REFERENCES badge_issuance_rule_versions (tenant_id, rule_id, id) ON DELETE CASCADE,
  CHECK (
    (
      candidate_learner_count IS NULL
      AND matched_learner_count IS NULL
      AND issue_jobs_enqueued IS NULL
      AND learners_missing_email IS NULL
      AND learners_already_issued IS NULL
      AND learners_unavailable IS NULL
      AND learner_identity_conflicts IS NULL
    )
    OR
    (
      candidate_learner_count IS NOT NULL
      AND matched_learner_count IS NOT NULL
      AND issue_jobs_enqueued IS NOT NULL
      AND learners_missing_email IS NOT NULL
      AND learners_already_issued IS NOT NULL
      AND learners_unavailable IS NOT NULL
      AND learner_identity_conflicts IS NOT NULL
    )
  ),
  CHECK (
    (status = 'queued' AND started_at IS NULL AND completed_at IS NULL AND reason_tag IS NULL AND failure_tag IS NULL)
    OR (status = 'running' AND started_at IS NOT NULL AND completed_at IS NULL AND reason_tag IS NULL AND failure_tag IS NULL)
    OR (status = 'succeeded' AND started_at IS NOT NULL AND completed_at IS NOT NULL AND candidate_learner_count IS NOT NULL AND reason_tag IS NULL AND failure_tag IS NULL)
    OR (status = 'retrying' AND completed_at IS NULL AND (reason_tag IS NOT NULL OR failure_tag IS NOT NULL))
    OR (status = 'failed' AND completed_at IS NOT NULL AND failure_tag IS NOT NULL)
    OR (status = 'noop' AND started_at IS NOT NULL AND completed_at IS NOT NULL AND candidate_learner_count IS NULL AND reason_tag IS NOT NULL AND failure_tag IS NULL)
  )
);

CREATE INDEX idx_badge_rule_automated_evaluation_status_rule
  ON badge_rule_automated_evaluation_status (tenant_id, rule_id, updated_at DESC);
