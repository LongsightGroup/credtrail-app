ALTER TABLE badge_issuance_rule_approval_events
  DROP CONSTRAINT IF EXISTS badge_issuance_rule_approval_events_action_check;

ALTER TABLE badge_issuance_rule_approval_events
  ADD CONSTRAINT badge_issuance_rule_approval_events_action_check
  CHECK (
    action IN (
      'submitted',
      'approved',
      'rejected',
      'changes_requested',
      'withdrawn',
      'reopened'
    )
  );
