-- Remove the unsupported verification-cache job from the durable queue contract.

DELETE FROM job_queue_messages
WHERE job_type = 'rebuild_verification_cache';

ALTER TABLE job_queue_messages
  DROP CONSTRAINT IF EXISTS job_queue_messages_job_type_check;

ALTER TABLE job_queue_messages
  ADD CONSTRAINT job_queue_messages_job_type_check
  CHECK (
    job_type IN (
      'issue_badge',
      'revoke_badge',
      'import_migration_batch',
      'import_learner_record_batch',
      'generate_badge_template_image',
      'process_badge_rule_lifecycle',
      'process_automated_badge_rule',
      'send_badge_rule_approval_notification',
      'process_learner_evidence_change'
    )
  );
