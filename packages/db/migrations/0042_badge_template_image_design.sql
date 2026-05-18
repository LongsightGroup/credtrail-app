-- Track badge template image history and asynchronous AI generation drafts.

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
      'generate_badge_template_image'
    )
  );

CREATE TABLE IF NOT EXISTS badge_template_image_revisions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  badge_template_id TEXT NOT NULL,
  previous_image_uri TEXT,
  new_image_uri TEXT,
  source_type TEXT NOT NULL
    CHECK (source_type IN ('manual_update', 'upload', 'ai_generated', 'restore')),
  prompt_text TEXT,
  provider TEXT,
  model TEXT,
  metadata_json TEXT,
  created_by_user_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (tenant_id, badge_template_id)
    REFERENCES badge_templates (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_badge_template_image_revisions_template
  ON badge_template_image_revisions (tenant_id, badge_template_id, created_at DESC);

CREATE TABLE IF NOT EXISTS badge_template_image_generations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  badge_template_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued', 'processing', 'succeeded', 'failed')),
  prompt_text TEXT NOT NULL,
  style_preset TEXT NOT NULL,
  prompt_notes TEXT,
  accent_color TEXT,
  result_image_uri TEXT,
  error_message TEXT,
  requested_by_user_id TEXT,
  queued_job_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  completed_at TEXT,
  FOREIGN KEY (tenant_id, badge_template_id)
    REFERENCES badge_templates (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (requested_by_user_id) REFERENCES users (id) ON DELETE SET NULL,
  FOREIGN KEY (queued_job_id) REFERENCES job_queue_messages (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_badge_template_image_generations_template
  ON badge_template_image_generations (tenant_id, badge_template_id, created_at DESC);
