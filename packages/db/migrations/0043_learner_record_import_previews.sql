-- Persist reviewed learner-record import previews so queue actions are server-owned.

CREATE TABLE IF NOT EXISTS learner_record_import_previews (
  tenant_id TEXT NOT NULL,
  batch_id TEXT NOT NULL,
  file_name TEXT NOT NULL,
  format TEXT NOT NULL CHECK (format IN ('csv')),
  defaults_json TEXT NOT NULL,
  reports_json TEXT NOT NULL,
  queue_payloads_json TEXT NOT NULL,
  created_by_user_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT NOT NULL,
  queued_at TEXT,
  PRIMARY KEY (tenant_id, batch_id),
  FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
  FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_learner_record_import_previews_tenant_created
  ON learner_record_import_previews (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_learner_record_import_previews_expires
  ON learner_record_import_previews (expires_at);
