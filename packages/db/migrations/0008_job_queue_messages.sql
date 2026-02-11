-- Persist async job messages in D1 so queue state is database-backed.

CREATE TABLE IF NOT EXISTS job_queue_messages (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  job_type TEXT NOT NULL
    CHECK (job_type IN ('issue_badge', 'revoke_badge', 'rebuild_verification_cache', 'import_migration_batch')),
  payload_json TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  max_attempts INTEGER NOT NULL DEFAULT 8 CHECK (max_attempts > 0),
  available_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  leased_until TEXT,
  lease_token TEXT,
  last_error TEXT,
  completed_at TEXT,
  failed_at TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (tenant_id, job_type, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_job_queue_messages_status_created
  ON job_queue_messages (status, available_at, created_at);

CREATE INDEX IF NOT EXISTS idx_job_queue_messages_lease_token
  ON job_queue_messages (lease_token);
