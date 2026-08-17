-- Make each learner-record import row atomic and retry-safe.

CREATE TABLE IF NOT EXISTS learner_record_import_applications (
  tenant_id TEXT NOT NULL,
  batch_id TEXT NOT NULL,
  row_number INTEGER NOT NULL CHECK (row_number > 0),
  learner_profile_id TEXT,
  learner_record_entry_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  applied_at TEXT,
  PRIMARY KEY (tenant_id, batch_id, row_number),
  CHECK (
    (
      learner_profile_id IS NULL
      AND learner_record_entry_id IS NULL
      AND applied_at IS NULL
    )
    OR (
      learner_profile_id IS NOT NULL
      AND learner_record_entry_id IS NOT NULL
      AND applied_at IS NOT NULL
    )
  ),
  FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, learner_profile_id)
    REFERENCES learner_profiles (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (learner_record_entry_id)
    REFERENCES learner_record_entries (id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_learner_record_import_applications_entry
  ON learner_record_import_applications (learner_record_entry_id)
  WHERE learner_record_entry_id IS NOT NULL;
