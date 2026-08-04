CREATE TABLE IF NOT EXISTS learner_lms_identities (
  tenant_id TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  lms_learner_id TEXT NOT NULL,
  learner_profile_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tenant_id, connection_id, lms_learner_id),
  UNIQUE (tenant_id, connection_id, learner_profile_id),
  FOREIGN KEY (tenant_id, connection_id)
    REFERENCES tenant_lms_connections (tenant_id, id)
    ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, learner_profile_id)
    REFERENCES learner_profiles (tenant_id, id)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_learner_lms_identities_lookup
  ON learner_lms_identities (tenant_id, lms_learner_id);

CREATE INDEX IF NOT EXISTS idx_learner_lms_identities_profile
  ON learner_lms_identities (tenant_id, learner_profile_id);
