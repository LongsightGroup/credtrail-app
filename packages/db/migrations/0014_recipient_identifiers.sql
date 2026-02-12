-- Extend learner identity aliases and add recipient identifiers for OB3 credentialSubject.

ALTER TABLE learner_identities RENAME TO learner_identities_legacy;

CREATE TABLE learner_identities (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  learner_profile_id TEXT NOT NULL,
  identity_type TEXT NOT NULL
    CHECK (identity_type IN ('email', 'email_sha256', 'did', 'url', 'saml_subject', 'sourced_id')),
  identity_value TEXT NOT NULL,
  is_primary INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0, 1)),
  is_verified INTEGER NOT NULL DEFAULT 0 CHECK (is_verified IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, identity_type, identity_value),
  FOREIGN KEY (tenant_id, learner_profile_id)
    REFERENCES learner_profiles (tenant_id, id) ON DELETE CASCADE
);

INSERT INTO learner_identities (
  id,
  tenant_id,
  learner_profile_id,
  identity_type,
  identity_value,
  is_primary,
  is_verified,
  created_at,
  updated_at
)
SELECT
  id,
  tenant_id,
  learner_profile_id,
  identity_type,
  identity_value,
  is_primary,
  is_verified,
  created_at,
  updated_at
FROM learner_identities_legacy;

DROP TABLE learner_identities_legacy;

CREATE INDEX IF NOT EXISTS idx_learner_identities_lookup
  ON learner_identities (tenant_id, identity_type, identity_value);

CREATE INDEX IF NOT EXISTS idx_learner_identities_profile
  ON learner_identities (tenant_id, learner_profile_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_learner_identities_primary_per_profile
  ON learner_identities (tenant_id, learner_profile_id)
  WHERE is_primary = 1;

CREATE TABLE IF NOT EXISTS recipient_identifiers (
  assertion_id TEXT NOT NULL,
  identifier_type TEXT NOT NULL
    CHECK (identifier_type IN ('emailAddress', 'sourcedId', 'did', 'nationalIdentityNumber', 'studentId')),
  identifier_value TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (assertion_id, identifier_type, identifier_value),
  FOREIGN KEY (assertion_id) REFERENCES assertions (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_recipient_identifiers_assertion
  ON recipient_identifiers (assertion_id);
