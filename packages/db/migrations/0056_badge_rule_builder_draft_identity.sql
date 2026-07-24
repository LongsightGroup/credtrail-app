ALTER TABLE badge_issuance_rule_builder_drafts
  ADD COLUMN id TEXT;

UPDATE badge_issuance_rule_builder_drafts
SET id = 'brd_' || REPLACE(gen_random_uuid()::text, '-', '')
WHERE id IS NULL;

ALTER TABLE badge_issuance_rule_builder_drafts
  ALTER COLUMN id SET NOT NULL;

ALTER TABLE badge_issuance_rule_builder_drafts
  DROP CONSTRAINT badge_issuance_rule_builder_drafts_pkey;

ALTER TABLE badge_issuance_rule_builder_drafts
  DROP COLUMN rule_id_key;

ALTER TABLE badge_issuance_rule_builder_drafts
  ADD PRIMARY KEY (tenant_id, id);

CREATE UNIQUE INDEX idx_badge_rule_builder_drafts_user_rule
  ON badge_issuance_rule_builder_drafts (tenant_id, user_id, rule_id)
  WHERE rule_id IS NOT NULL;

CREATE INDEX idx_badge_rule_builder_drafts_user_updated
  ON badge_issuance_rule_builder_drafts (tenant_id, user_id, updated_at DESC);
