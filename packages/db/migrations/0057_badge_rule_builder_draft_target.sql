ALTER TABLE badge_issuance_rule_versions
  ADD CONSTRAINT badge_issuance_rule_versions_tenant_rule_id_key
  UNIQUE (tenant_id, rule_id, id);

ALTER TABLE badge_issuance_rule_builder_drafts
  DROP CONSTRAINT badge_issuance_rule_builder_drafts_version_id_fkey;

DELETE FROM badge_issuance_rule_builder_drafts
WHERE (rule_id IS NULL) <> (version_id IS NULL);

ALTER TABLE badge_issuance_rule_builder_drafts
  ADD CONSTRAINT badge_rule_builder_drafts_target_check
  CHECK (
    (rule_id IS NULL AND version_id IS NULL)
    OR
    (rule_id IS NOT NULL AND version_id IS NOT NULL)
  );

ALTER TABLE badge_issuance_rule_builder_drafts
  ADD CONSTRAINT badge_rule_builder_drafts_tenant_rule_version_fkey
  FOREIGN KEY (tenant_id, rule_id, version_id)
  REFERENCES badge_issuance_rule_versions (tenant_id, rule_id, id)
  ON DELETE CASCADE;
