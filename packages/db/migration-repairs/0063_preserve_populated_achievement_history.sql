-- Production repair for installations where migration 0063 cannot truthfully
-- synthesize immutable achievement snapshots for existing assertions.

ALTER TABLE badge_issuance_rule_versions
  ADD COLUMN snapshot_badge_template_description TEXT,
  ADD COLUMN snapshot_badge_template_criteria_uri TEXT,
  ADD COLUMN snapshot_badge_template_trusted_credential_metadata_json TEXT;

ALTER TABLE assertions
  ADD COLUMN achievement_snapshot_json TEXT,
  ADD CONSTRAINT assertions_achievement_snapshot_json_object_check
    CHECK (
      achievement_snapshot_json IS NULL
      OR jsonb_typeof(achievement_snapshot_json::jsonb) = 'object'
    ) NOT VALID,
  ADD CONSTRAINT assertions_achievement_snapshot_template_check
    CHECK (
      achievement_snapshot_json IS NULL
      OR (
        achievement_snapshot_json::jsonb ? 'badgeTemplateId'
        AND achievement_snapshot_json::jsonb ->> 'badgeTemplateId' = badge_template_id
      )
    ) NOT VALID;

ALTER TABLE assertion_issuance_provenance
  DROP CONSTRAINT IF EXISTS assertion_issuance_provenance_rule_id_fkey,
  DROP CONSTRAINT IF EXISTS assertion_issuance_provenance_version_id_fkey;

ALTER TABLE assertion_issuance_provenance
  ADD CONSTRAINT assertion_issuance_provenance_source_shape_check
    CHECK (
      (
        source IN ('manual', 'programmatic')
        AND rule_id IS NULL
        AND version_id IS NULL
        AND provenance_json IS NULL
      )
      OR
      (
        source IN ('lti_roster', 'rule_evaluate')
        AND rule_id IS NOT NULL
        AND version_id IS NOT NULL
        AND provenance_json IS NOT NULL
      )
    ) NOT VALID,
  ADD CONSTRAINT assertion_issuance_provenance_tenant_rule_fkey
    FOREIGN KEY (tenant_id, rule_id)
    REFERENCES badge_issuance_rules (tenant_id, id)
    ON DELETE RESTRICT
    NOT VALID,
  ADD CONSTRAINT assertion_issuance_provenance_tenant_rule_version_fkey
    FOREIGN KEY (tenant_id, rule_id, version_id)
    REFERENCES badge_issuance_rule_versions (tenant_id, rule_id, id)
    ON DELETE RESTRICT
    NOT VALID;
