DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM badge_issuance_rule_versions LIMIT 1)
    OR EXISTS (SELECT 1 FROM assertions LIMIT 1) THEN
    RAISE EXCEPTION
      'Migration 0063 requires empty badge rule version and assertion tables; recreate pre-client data so immutable achievement history is not fabricated from mutable templates';
  END IF;
END $$;

ALTER TABLE badge_issuance_rule_versions
  ADD COLUMN snapshot_badge_template_description TEXT,
  ADD COLUMN snapshot_badge_template_criteria_uri TEXT,
  ADD COLUMN snapshot_badge_template_trusted_credential_metadata_json TEXT;

ALTER TABLE assertions
  ADD COLUMN achievement_snapshot_json TEXT NOT NULL,
  ADD CONSTRAINT assertions_achievement_snapshot_json_object_check
    CHECK (jsonb_typeof(achievement_snapshot_json::jsonb) = 'object'),
  ADD CONSTRAINT assertions_achievement_snapshot_template_check
    CHECK (
      achievement_snapshot_json::jsonb ? 'badgeTemplateId'
      AND achievement_snapshot_json::jsonb ->> 'badgeTemplateId' = badge_template_id
    );

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
    ),
  ADD CONSTRAINT assertion_issuance_provenance_tenant_rule_fkey
    FOREIGN KEY (tenant_id, rule_id)
    REFERENCES badge_issuance_rules (tenant_id, id)
    ON DELETE RESTRICT,
  ADD CONSTRAINT assertion_issuance_provenance_tenant_rule_version_fkey
    FOREIGN KEY (tenant_id, rule_id, version_id)
    REFERENCES badge_issuance_rule_versions (tenant_id, rule_id, id)
    ON DELETE RESTRICT;
