DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM badge_issuance_rule_versions LIMIT 1) THEN
    RAISE EXCEPTION
      'Migration 0062 requires an empty badge rule version table; recreate pre-client data so immutable rule history is not fabricated from mutable rule and template rows';
  END IF;
END $$;

ALTER TABLE badge_issuance_rule_versions
  ADD COLUMN snapshot_name TEXT NOT NULL,
  ADD COLUMN snapshot_description TEXT,
  ADD COLUMN snapshot_badge_template_id TEXT NOT NULL,
  ADD COLUMN snapshot_badge_template_title TEXT NOT NULL,
  ADD COLUMN snapshot_badge_template_image_uri TEXT,
  ADD COLUMN snapshot_org_unit_id TEXT NOT NULL,
  ADD COLUMN snapshot_owner_org_unit_id TEXT NOT NULL,
  ADD COLUMN snapshot_lms_provider_kind TEXT NOT NULL,
  ADD COLUMN snapshot_lms_connection_id TEXT;

ALTER TABLE badge_issuance_rule_versions
  ADD CONSTRAINT badge_rule_version_snapshot_name_check
    CHECK (LENGTH(BTRIM(snapshot_name)) > 0),
  ADD CONSTRAINT badge_rule_version_snapshot_badge_template_id_check
    CHECK (LENGTH(BTRIM(snapshot_badge_template_id)) > 0),
  ADD CONSTRAINT badge_rule_version_snapshot_badge_template_title_check
    CHECK (LENGTH(BTRIM(snapshot_badge_template_title)) > 0),
  ADD CONSTRAINT badge_rule_version_snapshot_org_unit_id_check
    CHECK (LENGTH(BTRIM(snapshot_org_unit_id)) > 0),
  ADD CONSTRAINT badge_rule_version_snapshot_owner_org_unit_id_check
    CHECK (LENGTH(BTRIM(snapshot_owner_org_unit_id)) > 0),
  ADD CONSTRAINT badge_rule_version_snapshot_lms_provider_kind_check
    CHECK (
      snapshot_lms_provider_kind IN (
        'canvas',
        'moodle',
        'blackboard_ultra',
        'd2l_brightspace',
        'sakai'
      )
    );
