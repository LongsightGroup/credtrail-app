ALTER TABLE badge_issuance_rule_versions
  ADD COLUMN snapshot_name TEXT,
  ADD COLUMN snapshot_description TEXT,
  ADD COLUMN snapshot_badge_template_id TEXT,
  ADD COLUMN snapshot_badge_template_title TEXT,
  ADD COLUMN snapshot_badge_template_image_uri TEXT,
  ADD COLUMN snapshot_org_unit_id TEXT,
  ADD COLUMN snapshot_owner_org_unit_id TEXT,
  ADD COLUMN snapshot_lms_provider_kind TEXT,
  ADD COLUMN snapshot_lms_connection_id TEXT;

UPDATE badge_issuance_rule_versions AS versions
SET
  snapshot_name = rules.name,
  snapshot_description = rules.description,
  snapshot_badge_template_id = rules.badge_template_id,
  snapshot_badge_template_title = templates.title,
  snapshot_badge_template_image_uri = templates.image_uri,
  snapshot_org_unit_id = rules.org_unit_id,
  snapshot_owner_org_unit_id = rules.owner_org_unit_id,
  snapshot_lms_provider_kind = rules.lms_provider_kind,
  snapshot_lms_connection_id = rules.lms_connection_id
FROM badge_issuance_rules AS rules
INNER JOIN badge_templates AS templates
  ON templates.id = rules.badge_template_id
  AND templates.tenant_id = rules.tenant_id
WHERE rules.id = versions.rule_id
  AND rules.tenant_id = versions.tenant_id;

ALTER TABLE badge_issuance_rule_versions
  ALTER COLUMN snapshot_name SET NOT NULL,
  ALTER COLUMN snapshot_badge_template_id SET NOT NULL,
  ALTER COLUMN snapshot_badge_template_title SET NOT NULL,
  ALTER COLUMN snapshot_org_unit_id SET NOT NULL,
  ALTER COLUMN snapshot_owner_org_unit_id SET NOT NULL,
  ALTER COLUMN snapshot_lms_provider_kind SET NOT NULL;

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
