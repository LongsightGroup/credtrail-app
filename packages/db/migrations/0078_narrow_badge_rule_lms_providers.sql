-- Remove rule records for provider variants that CredTrail cannot connect to or evaluate.
DELETE FROM badge_issuance_rules
WHERE lms_provider_kind NOT IN ('canvas', 'sakai');

ALTER TABLE badge_issuance_rules
  DROP CONSTRAINT IF EXISTS badge_issuance_rules_lms_provider_kind_check;

ALTER TABLE badge_issuance_rules
  ADD CONSTRAINT badge_issuance_rules_lms_provider_kind_check
  CHECK (lms_provider_kind IN ('canvas', 'sakai'));

ALTER TABLE badge_issuance_rule_versions
  DROP CONSTRAINT IF EXISTS badge_rule_version_snapshot_lms_provider_kind_check;

ALTER TABLE badge_issuance_rule_versions
  ADD CONSTRAINT badge_rule_version_snapshot_lms_provider_kind_check
  CHECK (snapshot_lms_provider_kind IN ('canvas', 'sakai'));

ALTER TABLE badge_issuance_rule_registry_projection
  DROP CONSTRAINT IF EXISTS badge_rule_registry_projection_lms_provider_kind_check;

ALTER TABLE badge_issuance_rule_registry_projection
  ADD CONSTRAINT badge_rule_registry_projection_lms_provider_kind_check
  CHECK (lms_provider_kind IN ('canvas', 'sakai'));
