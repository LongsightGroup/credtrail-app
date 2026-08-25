-- Validate the checks added by the 0078 repair after its transaction releases
-- ACCESS EXCLUSIVE locks. VALIDATE permits ordinary reads and writes.
ALTER TABLE badge_issuance_rules
  VALIDATE CONSTRAINT badge_issuance_rules_lms_provider_kind_check;

ALTER TABLE badge_issuance_rule_versions
  VALIDATE CONSTRAINT badge_rule_version_snapshot_lms_provider_kind_check;

ALTER TABLE badge_issuance_rule_registry_projection
  VALIDATE CONSTRAINT badge_rule_registry_projection_lms_provider_kind_check;
