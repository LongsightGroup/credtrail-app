-- Safe replacement for migration 0078 on installations that have not applied
-- it yet. Remove restrictive dependents before deleting unsupported rules.
DELETE FROM assertion_issuance_provenance AS provenance
USING badge_issuance_rules AS rules
WHERE provenance.tenant_id = rules.tenant_id
  AND provenance.rule_id = rules.id
  AND rules.lms_provider_kind NOT IN ('canvas', 'sakai');

UPDATE lti_resource_link_placements AS placements
SET rule_id = NULL
FROM badge_issuance_rules AS rules
WHERE placements.rule_id = rules.id
  AND rules.lms_provider_kind NOT IN ('canvas', 'sakai');

DELETE FROM badge_issuance_rules
WHERE lms_provider_kind NOT IN ('canvas', 'sakai');

-- Adding an unvalidated check only takes the heavyweight table lock long
-- enough to update metadata. Migration 0079 validates after this transaction.
ALTER TABLE badge_issuance_rules
  DROP CONSTRAINT IF EXISTS badge_issuance_rules_lms_provider_kind_check;

ALTER TABLE badge_issuance_rules
  ADD CONSTRAINT badge_issuance_rules_lms_provider_kind_check
  CHECK (lms_provider_kind IN ('canvas', 'sakai'))
  NOT VALID;

ALTER TABLE badge_issuance_rule_versions
  DROP CONSTRAINT IF EXISTS badge_rule_version_snapshot_lms_provider_kind_check;

ALTER TABLE badge_issuance_rule_versions
  ADD CONSTRAINT badge_rule_version_snapshot_lms_provider_kind_check
  CHECK (snapshot_lms_provider_kind IN ('canvas', 'sakai'))
  NOT VALID;

ALTER TABLE badge_issuance_rule_registry_projection
  DROP CONSTRAINT IF EXISTS badge_rule_registry_projection_lms_provider_kind_check;

ALTER TABLE badge_issuance_rule_registry_projection
  ADD CONSTRAINT badge_rule_registry_projection_lms_provider_kind_check
  CHECK (lms_provider_kind IN ('canvas', 'sakai'))
  NOT VALID;
