ALTER TABLE lti_resource_link_placements
  ADD COLUMN IF NOT EXISTS rule_id TEXT;

CREATE INDEX IF NOT EXISTS idx_lti_resource_link_placements_rule
  ON lti_resource_link_placements (tenant_id, rule_id);

ALTER TABLE lti_resource_link_placements
  ADD CONSTRAINT lti_resource_link_placements_rule_fkey
  FOREIGN KEY (rule_id)
  REFERENCES badge_issuance_rules (id)
  ON DELETE SET NULL;
