-- Move badge rule approval governance from author-entered rule drafts to tenant/org-unit policy.

ALTER TABLE badge_issuance_rules
  ADD COLUMN IF NOT EXISTS owner_org_unit_id TEXT;

UPDATE badge_issuance_rules
SET owner_org_unit_id = badge_templates.owner_org_unit_id
FROM badge_templates
WHERE badge_issuance_rules.tenant_id = badge_templates.tenant_id
  AND badge_issuance_rules.badge_template_id = badge_templates.id
  AND badge_issuance_rules.owner_org_unit_id IS NULL;

UPDATE badge_issuance_rules
SET owner_org_unit_id = tenant_id || ':org:institution'
WHERE owner_org_unit_id IS NULL;

ALTER TABLE badge_issuance_rules
  ALTER COLUMN owner_org_unit_id SET NOT NULL;

ALTER TABLE badge_issuance_rules
  DROP CONSTRAINT IF EXISTS fk_badge_issuance_rules_owner_org_unit;

ALTER TABLE badge_issuance_rules
  ADD CONSTRAINT fk_badge_issuance_rules_owner_org_unit
  FOREIGN KEY (tenant_id, owner_org_unit_id)
  REFERENCES tenant_org_units (tenant_id, id)
  ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_badge_issuance_rules_tenant_owner_org_unit
  ON badge_issuance_rules (tenant_id, owner_org_unit_id);

CREATE TABLE IF NOT EXISTS badge_rule_approval_policies (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  org_unit_id TEXT,
  approval_requirement TEXT NOT NULL CHECK (approval_requirement IN ('always', 'never')),
  approval_steps_json TEXT NOT NULL,
  created_by_user_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, org_unit_id) REFERENCES tenant_org_units (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_badge_rule_approval_policies_tenant_default
  ON badge_rule_approval_policies (tenant_id)
  WHERE org_unit_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_badge_rule_approval_policies_tenant_org_unit
  ON badge_rule_approval_policies (tenant_id, org_unit_id)
  WHERE org_unit_id IS NOT NULL;

-- Store the tenant-wide governance default so normal resolution reads policy from DB.
INSERT INTO badge_rule_approval_policies (
  id,
  tenant_id,
  org_unit_id,
  approval_requirement,
  approval_steps_json,
  created_by_user_id,
  created_at,
  updated_at
)
SELECT
  tenants.id || ':badge-rule-approval-policy:default',
  tenants.id,
  NULL,
  'always',
  '[{"requiredRole":"admin","label":"Administrative approval"}]',
  NULL,
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
FROM tenants
ON CONFLICT DO NOTHING;
