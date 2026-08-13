COMMENT ON COLUMN badge_issuance_rules.owner_org_unit_id IS
  'Snapshot of the selected badge template owner org unit at rule create or draft edit time. Badge rule approval policy resolves against this captured scope.';

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
