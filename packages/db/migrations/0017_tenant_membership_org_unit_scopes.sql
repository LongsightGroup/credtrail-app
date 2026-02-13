-- Add scoped RBAC bindings between tenant memberships and org-unit hierarchy.
CREATE TABLE IF NOT EXISTS tenant_membership_org_unit_scopes (
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  org_unit_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'issuer', 'viewer')),
  created_by_user_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tenant_id, user_id, org_unit_id),
  FOREIGN KEY (tenant_id, user_id)
    REFERENCES memberships (tenant_id, user_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, org_unit_id)
    REFERENCES tenant_org_units (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (created_by_user_id)
    REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_membership_org_scopes_tenant_user_role
  ON tenant_membership_org_unit_scopes (tenant_id, user_id, role);

CREATE INDEX IF NOT EXISTS idx_membership_org_scopes_tenant_org_unit
  ON tenant_membership_org_unit_scopes (tenant_id, org_unit_id);
