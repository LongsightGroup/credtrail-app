-- Delegated issuing authority grants scoped by org unit, actions, and optional badge templates.
CREATE TABLE IF NOT EXISTS delegated_issuing_authority_grants (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  delegate_user_id TEXT NOT NULL,
  delegated_by_user_id TEXT,
  org_unit_id TEXT NOT NULL,
  allowed_actions_json TEXT NOT NULL,
  starts_at TEXT NOT NULL,
  ends_at TEXT NOT NULL,
  revoked_at TEXT,
  revoked_by_user_id TEXT,
  revoked_reason TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CHECK (starts_at < ends_at),
  FOREIGN KEY (tenant_id, delegate_user_id)
    REFERENCES memberships (tenant_id, user_id) ON DELETE CASCADE,
  FOREIGN KEY (delegated_by_user_id)
    REFERENCES users (id) ON DELETE SET NULL,
  FOREIGN KEY (tenant_id, org_unit_id)
    REFERENCES tenant_org_units (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (revoked_by_user_id)
    REFERENCES users (id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS delegated_issuing_authority_grant_badge_templates (
  tenant_id TEXT NOT NULL,
  grant_id TEXT NOT NULL,
  badge_template_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tenant_id, grant_id, badge_template_id),
  FOREIGN KEY (tenant_id, grant_id)
    REFERENCES delegated_issuing_authority_grants (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, badge_template_id)
    REFERENCES badge_templates (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS delegated_issuing_authority_grant_events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  grant_id TEXT NOT NULL,
  event_type TEXT NOT NULL CHECK (event_type IN ('granted', 'revoked', 'expired')),
  actor_user_id TEXT,
  details_json TEXT,
  occurred_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (tenant_id, grant_id)
    REFERENCES delegated_issuing_authority_grants (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (actor_user_id)
    REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_delegated_grants_delegate_active
  ON delegated_issuing_authority_grants (tenant_id, delegate_user_id, revoked_at, starts_at, ends_at);

CREATE INDEX IF NOT EXISTS idx_delegated_grants_delegate_org
  ON delegated_issuing_authority_grants (tenant_id, delegate_user_id, org_unit_id);

CREATE INDEX IF NOT EXISTS idx_delegated_grants_org_unit
  ON delegated_issuing_authority_grants (tenant_id, org_unit_id);

CREATE INDEX IF NOT EXISTS idx_delegated_grant_badge_templates_template
  ON delegated_issuing_authority_grant_badge_templates (tenant_id, badge_template_id);

CREATE INDEX IF NOT EXISTS idx_delegated_grant_events_grant
  ON delegated_issuing_authority_grant_events (tenant_id, grant_id, occurred_at DESC);
