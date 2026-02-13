-- Add institution-owned badge registry primitives and immutable ownership history.
CREATE TABLE IF NOT EXISTS tenant_org_units (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  unit_type TEXT NOT NULL CHECK (unit_type IN ('institution', 'college', 'department', 'program')),
  slug TEXT NOT NULL,
  display_name TEXT NOT NULL,
  parent_org_unit_id TEXT,
  created_by_user_id TEXT,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, slug),
  FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
  FOREIGN KEY (parent_org_unit_id) REFERENCES tenant_org_units (id) ON DELETE SET NULL,
  FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_tenant_org_units_tenant_type
  ON tenant_org_units (tenant_id, unit_type, is_active);

CREATE INDEX IF NOT EXISTS idx_tenant_org_units_tenant_parent
  ON tenant_org_units (tenant_id, parent_org_unit_id);

-- Each tenant gets a deterministic default institution org unit for ownership fallback.
INSERT OR IGNORE INTO tenant_org_units (
  id,
  tenant_id,
  unit_type,
  slug,
  display_name,
  parent_org_unit_id,
  created_by_user_id,
  is_active,
  created_at,
  updated_at
)
SELECT
  tenants.id || ':org:institution',
  tenants.id,
  'institution',
  'institution',
  tenants.display_name || ' Institution',
  NULL,
  NULL,
  1,
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
FROM tenants;

ALTER TABLE badge_templates
  ADD COLUMN owner_org_unit_id TEXT;

ALTER TABLE badge_templates
  ADD COLUMN governance_metadata_json TEXT;

-- Backfill existing templates into deterministic institution ownership.
UPDATE badge_templates
SET owner_org_unit_id = tenant_id || ':org:institution'
WHERE owner_org_unit_id IS NULL;

UPDATE badge_templates
SET governance_metadata_json = '{"stability":"institution_registry"}'
WHERE governance_metadata_json IS NULL;

CREATE INDEX IF NOT EXISTS idx_badge_templates_tenant_owner_org_unit
  ON badge_templates (tenant_id, owner_org_unit_id);

CREATE TRIGGER IF NOT EXISTS trg_badge_templates_validate_owner_insert
BEFORE INSERT ON badge_templates
FOR EACH ROW
BEGIN
  SELECT RAISE(ABORT, 'badge_templates.owner_org_unit_id is required')
  WHERE NEW.owner_org_unit_id IS NULL;

  SELECT RAISE(ABORT, 'badge_templates.governance_metadata_json is required')
  WHERE NEW.governance_metadata_json IS NULL;

  SELECT RAISE(
    ABORT,
    'badge_templates.owner_org_unit_id must reference a tenant org unit from the same tenant'
  )
  WHERE NOT EXISTS (
    SELECT 1
    FROM tenant_org_units
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.owner_org_unit_id
  );
END;

CREATE TRIGGER IF NOT EXISTS trg_badge_templates_validate_owner_update
BEFORE UPDATE OF tenant_id, owner_org_unit_id, governance_metadata_json ON badge_templates
FOR EACH ROW
BEGIN
  SELECT RAISE(ABORT, 'badge_templates.owner_org_unit_id is required')
  WHERE NEW.owner_org_unit_id IS NULL;

  SELECT RAISE(ABORT, 'badge_templates.governance_metadata_json is required')
  WHERE NEW.governance_metadata_json IS NULL;

  SELECT RAISE(
    ABORT,
    'badge_templates.owner_org_unit_id must reference a tenant org unit from the same tenant'
  )
  WHERE NOT EXISTS (
    SELECT 1
    FROM tenant_org_units
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.owner_org_unit_id
  );
END;

CREATE TABLE IF NOT EXISTS badge_template_ownership_events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  badge_template_id TEXT NOT NULL,
  from_org_unit_id TEXT,
  to_org_unit_id TEXT NOT NULL,
  reason_code TEXT NOT NULL CHECK (
    reason_code IN (
      'initial_assignment',
      'administrative_transfer',
      'reorganization',
      'governance_policy_update',
      'other'
    )
  ),
  reason TEXT,
  governance_metadata_json TEXT,
  transferred_by_user_id TEXT,
  transferred_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (tenant_id, badge_template_id)
    REFERENCES badge_templates (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (from_org_unit_id) REFERENCES tenant_org_units (id) ON DELETE SET NULL,
  FOREIGN KEY (to_org_unit_id) REFERENCES tenant_org_units (id) ON DELETE RESTRICT,
  FOREIGN KEY (transferred_by_user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_badge_template_ownership_events_template
  ON badge_template_ownership_events (tenant_id, badge_template_id, transferred_at DESC);

CREATE INDEX IF NOT EXISTS idx_badge_template_ownership_events_to_org
  ON badge_template_ownership_events (tenant_id, to_org_unit_id, transferred_at DESC);

CREATE TRIGGER IF NOT EXISTS trg_badge_template_ownership_events_validate_insert
BEFORE INSERT ON badge_template_ownership_events
FOR EACH ROW
BEGIN
  SELECT RAISE(
    ABORT,
    'badge_template_ownership_events.to_org_unit_id must reference a tenant org unit from the same tenant'
  )
  WHERE NOT EXISTS (
    SELECT 1
    FROM tenant_org_units
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.to_org_unit_id
  );

  SELECT RAISE(
    ABORT,
    'badge_template_ownership_events.from_org_unit_id must reference a tenant org unit from the same tenant'
  )
  WHERE NEW.from_org_unit_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1
      FROM tenant_org_units
      WHERE tenant_id = NEW.tenant_id
        AND id = NEW.from_org_unit_id
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_badge_template_ownership_events_immutable_update
BEFORE UPDATE ON badge_template_ownership_events
FOR EACH ROW
BEGIN
  SELECT RAISE(ABORT, 'badge_template_ownership_events is immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_badge_template_ownership_events_immutable_delete
BEFORE DELETE ON badge_template_ownership_events
FOR EACH ROW
BEGIN
  SELECT RAISE(ABORT, 'badge_template_ownership_events is immutable');
END;

-- Backfill initial immutable assignment events for existing templates.
INSERT OR IGNORE INTO badge_template_ownership_events (
  id,
  tenant_id,
  badge_template_id,
  from_org_unit_id,
  to_org_unit_id,
  reason_code,
  reason,
  governance_metadata_json,
  transferred_by_user_id,
  transferred_at,
  created_at
)
SELECT
  badge_templates.id || ':ownership:initial',
  badge_templates.tenant_id,
  badge_templates.id,
  NULL,
  badge_templates.owner_org_unit_id,
  'initial_assignment',
  'Seeded during institutional ownership migration',
  badge_templates.governance_metadata_json,
  badge_templates.created_by_user_id,
  badge_templates.created_at,
  badge_templates.created_at
FROM badge_templates
WHERE badge_templates.owner_org_unit_id IS NOT NULL;
