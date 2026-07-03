-- Make badge issuance rules first-class org-unit scoped records and add course org units.

ALTER TABLE tenant_org_units
  DROP CONSTRAINT IF EXISTS tenant_org_units_unit_type_check;

ALTER TABLE tenant_org_units
  ADD CONSTRAINT tenant_org_units_unit_type_check
  CHECK (unit_type IN ('institution', 'college', 'department', 'program', 'course'));

CREATE OR REPLACE FUNCTION trg_tenant_org_units_validate_hierarchy()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  parent_unit_type TEXT;
BEGIN
  IF NEW.unit_type = 'institution' THEN
    IF NEW.parent_org_unit_id IS NOT NULL THEN
      RAISE EXCEPTION 'institution org units cannot have a parent';
    END IF;

    RETURN NEW;
  END IF;

  IF NEW.parent_org_unit_id IS NULL THEN
    RAISE EXCEPTION '% org units require a parent', NEW.unit_type;
  END IF;

  SELECT unit_type
  INTO parent_unit_type
  FROM tenant_org_units
  WHERE tenant_id = NEW.tenant_id
    AND id = NEW.parent_org_unit_id;

  IF parent_unit_type IS NULL THEN
    RAISE EXCEPTION 'org unit parent must belong to the same tenant';
  END IF;

  IF NEW.unit_type = 'college' AND parent_unit_type <> 'institution' THEN
    RAISE EXCEPTION 'college org units require an institution parent';
  END IF;

  IF NEW.unit_type = 'department' AND parent_unit_type <> 'college' THEN
    RAISE EXCEPTION 'department org units require a college parent';
  END IF;

  IF NEW.unit_type = 'program' AND parent_unit_type <> 'department' THEN
    RAISE EXCEPTION 'program org units require a department parent';
  END IF;

  IF NEW.unit_type = 'course' AND parent_unit_type NOT IN ('department', 'program') THEN
    RAISE EXCEPTION 'course org units require a department or program parent';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_tenant_org_units_validate_hierarchy_insert ON tenant_org_units;
CREATE TRIGGER trg_tenant_org_units_validate_hierarchy_insert
BEFORE INSERT ON tenant_org_units
FOR EACH ROW
EXECUTE FUNCTION trg_tenant_org_units_validate_hierarchy();

DROP TRIGGER IF EXISTS trg_tenant_org_units_validate_hierarchy_update ON tenant_org_units;
CREATE TRIGGER trg_tenant_org_units_validate_hierarchy_update
BEFORE UPDATE OF tenant_id, unit_type, parent_org_unit_id ON tenant_org_units
FOR EACH ROW
EXECUTE FUNCTION trg_tenant_org_units_validate_hierarchy();

ALTER TABLE badge_issuance_rules
  ADD COLUMN IF NOT EXISTS org_unit_id TEXT;

UPDATE badge_issuance_rules
SET org_unit_id = owner_org_unit_id
WHERE org_unit_id IS NULL;

UPDATE badge_issuance_rules
SET org_unit_id = tenant_id || ':org:institution'
WHERE org_unit_id IS NULL;

ALTER TABLE badge_issuance_rules
  ALTER COLUMN org_unit_id SET NOT NULL;

COMMENT ON COLUMN badge_issuance_rules.org_unit_id IS
  'Canonical org-unit scope for badge rule governance, delegated visibility, LTI course ownership, and reporting.';

COMMENT ON COLUMN badge_issuance_rules.owner_org_unit_id IS
  'Snapshot of the selected badge template owner org unit at rule create or draft edit time. Template ownership metadata only; rule governance resolves against badge_issuance_rules.org_unit_id.';

ALTER TABLE badge_issuance_rules
  DROP CONSTRAINT IF EXISTS fk_badge_issuance_rules_org_unit;

ALTER TABLE badge_issuance_rules
  ADD CONSTRAINT fk_badge_issuance_rules_org_unit
  FOREIGN KEY (tenant_id, org_unit_id)
  REFERENCES tenant_org_units (tenant_id, id)
  ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_badge_issuance_rules_tenant_org_unit
  ON badge_issuance_rules (tenant_id, org_unit_id);
