-- Persist exact LMS course contexts and rule-level placement availability.

CREATE TABLE tenant_lms_course_contexts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  lms_connection_id TEXT NOT NULL,
  context_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  course_code TEXT,
  course_org_unit_id TEXT,
  created_by_user_id TEXT,
  first_seen_at TEXT,
  last_seen_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, lms_connection_id, context_id),
  CHECK (LENGTH(BTRIM(context_id)) > 0),
  CHECK (LENGTH(BTRIM(display_name)) > 0),
  CHECK (course_code IS NULL OR LENGTH(BTRIM(course_code)) > 0),
  CHECK (
    (first_seen_at IS NULL AND last_seen_at IS NULL)
    OR (
      first_seen_at IS NOT NULL
      AND last_seen_at IS NOT NULL
      AND first_seen_at::TIMESTAMPTZ <= last_seen_at::TIMESTAMPTZ
    )
  ),
  FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, lms_connection_id)
    REFERENCES tenant_lms_connections (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, course_org_unit_id)
    REFERENCES tenant_org_units (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX idx_tenant_lms_course_contexts_connection
  ON tenant_lms_course_contexts (tenant_id, lms_connection_id, display_name, context_id);

CREATE INDEX idx_tenant_lms_course_contexts_org_unit
  ON tenant_lms_course_contexts (tenant_id, course_org_unit_id)
  WHERE course_org_unit_id IS NOT NULL;

CREATE TABLE badge_rule_placement_availabilities (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  scope_type TEXT NOT NULL,
  root_org_unit_id TEXT,
  created_by_user_id TEXT,
  updated_by_user_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, rule_id),
  CHECK (scope_type IN ('selected_courses', 'org_unit_subtree', 'tenant')),
  CHECK (
    (scope_type = 'org_unit_subtree' AND root_org_unit_id IS NOT NULL)
    OR (scope_type IN ('selected_courses', 'tenant') AND root_org_unit_id IS NULL)
  ),
  FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, rule_id)
    REFERENCES badge_issuance_rules (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, root_org_unit_id)
    REFERENCES tenant_org_units (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE SET NULL,
  FOREIGN KEY (updated_by_user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX idx_badge_rule_placement_availabilities_rule
  ON badge_rule_placement_availabilities (tenant_id, rule_id);

CREATE INDEX idx_badge_rule_placement_availabilities_org_unit
  ON badge_rule_placement_availabilities (tenant_id, root_org_unit_id)
  WHERE root_org_unit_id IS NOT NULL;

CREATE TABLE badge_rule_placement_available_courses (
  tenant_id TEXT NOT NULL,
  availability_id TEXT NOT NULL,
  course_context_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tenant_id, availability_id, course_context_id),
  FOREIGN KEY (tenant_id, availability_id)
    REFERENCES badge_rule_placement_availabilities (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, course_context_id)
    REFERENCES tenant_lms_course_contexts (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_badge_rule_placement_available_courses_context
  ON badge_rule_placement_available_courses (tenant_id, course_context_id, availability_id);

CREATE OR REPLACE FUNCTION trg_tenant_lms_course_contexts_validate_mapping()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.course_org_unit_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1
      FROM tenant_org_units
      WHERE tenant_id = NEW.tenant_id
        AND id = NEW.course_org_unit_id
        AND unit_type = 'course'
    )
  THEN
    RAISE EXCEPTION 'LMS course contexts must map to a course org unit from the same tenant';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_tenant_lms_course_contexts_validate_mapping_insert
BEFORE INSERT ON tenant_lms_course_contexts
FOR EACH ROW
EXECUTE FUNCTION trg_tenant_lms_course_contexts_validate_mapping();

CREATE TRIGGER trg_tenant_lms_course_contexts_validate_mapping_update
BEFORE UPDATE OF tenant_id, course_org_unit_id ON tenant_lms_course_contexts
FOR EACH ROW
EXECUTE FUNCTION trg_tenant_lms_course_contexts_validate_mapping();

CREATE OR REPLACE FUNCTION trg_badge_rule_placement_availabilities_validate_root()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.scope_type = 'org_unit_subtree'
    AND NOT EXISTS (
      SELECT 1
      FROM tenant_org_units
      WHERE tenant_id = NEW.tenant_id
        AND id = NEW.root_org_unit_id
        AND unit_type IN ('institution', 'college', 'department', 'program')
    )
  THEN
    RAISE EXCEPTION 'Rule placement availability must use a non-course org-unit root';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_badge_rule_placement_availabilities_validate_root_insert
BEFORE INSERT ON badge_rule_placement_availabilities
FOR EACH ROW
EXECUTE FUNCTION trg_badge_rule_placement_availabilities_validate_root();

CREATE TRIGGER trg_badge_rule_placement_availabilities_validate_root_update
BEFORE UPDATE OF tenant_id, scope_type, root_org_unit_id ON badge_rule_placement_availabilities
FOR EACH ROW
EXECUTE FUNCTION trg_badge_rule_placement_availabilities_validate_root();

CREATE OR REPLACE FUNCTION trg_badge_rule_placement_available_courses_validate_parent()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM badge_rule_placement_availabilities
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.availability_id
      AND scope_type = 'selected_courses'
  ) THEN
    RAISE EXCEPTION 'Selected course targets require selected_courses availability';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_badge_rule_placement_available_courses_validate_parent_insert
BEFORE INSERT ON badge_rule_placement_available_courses
FOR EACH ROW
EXECUTE FUNCTION trg_badge_rule_placement_available_courses_validate_parent();

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM lti_resource_link_placements AS placements
    LEFT JOIN badge_issuance_rules AS rules
      ON rules.tenant_id = placements.tenant_id
      AND rules.id = placements.rule_id
    LEFT JOIN tenant_lms_connections AS connections
      ON connections.tenant_id = rules.tenant_id
      AND connections.id = rules.lms_connection_id
    WHERE placements.rule_id IS NOT NULL
      AND placements.context_id IS NOT NULL
      AND LENGTH(BTRIM(placements.context_id)) > 0
      AND connections.id IS NULL
  ) THEN
    RAISE EXCEPTION 'Cannot backfill LMS course contexts without an exact tenant LMS connection';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM lti_resource_link_placements AS placements
    INNER JOIN badge_issuance_rules AS rules
      ON rules.tenant_id = placements.tenant_id
      AND rules.id = placements.rule_id
    INNER JOIN tenant_org_units AS org_units
      ON org_units.tenant_id = rules.tenant_id
      AND org_units.id = rules.org_unit_id
      AND org_units.unit_type = 'course'
      AND org_units.is_active = 1
    WHERE placements.context_id IS NOT NULL
      AND LENGTH(BTRIM(placements.context_id)) > 0
    GROUP BY placements.tenant_id, rules.lms_connection_id, placements.context_id
    HAVING COUNT(DISTINCT org_units.id) > 1
  ) THEN
    RAISE EXCEPTION 'Cannot backfill an LMS course context with conflicting course org-unit mappings';
  END IF;
END;
$$;

WITH context_sources AS (
  SELECT
    placements.tenant_id,
    rules.lms_connection_id,
    placements.context_id,
    COALESCE(
      MAX(org_units.display_name) FILTER (
        WHERE org_units.unit_type = 'course' AND org_units.is_active = 1
      ),
      placements.context_id
    ) AS display_name,
    MAX(org_units.id) FILTER (
      WHERE org_units.unit_type = 'course' AND org_units.is_active = 1
    ) AS course_org_unit_id,
    MIN(placements.created_at) AS first_seen_at,
    MAX(placements.last_seen_at) AS last_seen_at,
    MIN(placements.created_at) AS created_at,
    MAX(placements.updated_at) AS updated_at
  FROM lti_resource_link_placements AS placements
  INNER JOIN badge_issuance_rules AS rules
    ON rules.tenant_id = placements.tenant_id
    AND rules.id = placements.rule_id
  LEFT JOIN tenant_org_units AS org_units
    ON org_units.tenant_id = rules.tenant_id
    AND org_units.id = rules.org_unit_id
  WHERE placements.rule_id IS NOT NULL
    AND placements.context_id IS NOT NULL
    AND LENGTH(BTRIM(placements.context_id)) > 0
  GROUP BY placements.tenant_id, rules.lms_connection_id, placements.context_id
)
INSERT INTO tenant_lms_course_contexts (
  id,
  tenant_id,
  lms_connection_id,
  context_id,
  display_name,
  course_code,
  course_org_unit_id,
  created_by_user_id,
  first_seen_at,
  last_seen_at,
  created_at,
  updated_at
)
SELECT
  'lctx_' || MD5(tenant_id || CHR(31) || lms_connection_id || CHR(31) || context_id),
  tenant_id,
  lms_connection_id,
  context_id,
  display_name,
  NULL,
  course_org_unit_id,
  NULL,
  first_seen_at,
  last_seen_at,
  created_at,
  updated_at
FROM context_sources;

INSERT INTO badge_rule_placement_availabilities (
  id,
  tenant_id,
  rule_id,
  scope_type,
  root_org_unit_id,
  created_by_user_id,
  updated_by_user_id,
  created_at,
  updated_at
)
SELECT
  'brpa_' || MD5(placements.tenant_id || CHR(31) || placements.rule_id),
  placements.tenant_id,
  placements.rule_id,
  'selected_courses',
  NULL,
  NULL,
  NULL,
  MIN(placements.created_at),
  MAX(placements.updated_at)
FROM lti_resource_link_placements AS placements
WHERE placements.rule_id IS NOT NULL
  AND placements.context_id IS NOT NULL
  AND LENGTH(BTRIM(placements.context_id)) > 0
GROUP BY placements.tenant_id, placements.rule_id;

INSERT INTO badge_rule_placement_available_courses (
  tenant_id,
  availability_id,
  course_context_id,
  created_at
)
SELECT DISTINCT
  placements.tenant_id,
  availability.id,
  course_context.id,
  MIN(placements.created_at) OVER (
    PARTITION BY placements.tenant_id, placements.rule_id, course_context.id
  )
FROM lti_resource_link_placements AS placements
INNER JOIN badge_issuance_rules AS rules
  ON rules.tenant_id = placements.tenant_id
  AND rules.id = placements.rule_id
INNER JOIN badge_rule_placement_availabilities AS availability
  ON availability.tenant_id = placements.tenant_id
  AND availability.rule_id = placements.rule_id
INNER JOIN tenant_lms_course_contexts AS course_context
  ON course_context.tenant_id = placements.tenant_id
  AND course_context.lms_connection_id = rules.lms_connection_id
  AND course_context.context_id = placements.context_id
WHERE placements.rule_id IS NOT NULL
  AND placements.context_id IS NOT NULL
  AND LENGTH(BTRIM(placements.context_id)) > 0;
