-- Keep one canonical completion handoff per learner-pathway enrollment.

WITH ranked_handoffs AS (
  SELECT
    handoffs.id,
    ROW_NUMBER() OVER (
      PARTITION BY handoffs.tenant_id, handoffs.enrollment_id
      ORDER BY
        CASE WHEN handoffs.status = 'issued' THEN 0 ELSE 1 END,
        evaluations.sequence_number DESC,
        handoffs.created_at DESC,
        handoffs.id DESC
    ) AS handoff_rank
  FROM learner_pathway_completion_handoffs AS handoffs
  INNER JOIN learner_pathway_evaluations AS evaluations
    ON evaluations.tenant_id = handoffs.tenant_id
    AND evaluations.id = handoffs.evaluation_id
)
DELETE FROM learner_pathway_completion_handoffs AS handoffs
USING ranked_handoffs
WHERE handoffs.id = ranked_handoffs.id
  AND ranked_handoffs.handoff_rank > 1;

ALTER TABLE learner_pathway_completion_handoffs
  ADD CONSTRAINT learner_pathway_completion_handoffs_enrollment_key
  UNIQUE (tenant_id, enrollment_id);

-- Deliver learner evidence projection work through the existing durable DB queue.

ALTER TABLE job_queue_messages
  DROP CONSTRAINT IF EXISTS job_queue_messages_job_type_check;

ALTER TABLE job_queue_messages
  ADD CONSTRAINT job_queue_messages_job_type_check
  CHECK (
    job_type IN (
      'issue_badge',
      'revoke_badge',
      'rebuild_verification_cache',
      'import_migration_batch',
      'import_learner_record_batch',
      'generate_badge_template_image',
      'process_badge_rule_lifecycle',
      'process_automated_badge_rule',
      'send_badge_rule_approval_notification',
      'process_learner_evidence_change'
    )
  );

-- Project mutable badge-rule registry fields once so registry reads can use indexes.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE badge_issuance_rule_registry_projection (
  tenant_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  org_unit_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  badge_title TEXT NOT NULL,
  lms_provider_kind TEXT NOT NULL,
  current_version_number INTEGER NOT NULL DEFAULT 0,
  latest_version_number INTEGER NOT NULL DEFAULT 0,
  latest_status TEXT,
  registry_updated_at TEXT NOT NULL,
  search_text TEXT GENERATED ALWAYS AS (
    LOWER(display_name || ' ' || badge_title || ' ' || lms_provider_kind || ' ' || rule_id)
  ) STORED,
  PRIMARY KEY (tenant_id, rule_id),
  FOREIGN KEY (tenant_id, rule_id)
    REFERENCES badge_issuance_rules (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_badge_rule_registry_name
  ON badge_issuance_rule_registry_projection (tenant_id, LOWER(display_name), rule_id);

CREATE INDEX idx_badge_rule_registry_badge
  ON badge_issuance_rule_registry_projection (tenant_id, LOWER(badge_title), rule_id);

CREATE INDEX idx_badge_rule_registry_lms
  ON badge_issuance_rule_registry_projection (tenant_id, lms_provider_kind, rule_id);

CREATE INDEX idx_badge_rule_registry_current_version
  ON badge_issuance_rule_registry_projection
  (tenant_id, current_version_number, rule_id);

CREATE INDEX idx_badge_rule_registry_latest_version
  ON badge_issuance_rule_registry_projection
  (tenant_id, latest_version_number, rule_id);

CREATE INDEX idx_badge_rule_registry_updated
  ON badge_issuance_rule_registry_projection
  (tenant_id, registry_updated_at, rule_id);

CREATE INDEX idx_badge_rule_registry_status
  ON badge_issuance_rule_registry_projection
  (tenant_id, latest_status, registry_updated_at, rule_id);

CREATE INDEX idx_badge_rule_registry_search
  ON badge_issuance_rule_registry_projection USING GIN (search_text gin_trgm_ops);

CREATE OR REPLACE FUNCTION refresh_badge_issuance_rule_registry_projection(
  projection_tenant_id TEXT,
  projection_rule_id TEXT
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO badge_issuance_rule_registry_projection (
    tenant_id,
    rule_id,
    org_unit_id,
    display_name,
    badge_title,
    lms_provider_kind,
    current_version_number,
    latest_version_number,
    latest_status,
    registry_updated_at
  )
  SELECT
    rules.tenant_id,
    rules.id,
    rules.org_unit_id,
    COALESCE(active_version.snapshot_name, latest_version.snapshot_name, rules.name),
    COALESCE(
      active_version.snapshot_badge_template_title,
      latest_version.snapshot_badge_template_title,
      templates.title
    ),
    COALESCE(
      active_version.snapshot_lms_provider_kind,
      latest_version.snapshot_lms_provider_kind,
      rules.lms_provider_kind
    ),
    COALESCE(active_version.version_number, 0),
    COALESCE(latest_version.version_number, 0),
    latest_version.status,
    COALESCE(active_version.updated_at, latest_version.updated_at, rules.updated_at)
  FROM badge_issuance_rules AS rules
  INNER JOIN badge_templates AS templates
    ON templates.tenant_id = rules.tenant_id
    AND templates.id = rules.badge_template_id
  LEFT JOIN LATERAL (
    SELECT versions.*
    FROM badge_issuance_rule_versions AS versions
    WHERE versions.tenant_id = rules.tenant_id
      AND versions.rule_id = rules.id
    ORDER BY versions.version_number DESC
    LIMIT 1
  ) AS latest_version ON TRUE
  LEFT JOIN badge_issuance_rule_versions AS active_version
    ON active_version.tenant_id = rules.tenant_id
    AND active_version.rule_id = rules.id
    AND active_version.id = rules.active_version_id
  WHERE rules.tenant_id = projection_tenant_id
    AND rules.id = projection_rule_id
  ON CONFLICT (tenant_id, rule_id) DO UPDATE SET
    org_unit_id = EXCLUDED.org_unit_id,
    display_name = EXCLUDED.display_name,
    badge_title = EXCLUDED.badge_title,
    lms_provider_kind = EXCLUDED.lms_provider_kind,
    current_version_number = EXCLUDED.current_version_number,
    latest_version_number = EXCLUDED.latest_version_number,
    latest_status = EXCLUDED.latest_status,
    registry_updated_at = EXCLUDED.registry_updated_at;
END;
$$;

CREATE OR REPLACE FUNCTION refresh_badge_rule_registry_from_rule()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM refresh_badge_issuance_rule_registry_projection(NEW.tenant_id, NEW.id);
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION refresh_badge_rule_registry_from_version()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    PERFORM refresh_badge_issuance_rule_registry_projection(OLD.tenant_id, OLD.rule_id);
    RETURN OLD;
  END IF;

  PERFORM refresh_badge_issuance_rule_registry_projection(NEW.tenant_id, NEW.rule_id);
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_refresh_badge_rule_registry_from_rule
AFTER INSERT OR UPDATE ON badge_issuance_rules
FOR EACH ROW
EXECUTE FUNCTION refresh_badge_rule_registry_from_rule();

CREATE TRIGGER trg_refresh_badge_rule_registry_from_version
AFTER INSERT OR UPDATE OR DELETE ON badge_issuance_rule_versions
FOR EACH ROW
EXECUTE FUNCTION refresh_badge_rule_registry_from_version();

CREATE OR REPLACE FUNCTION refresh_badge_rule_registry_from_template()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  affected_rule RECORD;
BEGIN
  FOR affected_rule IN
    SELECT rules.tenant_id, rules.id
    FROM badge_issuance_rules AS rules
    WHERE rules.tenant_id = NEW.tenant_id
      AND rules.badge_template_id = NEW.id
  LOOP
    PERFORM refresh_badge_issuance_rule_registry_projection(
      affected_rule.tenant_id,
      affected_rule.id
    );
  END LOOP;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_refresh_badge_rule_registry_from_template
AFTER UPDATE OF title ON badge_templates
FOR EACH ROW
WHEN (OLD.title IS DISTINCT FROM NEW.title)
EXECUTE FUNCTION refresh_badge_rule_registry_from_template();

SELECT refresh_badge_issuance_rule_registry_projection(tenant_id, id)
FROM badge_issuance_rules;
