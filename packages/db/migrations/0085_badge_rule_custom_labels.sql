ALTER TABLE badge_issuance_rules
  ADD COLUMN custom_label TEXT CHECK (
    custom_label IS NULL OR (length(btrim(custom_label)) BETWEEN 1 AND 200)
  );

-- Preserve existing explicit labels when moving naming out of governed requirements.
UPDATE badge_issuance_rules AS rules
SET custom_label = NULLIF(btrim(version.rule_json::jsonb ->> 'customLabel'), '')
FROM badge_issuance_rule_versions AS version
WHERE version.tenant_id = rules.tenant_id
  AND version.rule_id = rules.id
  AND version.id = COALESCE(rules.active_version_id, (
    SELECT latest.id FROM badge_issuance_rule_versions AS latest
    WHERE latest.tenant_id = rules.tenant_id AND latest.rule_id = rules.id
    ORDER BY latest.version_number DESC LIMIT 1
  ));

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
    COALESCE(rules.custom_label, rules.name),
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


SELECT refresh_badge_issuance_rule_registry_projection(tenant_id, id)
FROM badge_issuance_rules;
