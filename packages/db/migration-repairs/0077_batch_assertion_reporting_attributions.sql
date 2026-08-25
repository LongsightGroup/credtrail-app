-- Bounded replacement for migration 0077. Range each ownership-history join by
-- assertion ID so one statement never has to process the full assertion table.
DO $$
DECLARE
  batch_after_id TEXT;
  batch_through_id TEXT;
  batch_size CONSTANT INTEGER := 10000;
BEGIN
  LOOP
    SELECT MAX(assertion_batch.id)
    INTO batch_through_id
    FROM (
      SELECT assertions.id
      FROM assertions
      WHERE batch_after_id IS NULL OR assertions.id > batch_after_id
      ORDER BY assertions.id
      LIMIT batch_size
    ) assertion_batch;

    EXIT WHEN batch_through_id IS NULL;

    INSERT INTO assertion_reporting_attributions (
      assertion_id,
      tenant_id,
      badge_template_id,
      org_unit_id,
      attribution_source,
      attributed_at,
      created_at,
      updated_at
    )
    SELECT
      assertions.id,
      assertions.tenant_id,
      assertions.badge_template_id,
      COALESCE(ownership_at_issue.to_org_unit_id, badge_templates.owner_org_unit_id),
      CASE
        WHEN ownership_at_issue.to_org_unit_id IS NULL THEN 'current_owner_fallback'
        ELSE 'historical_backfill'
      END,
      assertions.issued_at,
      CURRENT_TIMESTAMP,
      CURRENT_TIMESTAMP
    FROM assertions
    INNER JOIN badge_templates
      ON badge_templates.tenant_id = assertions.tenant_id
      AND badge_templates.id = assertions.badge_template_id
    LEFT JOIN LATERAL (
      SELECT ownership_events.to_org_unit_id
      FROM badge_template_ownership_events ownership_events
      WHERE ownership_events.tenant_id = assertions.tenant_id
        AND ownership_events.badge_template_id = assertions.badge_template_id
        AND ownership_events.transferred_at::timestamptz <= assertions.issued_at::timestamptz
      ORDER BY
        ownership_events.transferred_at::timestamptz DESC,
        ownership_events.created_at::timestamptz DESC,
        ownership_events.id DESC
      LIMIT 1
    ) ownership_at_issue ON TRUE
    LEFT JOIN assertion_reporting_attributions attribution
      ON attribution.assertion_id = assertions.id
    WHERE (batch_after_id IS NULL OR assertions.id > batch_after_id)
      AND assertions.id <= batch_through_id
      AND attribution.assertion_id IS NULL
    ON CONFLICT (assertion_id) DO NOTHING;

    batch_after_id := batch_through_id;
  END LOOP;
END $$;
