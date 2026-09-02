ALTER TABLE lti_resource_link_placements
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active',
  ADD COLUMN IF NOT EXISTS last_seen_at TEXT,
  ADD COLUMN IF NOT EXISTS retired_at TEXT,
  ADD COLUMN IF NOT EXISTS retired_by_user_id TEXT;

UPDATE lti_resource_link_placements
SET last_seen_at = updated_at
WHERE last_seen_at IS NULL;

ALTER TABLE lti_resource_link_placements
  ALTER COLUMN last_seen_at SET NOT NULL;

ALTER TABLE lti_resource_link_placements
  ADD CONSTRAINT lti_resource_link_placements_status_check
  CHECK (status IN ('active', 'retired')),
  ADD CONSTRAINT lti_resource_link_placements_lifecycle_check
  CHECK (
    (
      status = 'active'
      AND retired_at IS NULL
      AND retired_by_user_id IS NULL
    )
    OR
    (
      status = 'retired'
      AND retired_at IS NOT NULL
      AND retired_by_user_id IS NOT NULL
    )
  ),
  ADD CONSTRAINT lti_resource_link_placements_retired_by_user_fkey
  FOREIGN KEY (retired_by_user_id)
  REFERENCES users (id)
  ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_lti_resource_link_placements_context_status
  ON lti_resource_link_placements (
    tenant_id,
    issuer,
    client_id,
    deployment_id,
    context_id,
    status,
    last_seen_at DESC
  );

CREATE INDEX IF NOT EXISTS idx_lti_resource_link_placements_rule_status
  ON lti_resource_link_placements (tenant_id, rule_id, status, last_seen_at DESC);
