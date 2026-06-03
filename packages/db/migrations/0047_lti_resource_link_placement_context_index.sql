CREATE INDEX IF NOT EXISTS idx_lti_resource_link_placements_context_lookup
  ON lti_resource_link_placements (
    tenant_id,
    issuer,
    client_id,
    deployment_id,
    context_id,
    created_at DESC,
    id DESC
  );
