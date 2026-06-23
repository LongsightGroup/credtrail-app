-- Remove unused SAML enterprise SSO configuration and restrict auth providers to OIDC.

DELETE FROM tenant_auth_providers
WHERE protocol = 'saml';

UPDATE tenant_auth_policies
SET
  default_provider_id = NULL,
  updated_at = CURRENT_TIMESTAMP
WHERE default_provider_id IS NOT NULL
  AND default_provider_id NOT IN (
    SELECT id
    FROM tenant_auth_providers
  );

DROP TABLE IF EXISTS tenant_sso_saml_configurations;

ALTER TABLE tenant_auth_providers
  DROP CONSTRAINT IF EXISTS tenant_auth_providers_protocol_check,
  ADD CONSTRAINT tenant_auth_providers_protocol_check CHECK (protocol IN ('oidc'));
