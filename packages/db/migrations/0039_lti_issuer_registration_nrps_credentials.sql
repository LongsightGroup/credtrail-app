ALTER TABLE lti_issuer_registrations
  ADD COLUMN IF NOT EXISTS token_endpoint TEXT;

ALTER TABLE lti_issuer_registrations
  ADD COLUMN IF NOT EXISTS client_secret TEXT;
