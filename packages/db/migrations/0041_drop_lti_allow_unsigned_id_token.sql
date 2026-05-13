-- Remove the obsolete unsigned LTI launch compatibility flag. LTI launch
-- verification is signed-only and fail-closed.

ALTER TABLE lti_issuer_registrations
  DROP COLUMN IF EXISTS allow_unsigned_id_token;
