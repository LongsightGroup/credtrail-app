ALTER TABLE badge_templates
ADD COLUMN IF NOT EXISTS trusted_credential_metadata_json TEXT;
