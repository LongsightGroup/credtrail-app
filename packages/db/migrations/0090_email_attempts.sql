-- Persist the claim before contacting a mail provider. Pending means acceptance is unknown.
CREATE TABLE email_attempts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT REFERENCES tenants(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('magic_link', 'password_reset', 'member_invite', 'issuance', 'rule_approval', 'rule_lifecycle')),
  target_id TEXT,
  recipient_email TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'accepted', 'failed', 'skipped')),
  reason TEXT CHECK (reason IN ('not_configured', 'development', 'render_failed', 'provider_rejected', 'provider_uncertain')),
  provider_message_id TEXT,
  deduplication_key TEXT,
  created_at TEXT NOT NULL,
  completed_at TEXT,
  CHECK ((status = 'pending' AND completed_at IS NULL) OR (status <> 'pending' AND completed_at IS NOT NULL)),
  CHECK (status <> 'skipped' OR (reason IS NOT NULL AND reason IN ('not_configured', 'development'))),
  CHECK (status <> 'failed' OR (reason IS NOT NULL AND reason IN ('render_failed', 'provider_rejected'))),
  CHECK (status <> 'pending' OR reason IS NULL OR reason = 'provider_uncertain'),
  CHECK ((status = 'accepted' AND reason IS NULL AND provider_message_id IS NOT NULL AND length(provider_message_id) > 0)
    OR (status <> 'accepted' AND provider_message_id IS NULL))
);
CREATE INDEX idx_email_attempts_tenant_created ON email_attempts (tenant_id, created_at DESC, id DESC);
CREATE INDEX idx_email_attempts_target ON email_attempts (tenant_id, kind, target_id, created_at DESC);
-- Accepted and uncertain messages must never be resent by an automatic reminder rerun.
CREATE UNIQUE INDEX idx_email_attempts_deduplication ON email_attempts (deduplication_key)
  WHERE deduplication_key IS NOT NULL AND status IN ('pending', 'accepted');
