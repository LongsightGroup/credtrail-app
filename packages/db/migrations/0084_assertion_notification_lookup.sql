-- Support latest-outcome filtering without scanning a tenant's full audit history per badge.
CREATE INDEX IF NOT EXISTS idx_audit_logs_assertion_email_latest
  ON audit_logs (tenant_id, target_id, occurred_at DESC, created_at DESC, id DESC)
  WHERE action = 'assertion.issuance_email' AND target_type = 'assertion';
