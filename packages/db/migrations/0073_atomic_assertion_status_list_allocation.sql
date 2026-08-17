-- Allocate assertion status-list indexes atomically per tenant.

CREATE TABLE assertion_status_list_counters (
  tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  next_index INTEGER NOT NULL CHECK (next_index >= 0)
);

INSERT INTO assertion_status_list_counters (tenant_id, next_index)
SELECT tenant_id, COALESCE(MAX(status_list_index), -1) + 1
FROM assertions
GROUP BY tenant_id
ON CONFLICT (tenant_id) DO UPDATE
SET next_index = GREATEST(
  assertion_status_list_counters.next_index,
  EXCLUDED.next_index
);

DROP INDEX IF EXISTS idx_assertions_tenant_status_list_index;

CREATE UNIQUE INDEX idx_assertions_tenant_status_list_index
  ON assertions (tenant_id, status_list_index)
  WHERE status_list_index IS NOT NULL;
