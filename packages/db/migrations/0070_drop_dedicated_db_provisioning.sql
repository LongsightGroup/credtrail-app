-- CredTrail v1 uses shared Postgres for every tenant; remove the unused dedicated-DB workflow.

DROP TABLE IF EXISTS tenant_dedicated_db_provisioning_requests;
