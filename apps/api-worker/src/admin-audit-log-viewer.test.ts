import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    listAuditLogs: vi.fn(),
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import { listAuditLogs, type AuditLogRecord, type SqlDatabase } from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { app } from "./index";
import { pageAssetPath } from "./ui/page-assets";

const mockedListAuditLogs = vi.mocked(listAuditLogs);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  BOOTSTRAP_ADMIN_TOKEN?: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
  };
};

const sampleAuditLogRecord = (overrides?: Partial<AuditLogRecord>): AuditLogRecord => {
  return {
    id: "aud_123",
    tenantId: "tenant_123",
    actorUserId: "usr_123",
    action: "membership.role_changed",
    targetType: "membership",
    targetId: "tenant_123:usr_456",
    metadataJson: '{"role":"admin"}',
    occurredAt: "2026-02-13T12:00:00.000Z",
    createdAt: "2026-02-13T12:00:00.000Z",
    ...overrides,
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);

  mockedListAuditLogs.mockReset();
  mockedListAuditLogs.mockResolvedValue([]);
});

describe("admin audit log viewer", () => {
  it("lists audit logs via bootstrap admin API", async () => {
    const env = {
      ...createEnv(),
      BOOTSTRAP_ADMIN_TOKEN: "bootstrap-secret",
    };
    mockedListAuditLogs.mockResolvedValue([sampleAuditLogRecord()]);

    const response = await app.request(
      "/v1/admin/audit-logs?tenantId=tenant_123&action=membership.role_changed&limit=5",
      {
        headers: {
          authorization: "Bearer bootstrap-secret",
        },
      },
      env,
    );
    const body = await response.json<{
      tenantId: string;
      action: string | null;
      limit: number;
      logs: AuditLogRecord[];
    }>();

    expect(response.status).toBe(200);
    expect(body.tenantId).toBe("tenant_123");
    expect(body.action).toBe("membership.role_changed");
    expect(body.limit).toBe(5);
    expect(body.logs).toHaveLength(1);
    expect(mockedListAuditLogs).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      action: "membership.role_changed",
      limit: 5,
    });
  });

  it("returns 400 for invalid audit-log query filters on admin API", async () => {
    const env = {
      ...createEnv(),
      BOOTSTRAP_ADMIN_TOKEN: "bootstrap-secret",
    };

    const response = await app.request(
      "/v1/admin/audit-logs?tenantId=tenant_123&limit=1000",
      {
        headers: {
          authorization: "Bearer bootstrap-secret",
        },
      },
      env,
    );

    expect(response.status).toBe(400);
    expect(mockedListAuditLogs).not.toHaveBeenCalled();
  });

  it("renders audit log viewer page and applies filters", async () => {
    const env = {
      ...createEnv(),
      BOOTSTRAP_ADMIN_TOKEN: "bootstrap-secret",
    };
    mockedListAuditLogs.mockResolvedValue([sampleAuditLogRecord()]);

    const response = await app.request(
      "/admin/audit-logs?token=bootstrap-secret&tenantId=tenant_123&action=membership.role_changed&limit=5",
      undefined,
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Audit log viewer");
    expect(body).toContain("membership.role_changed");
    expect(body).toContain(pageAssetPath("institutionAdminCss"));
    expect(body).toContain('class="ct-admin-content"');
    expect(body).toContain('class="ct-admin-page-header"');
    expect(body).toContain('class="ct-admin__form ct-admin__form--inline ct-grid"');
    expect(body).toContain('class="ct-admin__button"');
    expect(body).toContain('class="ct-admin__table"');
    expect(body).not.toContain('style="');
    expect(mockedListAuditLogs).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      action: "membership.role_changed",
      limit: 5,
    });
  });

  it("renders viewer page shell without querying when tenant filter is absent", async () => {
    const env = {
      ...createEnv(),
      BOOTSTRAP_ADMIN_TOKEN: "bootstrap-secret",
    };

    const response = await app.request("/admin/audit-logs?token=bootstrap-secret", undefined, env);
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Enter a tenant ID to load audit logs.");
    expect(mockedListAuditLogs).not.toHaveBeenCalled();
  });
});
