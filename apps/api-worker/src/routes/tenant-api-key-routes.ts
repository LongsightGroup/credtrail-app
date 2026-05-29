import {
  createAuditLog,
  createTenantApiKey,
  listTenantApiKeys,
  revokeTenantApiKey,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseCreateTenantApiKeyRequest,
  parseRevokeTenantApiKeyRequest,
  parseTenantApiKeyListQuery,
  parseTenantApiKeyPathParams,
  parseTenantPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import { renderTenantApiKeyAdminTableRowToString } from "../admin/api-key-table-row-fragment";
import type { AppBindings, AppContext, AppEnv } from "../app";

interface RegisterTenantApiKeyRoutesInput {
  app: Hono<AppEnv>;
  generateOpaqueToken: () => string;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  sha256Hex: (value: string) => Promise<string>;
  requireTenantRole: (
    c: AppContext,
    tenantId: string,
    allowedRoles: readonly TenantMembershipRole[],
  ) => Promise<
    | {
        session: SessionRecord;
        membershipRole: TenantMembershipRole;
      }
    | Response
  >;
  ADMIN_ROLES: readonly TenantMembershipRole[];
}

export const registerTenantApiKeyRoutes = (input: RegisterTenantApiKeyRoutesInput): void => {
  const { app, generateOpaqueToken, resolveDatabase, sha256Hex, requireTenantRole, ADMIN_ROLES } =
    input;

  app.get("/v1/tenants/:tenantId/api-keys", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const query = parseTenantApiKeyListQuery({
      includeRevoked: c.req.query("includeRevoked"),
    });
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const keys = await listTenantApiKeys(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      includeRevoked: query.includeRevoked,
    });

    return c.json({
      tenantId: pathParams.tenantId,
      keys: keys.map((key) => ({
        id: key.id,
        tenantId: key.tenantId,
        label: key.label,
        keyPrefix: key.keyPrefix,
        scopesJson: key.scopesJson,
        createdByUserId: key.createdByUserId,
        expiresAt: key.expiresAt,
        lastUsedAt: key.lastUsedAt,
        revokedAt: key.revokedAt,
        createdAt: key.createdAt,
        updatedAt: key.updatedAt,
      })),
    });
  });

  app.post("/v1/tenants/:tenantId/api-keys", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let request: ReturnType<typeof parseCreateTenantApiKeyRequest>;

    try {
      request = parseCreateTenantApiKeyRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid API key payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const rawApiKey = `ctak_${generateOpaqueToken()}${generateOpaqueToken()}`;
    const keyHash = await sha256Hex(rawApiKey);
    const keyPrefix = rawApiKey.slice(0, 12);
    const scopes =
      request.scopes === undefined || request.scopes.length === 0
        ? ["queue.issue", "queue.revoke"]
        : request.scopes;
    const keyRecord = await createTenantApiKey(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      label: request.label,
      keyPrefix,
      keyHash,
      scopesJson: JSON.stringify(scopes),
      createdByUserId: session.userId,
      expiresAt: request.expiresAt,
    });

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "tenant.api_key_created",
      targetType: "tenant_api_key",
      targetId: keyRecord.id,
      metadata: {
        role: membershipRole,
        label: keyRecord.label,
        keyPrefix: keyRecord.keyPrefix,
        scopes,
        expiresAt: keyRecord.expiresAt,
      },
    });

    return c.json(
      {
        tenantId: pathParams.tenantId,
        apiKey: rawApiKey,
        key: {
          id: keyRecord.id,
          label: keyRecord.label,
          keyPrefix: keyRecord.keyPrefix,
          scopesJson: keyRecord.scopesJson,
          createdByUserId: keyRecord.createdByUserId,
          expiresAt: keyRecord.expiresAt,
          revokedAt: keyRecord.revokedAt,
          createdAt: keyRecord.createdAt,
        },
        rowHtml: renderTenantApiKeyAdminTableRowToString({
          tenantId: pathParams.tenantId,
          apiKey: keyRecord,
        }),
      },
      201,
    );
  });

  app.post("/v1/tenants/:tenantId/api-keys/:apiKeyId/revoke", async (c) => {
    const pathParams = parseTenantApiKeyPathParams(c.req.param());
    let request: ReturnType<typeof parseRevokeTenantApiKeyRequest>;

    try {
      let payload: unknown = {};

      try {
        payload = await c.req.json<unknown>();
      } catch {
        payload = {};
      }

      request = parseRevokeTenantApiKeyRequest(payload);
    } catch {
      return c.json(
        {
          error: "Invalid API key revoke payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const revokedAt = request.revokedAt ?? new Date().toISOString();
    const revoked = await revokeTenantApiKey(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      apiKeyId: pathParams.apiKeyId,
      revokedAt,
    });

    if (revoked) {
      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "tenant.api_key_revoked",
        targetType: "tenant_api_key",
        targetId: pathParams.apiKeyId,
        metadata: {
          role: membershipRole,
          revokedAt,
        },
      });
    }

    return c.json({
      tenantId: pathParams.tenantId,
      apiKeyId: pathParams.apiKeyId,
      revoked,
    });
  });
};
