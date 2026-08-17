import {
  createAuditLog,
  createTenantApiKey,
  revokeTenantApiKey,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseCreateTenantApiKeyRequest,
  parseTenantApiKeyPathParams,
  parseTenantPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import { setAdminFlashCookie } from "../admin/admin-flash";
import { setAdminListMessageFlash } from "../admin/admin-list-message-flash";
import { buildApiKeysPagePath, tenantApiKeyAdminRevokePath } from "../admin/api-key-admin-helpers";
import type { AppContext, AppEnv } from "../app/types";
import type { ResolveDatabase } from "../app/route-deps";

interface RegisterTenantApiKeyAdminRoutesInput {
  app: Hono<AppEnv>;
  generateOpaqueToken: () => string;
  resolveDatabase: ResolveDatabase;
  sha256Hex: (value: string) => Promise<string>;
  resolveInstitutionAdminAdminRole: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<
    | Response
    | {
        principal: { userId: string };
        membershipRole: TenantMembershipRole;
      }
  >;
}

const parseScopesFromFormValue = (raw: FormDataEntryValue | null): string[] => {
  if (typeof raw !== "string") {
    return [];
  }

  return raw
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
};

export const registerTenantApiKeyAdminRoutes = (
  input: RegisterTenantApiKeyAdminRoutesInput,
): void => {
  const { app, generateOpaqueToken, resolveDatabase, sha256Hex, resolveInstitutionAdminAdminRole } =
    input;

  app.post("/tenants/:tenantId/admin/access/api-keys", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = buildApiKeysPagePath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const formData = await c.req.formData();
    const labelRaw = formData.get("label");
    const label = typeof labelRaw === "string" ? labelRaw.trim() : "";

    let request: ReturnType<typeof parseCreateTenantApiKeyRequest>;

    try {
      request = parseCreateTenantApiKeyRequest({
        label,
        scopes: parseScopesFromFormValue(formData.get("scopes")),
      });
    } catch {
      await setAdminListMessageFlash(c, {
        tenantId: pathParams.tenantId,
        userId: roleCheck.principal.userId,
        workspace: "access_api_keys",
        tone: "error",
        message: "Enter a label and valid scopes for the API key.",
      });

      return c.redirect(buildApiKeysPagePath(pathParams.tenantId), 303);
    }

    const { principal, membershipRole } = roleCheck;
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
      createdByUserId: principal.userId,
      expiresAt: request.expiresAt,
    });

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      actorUserId: principal.userId,
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

    await setAdminFlashCookie(c, {
      kind: "api_key_secret",
      tenantId: pathParams.tenantId,
      userId: principal.userId,
      value: rawApiKey,
    });
    await setAdminListMessageFlash(c, {
      tenantId: pathParams.tenantId,
      userId: principal.userId,
      workspace: "access_api_keys",
      tone: "success",
      message: "API key created. Store the secret before leaving this page.",
    });

    return c.redirect(buildApiKeysPagePath(pathParams.tenantId), 303);
  });

  app.post("/tenants/:tenantId/admin/access/api-keys/:apiKeyId/revoke", async (c) => {
    const pathParams = parseTenantApiKeyPathParams(c.req.param());
    const nextPath = tenantApiKeyAdminRevokePath(pathParams.tenantId, pathParams.apiKeyId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { principal, membershipRole } = roleCheck;
    const revokedAt = new Date().toISOString();
    const revoked = await revokeTenantApiKey(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      apiKeyId: pathParams.apiKeyId,
      revokedAt,
    });

    if (revoked) {
      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        actorUserId: principal.userId,
        action: "tenant.api_key_revoked",
        targetType: "tenant_api_key",
        targetId: pathParams.apiKeyId,
        metadata: {
          role: membershipRole,
          revokedAt,
        },
      });
    }

    await setAdminListMessageFlash(c, {
      tenantId: pathParams.tenantId,
      userId: principal.userId,
      workspace: "access_api_keys",
      tone: "success",
      message: revoked ? "API key revoked." : "API key was already revoked.",
    });

    return c.redirect(buildApiKeysPagePath(pathParams.tenantId), 303);
  });
};
