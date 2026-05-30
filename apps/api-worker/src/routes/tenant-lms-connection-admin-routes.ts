import {
  createAuditLog,
  findTenantLmsConnectionById,
  upsertTenantLmsConnection,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import { parseTenantPathParams, parseUpsertTenantLmsConnectionRequest } from "@credtrail/validation";
import type { Hono } from "hono";
import {
  buildLmsConnectionsPagePath,
  lmsConnectionsPageUrl,
} from "../admin/lms-connection-admin-helpers";
import type { AppBindings, AppContext, AppEnv } from "../app";

interface RegisterTenantLmsConnectionAdminRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  resolveInstitutionAdminAdminRole: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<
    | Response
    | {
        session: { userId: string };
        membershipRole: TenantMembershipRole;
      }
  >;
}

const readOptionalFormField = (formData: FormData, name: string): string | undefined => {
  const raw = formData.get(name);

  if (typeof raw !== "string") {
    return undefined;
  }

  const trimmed = raw.trim();

  return trimmed.length > 0 ? trimmed : undefined;
};

const buildUpsertPayloadFromForm = (formData: FormData): Record<string, string> => {
  const payload: Record<string, string> = {
    displayName: readOptionalFormField(formData, "displayName") ?? "",
    providerKind: readOptionalFormField(formData, "providerKind") ?? "",
    apiBaseUrl: readOptionalFormField(formData, "apiBaseUrl") ?? "",
  };

  const optionalFields = [
    "accessToken",
    "refreshToken",
    "authorizationEndpoint",
    "tokenEndpoint",
    "clientId",
    "clientSecret",
    "scope",
    "ltiIssuer",
    "ltiClientId",
    "ltiDeploymentId",
  ] as const;

  for (const field of optionalFields) {
    const value = readOptionalFormField(formData, field);

    if (value !== undefined) {
      payload[field] = value;
    }
  }

  return payload;
};

export const registerTenantLmsConnectionAdminRoutes = (
  input: RegisterTenantLmsConnectionAdminRoutesInput,
): void => {
  const { app, resolveDatabase, resolveInstitutionAdminAdminRole } = input;

  app.post("/tenants/:tenantId/admin/access/lms-connections", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = buildLmsConnectionsPagePath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const formData = await c.req.formData();
    const connectionId = readOptionalFormField(formData, "connectionId") ?? "";
    const isUpdate = connectionId.length > 0;

    let request: ReturnType<typeof parseUpsertTenantLmsConnectionRequest>;

    try {
      request = parseUpsertTenantLmsConnectionRequest(buildUpsertPayloadFromForm(formData));
    } catch {
      return c.redirect(
        lmsConnectionsPageUrl(pathParams.tenantId, {
          listError: "Check the connection name, provider, and server URL, then try again.",
          ...(isUpdate ? { edit: connectionId } : {}),
        }),
        303,
      );
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);

    if (isUpdate) {
      const existing = await findTenantLmsConnectionById(db, {
        tenantId: pathParams.tenantId,
        connectionId,
      });

      if (existing === null) {
        return c.redirect(
          lmsConnectionsPageUrl(pathParams.tenantId, {
            listError: "LMS connection not found.",
          }),
          303,
        );
      }
    }

    const connection = await upsertTenantLmsConnection(db, {
      ...(isUpdate ? { id: connectionId } : {}),
      tenantId: pathParams.tenantId,
      ...request,
    });

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: isUpdate ? "tenant.lms_connection.updated" : "tenant.lms_connection.created",
      targetType: "tenant_lms_connection",
      targetId: connection.id,
      metadata: {
        role: membershipRole,
        providerKind: connection.providerKind,
      },
    });

    return c.redirect(
      lmsConnectionsPageUrl(pathParams.tenantId, {
        listNotice: isUpdate ? "LMS connection updated." : "LMS connection saved.",
      }),
      303,
    );
  });
};
