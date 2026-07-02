import {
  createAuditLog,
  createTenantAuthProvider,
  deleteTenantAuthProvider,
  ensureTenantMembership,
  findTenantAuthProviderById,
  revokeTenantBreakGlassAccount,
  updateTenantAuthProvider,
  upsertTenantAuthPolicy,
  upsertTenantBreakGlassAccount,
  upsertUserByEmail,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseCreateTenantBreakGlassAccountRequest,
  parseTenantPathParams,
  parseUpsertTenantAuthPolicyRequest,
  parseUpsertTenantAuthProviderRequest,
} from "@credtrail/validation";
import type { Hono } from "hono";
import { accessAuthenticationPageUrl } from "../admin/access-admin-helpers";
import { readOptionalFormField } from "../admin/admin-form-helpers";
import { setAdminListMessageFlash } from "../admin/admin-list-message-flash";
import type { AppContext, AppEnv } from "../app";
import type { ResolveDatabase } from "../app/route-deps";
import { breakGlassPasswordResetEnrollmentStatus } from "../auth/break-glass-policy";

interface RegisterTenantAccessEnterpriseAdminRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  requireEnterpriseTenant: (
    c: AppContext,
    tenantId: string,
    db: SqlDatabase,
  ) => Promise<Response | null>;
  requestBreakGlassPasswordReset?: (
    c: AppContext,
    input: {
      tenantId: string;
      email: string;
    },
  ) => Promise<"sent" | "unavailable">;
  resolveInstitutionAdminAdminRole: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<
    | Response
    | {
        session: SessionRecord;
        membershipRole: TenantMembershipRole;
      }
  >;
}

const redirectToAuthentication = async (
  c: AppContext,
  input: {
    tenantId: string;
    userId: string;
    tone: "success" | "error";
    message: string;
    extra?: Record<string, string>;
  },
): Promise<Response> => {
  await setAdminListMessageFlash(c, {
    tenantId: input.tenantId,
    userId: input.userId,
    workspace: "access_authentication",
    tone: input.tone,
    message: input.message,
  });

  return c.redirect(accessAuthenticationPageUrl(input.tenantId, input.extra), 303);
};

export const registerTenantAccessEnterpriseAdminRoutes = (
  input: RegisterTenantAccessEnterpriseAdminRoutesInput,
): void => {
  const {
    app,
    resolveDatabase,
    requireEnterpriseTenant,
    requestBreakGlassPasswordReset,
    resolveInstitutionAdminAdminRole,
  } = input;

  app.post("/tenants/:tenantId/admin/access/authentication/policy", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = accessAuthenticationPageUrl(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    const formData = await c.req.formData();
    const loginMode = readOptionalFormField(formData, "loginMode");
    const defaultProviderId = readOptionalFormField(formData, "defaultProviderId");

    let request: ReturnType<typeof parseUpsertTenantAuthPolicyRequest>;

    try {
      request = parseUpsertTenantAuthPolicyRequest({
        loginMode,
        breakGlassEnabled: formData.get("breakGlassEnabled") !== null,
        localMfaRequired: formData.get("localMfaRequired") !== null,
        defaultProviderId: defaultProviderId ?? null,
      });
    } catch {
      return redirectToAuthentication(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Check the login mode and default provider, then try again.",
      });
    }

    if (request.defaultProviderId !== undefined && request.defaultProviderId !== null) {
      const provider = await findTenantAuthProviderById(
        db,
        pathParams.tenantId,
        request.defaultProviderId,
      );

      if (provider === null) {
        return redirectToAuthentication(c, {
          tenantId: pathParams.tenantId,
          userId: session.userId,
          tone: "error",
          message: "Default auth provider not found.",
        });
      }
    }

    const policy = await upsertTenantAuthPolicy(db, {
      tenantId: pathParams.tenantId,
      loginMode: request.loginMode,
      breakGlassEnabled: request.breakGlassEnabled,
      localMfaRequired: request.localMfaRequired,
      defaultProviderId: request.defaultProviderId,
    });

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "tenant.auth_policy_upserted",
      targetType: "tenant_auth_policy",
      targetId: pathParams.tenantId,
      metadata: {
        role: membershipRole,
        loginMode: policy.loginMode,
        breakGlassEnabled: policy.breakGlassEnabled,
        localMfaRequired: policy.localMfaRequired,
        defaultProviderId: policy.defaultProviderId,
        enforceForRoles: policy.enforceForRoles,
      },
    });

    return redirectToAuthentication(c, {
      tenantId: pathParams.tenantId,
      userId: session.userId,
      tone: "success",
      message: "Enterprise auth policy saved.",
    });
  });

  app.post("/tenants/:tenantId/admin/access/authentication/providers", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = accessAuthenticationPageUrl(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    const formData = await c.req.formData();
    const providerId = readOptionalFormField(formData, "providerId") ?? "";
    const protocol = readOptionalFormField(formData, "protocol") ?? "oidc";
    const label = readOptionalFormField(formData, "label") ?? "";
    const configJson = readOptionalFormField(formData, "configJson") ?? "";
    const isUpdate = providerId.length > 0;

    let request: ReturnType<typeof parseUpsertTenantAuthProviderRequest>;

    try {
      request = parseUpsertTenantAuthProviderRequest({
        protocol,
        label,
        enabled: formData.get("enabled") !== null,
        isDefault: formData.get("isDefault") !== null,
        configJson,
      });
    } catch {
      return redirectToAuthentication(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Check the provider label and OIDC configuration JSON, then try again.",
        ...(isUpdate ? { editProvider: providerId } : {}),
      });
    }

    if (isUpdate) {
      const existing = await findTenantAuthProviderById(db, pathParams.tenantId, providerId);

      if (existing === null) {
        return redirectToAuthentication(c, {
          tenantId: pathParams.tenantId,
          userId: session.userId,
          tone: "error",
          message: "Enterprise auth provider not found.",
        });
      }

      const updatedProvider = await updateTenantAuthProvider(db, {
        tenantId: pathParams.tenantId,
        providerId,
        protocol: request.protocol,
        label: request.label,
        enabled: request.enabled,
        isDefault: request.isDefault,
        configJson: request.configJson,
      });

      if (updatedProvider === null) {
        return redirectToAuthentication(c, {
          tenantId: pathParams.tenantId,
          userId: session.userId,
          tone: "error",
          message: "Enterprise auth provider not found.",
        });
      }

      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "tenant.auth_provider_updated",
        targetType: "tenant_auth_provider",
        targetId: updatedProvider.id,
        metadata: {
          role: membershipRole,
          protocol: updatedProvider.protocol,
          label: updatedProvider.label,
        },
      });

      return redirectToAuthentication(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "success",
        message: `Updated enterprise auth provider “${updatedProvider.label}”.`,
      });
    }

    const provider = await createTenantAuthProvider(db, {
      tenantId: pathParams.tenantId,
      protocol: request.protocol,
      label: request.label,
      enabled: request.enabled,
      isDefault: request.isDefault,
      configJson: request.configJson,
    });

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "tenant.auth_provider_created",
      targetType: "tenant_auth_provider",
      targetId: provider.id,
      metadata: {
        role: membershipRole,
        protocol: provider.protocol,
        label: provider.label,
      },
    });

    return redirectToAuthentication(c, {
      tenantId: pathParams.tenantId,
      userId: session.userId,
      tone: "success",
      message: `Created enterprise auth provider “${provider.label}”.`,
    });
  });

  app.post("/tenants/:tenantId/admin/access/authentication/providers/delete", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = accessAuthenticationPageUrl(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    const providerId = readOptionalFormField(await c.req.formData(), "providerId") ?? "";

    if (providerId.length === 0) {
      return redirectToAuthentication(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Provider ID missing from delete action.",
      });
    }

    const existing = await findTenantAuthProviderById(db, pathParams.tenantId, providerId);

    if (existing === null) {
      return redirectToAuthentication(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Enterprise auth provider not found.",
      });
    }

    await deleteTenantAuthProvider(db, pathParams.tenantId, providerId);

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "tenant.auth_provider_deleted",
      targetType: "tenant_auth_provider",
      targetId: providerId,
      metadata: {
        role: membershipRole,
        label: existing.label,
      },
    });

    return redirectToAuthentication(c, {
      tenantId: pathParams.tenantId,
      userId: session.userId,
      tone: "success",
      message: `Deleted enterprise auth provider “${existing.label}”.`,
    });
  });

  app.post("/tenants/:tenantId/admin/access/authentication/break-glass-accounts", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = accessAuthenticationPageUrl(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    const formData = await c.req.formData();
    const email = readOptionalFormField(formData, "email") ?? "";

    let request: ReturnType<typeof parseCreateTenantBreakGlassAccountRequest>;

    try {
      request = parseCreateTenantBreakGlassAccountRequest({
        email,
        sendEnrollmentEmail: formData.get("sendEnrollmentEmail") !== null,
      });
    } catch {
      return redirectToAuthentication(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Enter an institution email for the break-glass account.",
      });
    }

    const user = await upsertUserByEmail(db, request.email);
    const membershipResult = await ensureTenantMembership(db, pathParams.tenantId, user.id);
    await upsertTenantBreakGlassAccount(db, {
      tenantId: pathParams.tenantId,
      userId: user.id,
      createdByUserId: session.userId,
    });
    const passwordResetStatus = await breakGlassPasswordResetEnrollmentStatus(
      requestBreakGlassPasswordReset,
      c,
      {
        tenantId: pathParams.tenantId,
        email: request.email,
        sendEnrollmentEmail: request.sendEnrollmentEmail !== false,
      },
    );

    if (membershipResult.created) {
      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "membership.role_assigned",
        targetType: "membership",
        targetId: `${pathParams.tenantId}:${user.id}`,
        metadata: {
          userId: user.id,
          role: membershipResult.membership.role,
        },
      });
    }

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "tenant.break_glass_account_upserted",
      targetType: "tenant_break_glass_account",
      targetId: `${pathParams.tenantId}:${user.id}`,
      metadata: {
        role: membershipRole,
        email: request.email,
        sendEnrollmentEmail: request.sendEnrollmentEmail !== false,
        passwordResetStatus,
      },
    });

    const enrollmentNote =
      passwordResetStatus === "failed"
        ? " Setup email could not be sent."
        : passwordResetStatus === "sent"
          ? " Setup email sent."
          : "";

    return redirectToAuthentication(c, {
      tenantId: pathParams.tenantId,
      userId: session.userId,
      tone: passwordResetStatus === "failed" ? "error" : "success",
      message: `Break-glass account saved for ${request.email}.${enrollmentNote}`,
    });
  });

  app.post(
    "/tenants/:tenantId/admin/access/authentication/break-glass-accounts/revoke",
    async (c) => {
      const pathParams = parseTenantPathParams(c.req.param());
      const nextPath = accessAuthenticationPageUrl(pathParams.tenantId);
      const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const { session, membershipRole } = roleCheck;
      const db = resolveDatabase(c.env);
      const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

      if (enterpriseCheck !== null) {
        return enterpriseCheck;
      }

      const userId = readOptionalFormField(await c.req.formData(), "userId") ?? "";

      if (userId.length === 0) {
        return redirectToAuthentication(c, {
          tenantId: pathParams.tenantId,
          userId: session.userId,
          tone: "error",
          message: "Break-glass account user ID is missing.",
        });
      }

      const revoked = await revokeTenantBreakGlassAccount(db, {
        tenantId: pathParams.tenantId,
        userId,
        revokedAt: new Date().toISOString(),
      });

      if (!revoked) {
        return redirectToAuthentication(c, {
          tenantId: pathParams.tenantId,
          userId: session.userId,
          tone: "error",
          message: "Break-glass account was not found.",
        });
      }

      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "tenant.break_glass_account_revoked",
        targetType: "tenant_break_glass_account",
        targetId: `${pathParams.tenantId}:${userId}`,
        metadata: {
          role: membershipRole,
        },
      });

      return redirectToAuthentication(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "success",
        message: "Break-glass access revoked.",
      });
    },
  );
};
