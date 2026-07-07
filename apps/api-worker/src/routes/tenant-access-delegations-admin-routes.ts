import {
  createAuditLog,
  createDelegatedIssuingAuthorityGrant,
  findDelegatedIssuingAuthorityGrantById,
  revokeDelegatedIssuingAuthorityGrant,
} from "@credtrail/db";
import {
  parseCreateDelegatedIssuingAuthorityGrantRequest,
  parseRevokeDelegatedIssuingAuthorityGrantRequest,
  parseTenantPathParams,
} from "@credtrail/validation";
import {
  buildAccessDelegationsAdminPath,
  buildAccessDelegationsNewPath,
} from "../admin/access-admin-helpers";
import { readOptionalFormField } from "../admin/admin-form-helpers";
import { redirectWithAdminListFlash } from "../admin/admin-list-flash-redirect";
import type { AppContext } from "../app";
import type { TenantAccessAdminRouteDeps } from "./tenant-access-admin-route-deps";

const redirectToDelegations = (
  c: AppContext,
  input: {
    tenantId: string;
    userId: string;
    tone: "success" | "error";
    message: string;
  },
): Promise<Response> => {
  return redirectWithAdminListFlash(c, {
    ...input,
    workspace: "access_delegations",
    path: buildAccessDelegationsAdminPath(input.tenantId),
  });
};

const redirectToDelegationsNew = (
  c: AppContext,
  input: {
    tenantId: string;
    userId: string;
    tone: "success" | "error";
    message: string;
  },
): Promise<Response> => {
  return redirectWithAdminListFlash(c, {
    ...input,
    workspace: "access_delegations_new",
    path: buildAccessDelegationsNewPath(input.tenantId),
  });
};

const readBadgeTemplateIdsFromForm = (formData: FormData): string[] => {
  const raw = formData.get("badgeTemplateIds");

  if (typeof raw !== "string") {
    return [];
  }

  const trimmed = raw.trim();

  return trimmed.length > 0 ? [trimmed] : [];
};

const mapDelegationErrorMessage = (error: unknown): string => {
  if (!(error instanceof Error)) {
    return "Unable to save the delegation. Check the delegate, org unit, actions, and end time.";
  }

  if (error.message.includes("conflicts with existing grant")) {
    return "This delegation overlaps an existing grant for the same person and org unit.";
  }

  if (error.message.includes("Membership not found for tenant")) {
    return "Choose a tenant member who already belongs to this organization.";
  }

  if (error.message.includes("Org unit") && error.message.includes("not found for tenant")) {
    return "Choose an org unit that belongs to this organization.";
  }

  if (error.message.includes("Badge template") && error.message.includes("not found for tenant")) {
    return "Choose a badge template that belongs to this organization.";
  }

  if (error.message.includes("must be after") || error.message.includes("valid ISO timestamp")) {
    return "Choose a valid end date and time for this delegation.";
  }

  return "Unable to save the delegation. Check the delegate, org unit, actions, and end time.";
};

export const registerTenantAccessDelegationsAdminRoutes = (
  input: TenantAccessAdminRouteDeps,
): void => {
  const { app, resolveDatabase, resolveInstitutionAdminAdminRole } = input;

  app.post("/tenants/:tenantId/admin/access/delegations", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = buildAccessDelegationsNewPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const formData = await c.req.formData();
    const delegateUserId = readOptionalFormField(formData, "delegateUserId") ?? "";
    const orgUnitId = readOptionalFormField(formData, "orgUnitId") ?? "";
    const endsAtLocal = readOptionalFormField(formData, "endsAt") ?? "";
    const reason = readOptionalFormField(formData, "reason");
    const allowedActions = formData
      .getAll("allowedAction")
      .map((value) => (typeof value === "string" ? value.trim() : ""))
      .filter((value) => value.length > 0);
    const badgeTemplateIds = readBadgeTemplateIdsFromForm(formData);

    if (delegateUserId.length === 0 || orgUnitId.length === 0) {
      return redirectToDelegationsNew(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Choose a delegate and org unit before saving.",
      });
    }

    if (allowedActions.length === 0) {
      return redirectToDelegationsNew(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Select at least one allowed badge action.",
      });
    }

    if (endsAtLocal.length === 0) {
      return redirectToDelegationsNew(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Choose when this delegation should end.",
      });
    }

    const parsedEndsAtMs = Date.parse(endsAtLocal);

    if (!Number.isFinite(parsedEndsAtMs)) {
      return redirectToDelegationsNew(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Choose a valid end date and time for this delegation.",
      });
    }

    const endsAtIso = new Date(parsedEndsAtMs).toISOString();

    let request: ReturnType<typeof parseCreateDelegatedIssuingAuthorityGrantRequest>;

    try {
      request = parseCreateDelegatedIssuingAuthorityGrantRequest({
        orgUnitId,
        allowedActions,
        ...(badgeTemplateIds.length > 0 ? { badgeTemplateIds } : {}),
        endsAt: endsAtIso,
        ...(reason !== undefined ? { reason } : {}),
      });
    } catch {
      return redirectToDelegationsNew(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Check the delegate, org unit, allowed actions, and end time, then try again.",
      });
    }

    const db = resolveDatabase(c.env);

    try {
      const grant = await createDelegatedIssuingAuthorityGrant(db, {
        tenantId: pathParams.tenantId,
        delegateUserId,
        delegatedByUserId: session.userId,
        orgUnitId: request.orgUnitId,
        allowedActions: request.allowedActions,
        badgeTemplateIds: request.badgeTemplateIds,
        startsAt: request.startsAt ?? new Date().toISOString(),
        endsAt: request.endsAt,
        reason: request.reason,
      });

      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "delegated_issuing_authority.granted",
        targetType: "delegated_issuing_authority_grant",
        targetId: grant.id,
        metadata: {
          role: membershipRole,
          delegateUserId,
          orgUnitId: request.orgUnitId,
          allowedActions: request.allowedActions,
          badgeTemplateIds: request.badgeTemplateIds ?? [],
          startsAt: grant.startsAt,
          endsAt: request.endsAt,
        },
      });

      return redirectToDelegations(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "success",
        message: `Delegation saved for ${delegateUserId}.`,
      });
    } catch (error: unknown) {
      return redirectToDelegationsNew(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: mapDelegationErrorMessage(error),
      });
    }
  });

  app.post("/tenants/:tenantId/admin/access/delegations/revoke", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = buildAccessDelegationsAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const formData = await c.req.formData();
    const delegateUserId = readOptionalFormField(formData, "delegateUserId") ?? "";
    const grantId = readOptionalFormField(formData, "grantId") ?? "";
    const reason = readOptionalFormField(formData, "reason");

    if (delegateUserId.length === 0 || grantId.length === 0) {
      return redirectToDelegations(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Delegation identifiers are missing.",
      });
    }

    let request: ReturnType<typeof parseRevokeDelegatedIssuingAuthorityGrantRequest>;

    try {
      request = parseRevokeDelegatedIssuingAuthorityGrantRequest(
        reason !== undefined ? { reason } : {},
      );
    } catch {
      return redirectToDelegations(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Unable to remove this delegation.",
      });
    }

    const db = resolveDatabase(c.env);
    const existingGrant = await findDelegatedIssuingAuthorityGrantById(
      db,
      pathParams.tenantId,
      grantId,
    );

    if (existingGrant === null || existingGrant.delegateUserId !== delegateUserId) {
      return redirectToDelegations(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "That delegation was not found.",
      });
    }

    const revokedAt = request.revokedAt ?? new Date().toISOString();

    let revokeResult: Awaited<ReturnType<typeof revokeDelegatedIssuingAuthorityGrant>>;

    try {
      revokeResult = await revokeDelegatedIssuingAuthorityGrant(db, {
        tenantId: pathParams.tenantId,
        grantId,
        revokedByUserId: session.userId,
        revokedReason: request.reason,
        revokedAt,
      });
    } catch {
      return redirectToDelegations(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "That delegation is no longer active.",
      });
    }

    if (revokeResult.status !== "revoked") {
      return redirectToDelegations(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "That delegation is no longer active.",
      });
    }

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "delegated_issuing_authority.revoked",
      targetType: "delegated_issuing_authority_grant",
      targetId: grantId,
      metadata: {
        role: membershipRole,
        delegateUserId,
        reason: request.reason ?? null,
      },
    });

    return redirectToDelegations(c, {
      tenantId: pathParams.tenantId,
      userId: session.userId,
      tone: "success",
      message: "Delegation removed.",
    });
  });
};
