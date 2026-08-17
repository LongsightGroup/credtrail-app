import {
  findAssertionById,
  findBadgeTemplateById,
  recordAssertionLifecycleTransition,
  type DelegatedIssuingAuthorityAction,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseAssertionLifecycleTransitionRequest,
  parseTenantPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import { setAdminListMessageFlash } from "../admin/admin-list-message-flash";
import {
  issuedBadgesPageUrl,
  parseIssuedBadgesPageQuery,
  tenantIssuedBadgeAdminRevokePath,
} from "../admin/issued-badges-admin-helpers";
import type { AppContext, AppEnv } from "../app/types";
import type {
  RequireDelegatedIssuingAuthorityPermission,
  ResolveDatabase,
} from "../app/route-deps";

const issuedBadgeRevokePermissionError =
  "You do not have permission to revoke this badge for the selected template.";

interface RegisterTenantIssuedBadgesAdminRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  requireDelegatedIssuingAuthorityPermission: RequireDelegatedIssuingAuthorityPermission;
  assertionBelongsToTenant: (tenantId: string, assertionId: string) => boolean;
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

const readOptionalFormField = (formData: FormData, name: string): string | undefined => {
  const raw = formData.get(name);

  if (typeof raw !== "string") {
    return undefined;
  }

  const trimmed = raw.trim();

  return trimmed.length > 0 ? trimmed : undefined;
};

const readFilterFieldsFromForm = (
  formData: FormData,
): ReturnType<typeof parseIssuedBadgesPageQuery>["filters"] => {
  const issuedFrom = readOptionalFormField(formData, "issuedFrom");
  const issuedTo = readOptionalFormField(formData, "issuedTo");
  const recipientQuery = readOptionalFormField(formData, "recipientQuery");
  const badgeTemplateId = readOptionalFormField(formData, "badgeTemplateId");
  const orgUnitId = readOptionalFormField(formData, "orgUnitId");
  const state = readOptionalFormField(formData, "state");
  const limitRaw = formData.get("limit");

  return parseIssuedBadgesPageQuery({
    ...(issuedFrom === undefined ? {} : { issuedFrom }),
    ...(issuedTo === undefined ? {} : { issuedTo }),
    ...(recipientQuery === undefined ? {} : { recipientQuery }),
    ...(badgeTemplateId === undefined ? {} : { badgeTemplateId }),
    ...(orgUnitId === undefined ? {} : { orgUnitId }),
    ...(state === undefined ? {} : { state }),
    limit: typeof limitRaw === "string" && limitRaw.trim().length > 0 ? limitRaw.trim() : "100",
  }).filters;
};

const redirectIssuedBadgesWithFlash = async (
  c: AppContext,
  input: {
    tenantId: string;
    userId: string;
    tone: "success" | "error";
    message: string;
    filters: ReturnType<typeof parseIssuedBadgesPageQuery>["filters"];
    extra?: Record<string, string>;
  },
): Promise<Response> => {
  await setAdminListMessageFlash(c, {
    tenantId: input.tenantId,
    userId: input.userId,
    workspace: "issued_badges",
    tone: input.tone,
    message: input.message,
  });

  return c.redirect(issuedBadgesPageUrl(input.tenantId, input.filters, input.extra), 303);
};

export const registerTenantIssuedBadgesAdminRoutes = (
  input: RegisterTenantIssuedBadgesAdminRoutesInput,
): void => {
  const {
    app,
    resolveDatabase,
    requireDelegatedIssuingAuthorityPermission,
    assertionBelongsToTenant,
    resolveInstitutionAdminAdminRole,
  } = input;

  app.post("/tenants/:tenantId/admin/operations/issued-badges/revoke", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = tenantIssuedBadgeAdminRevokePath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const formData = await c.req.formData();
    const filters = readFilterFieldsFromForm(formData);
    const assertionIdRaw = formData.get("assertionId");
    const assertionId = typeof assertionIdRaw === "string" ? assertionIdRaw.trim() : "";

    const { principal, membershipRole } = roleCheck;

    if (assertionId.length === 0) {
      return redirectIssuedBadgesWithFlash(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "error",
        message: "Choose a badge before revoking it.",
        filters,
      });
    }

    if (!assertionBelongsToTenant(pathParams.tenantId, assertionId)) {
      return redirectIssuedBadgesWithFlash(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "error",
        message: "Badge not found for this institution.",
        filters,
      });
    }

    let request: ReturnType<typeof parseAssertionLifecycleTransitionRequest>;

    try {
      request = parseAssertionLifecycleTransitionRequest({
        toState: "revoked",
        reasonCode: formData.get("reasonCode"),
        reason: formData.get("reason"),
        transitionSource: "manual",
      });
    } catch {
      return redirectIssuedBadgesWithFlash(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "error",
        message: "Choose a reason code before revoking this badge.",
        filters,
        extra: {
          lifecycle: assertionId,
          lifecycleMode: "revoke",
        },
      });
    }

    const db = resolveDatabase(c.env);
    const assertion = await findAssertionById(db, pathParams.tenantId, assertionId);

    if (assertion === null) {
      return redirectIssuedBadgesWithFlash(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "error",
        message: "Badge not found for this institution.",
        filters,
      });
    }

    const badgeTemplate = await findBadgeTemplateById(
      db,
      pathParams.tenantId,
      assertion.badgeTemplateId,
    );

    if (badgeTemplate === null) {
      return redirectIssuedBadgesWithFlash(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "error",
        message: "Badge template not found for this institution.",
        filters,
      });
    }

    const requiredAction: DelegatedIssuingAuthorityAction = "revoke_badge";
    const delegatedPermission = await requireDelegatedIssuingAuthorityPermission(c, {
      db,
      tenantId: pathParams.tenantId,
      userId: principal.userId,
      membershipRole,
      ownerOrgUnitId: badgeTemplate.ownerOrgUnitId,
      badgeTemplateId: badgeTemplate.id,
      requiredAction,
    });

    if (delegatedPermission !== null) {
      return redirectIssuedBadgesWithFlash(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "error",
        message: issuedBadgeRevokePermissionError,
        filters,
        extra: {
          lifecycle: assertionId,
          lifecycleMode: "revoke",
        },
      });
    }

    const transitionResult = await recordAssertionLifecycleTransition(db, {
      tenantId: pathParams.tenantId,
      assertionId,
      toState: request.toState,
      reasonCode: request.reasonCode,
      ...(request.reason === undefined ? {} : { reason: request.reason }),
      transitionSource: "manual",
      actorUserId: principal.userId,
      transitionedAt: request.transitionedAt ?? new Date().toISOString(),
    });

    if (transitionResult.status === "invalid_transition") {
      return redirectIssuedBadgesWithFlash(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "error",
        message: transitionResult.message ?? "Lifecycle transition not allowed",
        filters,
        extra: {
          lifecycle: assertionId,
          lifecycleMode: "revoke",
        },
      });
    }

    const notice =
      transitionResult.status === "already_in_state"
        ? "Badge was already revoked."
        : "Badge revoked.";

    return redirectIssuedBadgesWithFlash(c, {
      tenantId: pathParams.tenantId,
      userId: principal.userId,
      tone: "success",
      message: notice,
      filters,
    });
  });
};
