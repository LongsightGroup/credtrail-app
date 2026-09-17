import {
  parseIssuedBadgeStatusForm,
  type IssuedBadgeStatusCorrection,
} from "../admin/issued-badge-status-form";
import {
  findAssertionById,
  findBadgeTemplateById,
  recordAssertionLifecycleTransition,
  type DelegatedIssuingAuthorityAction,
  type TenantMembershipRole,
} from "@credtrail/db";
import { parseTenantPathParams } from "@credtrail/validation";
import type { Hono } from "hono";
import { setAdminListMessageFlash } from "../admin/admin-list-message-flash";
import {
  issuedBadgesPageUrl,
  parseIssuedBadgesPageQuery,
  tenantIssuedBadgeAdminStatusPath,
} from "../admin/issued-badges-admin-helpers";
import type { AppContext, AppEnv } from "../app/types";
import type {
  RequireDelegatedIssuingAuthorityPermission,
  ResolveDatabase,
} from "../app/route-deps";

const issuedBadgeStatusPermissionError =
  "You do not have permission to make this status change for the selected badge.";

interface RegisterTenantIssuedBadgesAdminRoutesInput {
  app: Hono<AppEnv>;
  renderStatusCorrection: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
    correction: IssuedBadgeStatusCorrection,
  ) => Promise<Response>;
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
  const notificationStatus = readOptionalFormField(formData, "notificationStatus");
  const limitRaw = formData.get("limit");
  const cursor = readOptionalFormField(formData, "cursor");

  return parseIssuedBadgesPageQuery({
    ...(notificationStatus === undefined ? {} : { notificationStatus }),
    ...(cursor === undefined ? {} : { cursor }),
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

  app.post("/tenants/:tenantId/admin/operations/issued-badges/status", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = tenantIssuedBadgeAdminStatusPath(pathParams.tenantId);
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
        message: "Choose a badge before changing its status.",
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

    const parsed = parseIssuedBadgeStatusForm(formData);
    if (!parsed.ok) {
      c.status(422);
      return input.renderStatusCorrection(
        c,
        pathParams.tenantId,
        issuedBadgesPageUrl(pathParams.tenantId, filters),
        {
          assertionId,
          filters,
          form: parsed.error,
        },
      );
    }
    const request = parsed.value;

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

    const requiredAction: DelegatedIssuingAuthorityAction =
      request.toState === "revoked" ? "revoke_badge" : "manage_lifecycle";
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
        message: issuedBadgeStatusPermissionError,
        filters,
        extra: {
          lifecycle: assertionId,
          lifecycleMode: "status",
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
        message:
          "This badge can no longer make that status change. Review its current status and choose an available action.",
        filters,
        extra: {
          lifecycle: assertionId,
          lifecycleMode: "status",
        },
      });
    }

    const notice =
      transitionResult.status === "already_in_state"
        ? `This badge is already ${request.toState}. No further change was made.`
        : `Badge status updated to ${request.toState}.`;

    return redirectIssuedBadgesWithFlash(c, {
      tenantId: pathParams.tenantId,
      userId: principal.userId,
      tone: "success",
      message:
        filters.state && filters.state !== request.toState
          ? `${notice} It no longer matches your status filter.`
          : notice,
      filters,
      extra: { lifecycle: assertionId, lifecycleMode: "status" },
    });
  });
};
