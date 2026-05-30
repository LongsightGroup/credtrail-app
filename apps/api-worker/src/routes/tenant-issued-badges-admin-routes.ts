import {
  findAssertionById,
  findBadgeTemplateById,
  recordAssertionLifecycleTransition,
  type DelegatedIssuingAuthorityAction,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseAssertionLifecycleTransitionRequest,
  parseTenantPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import {
  issuedBadgesPageUrl,
  parseIssuedBadgesPageQuery,
  tenantIssuedBadgeAdminRevokePath,
} from "../admin/issued-badges-admin-helpers";

const issuedBadgeRevokePermissionError =
  "You do not have permission to revoke this badge for the selected template.";
import type { AppBindings, AppContext, AppEnv } from "../app";

interface RegisterTenantIssuedBadgesAdminRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  requireDelegatedIssuingAuthorityPermission: (
    c: AppContext,
    input: {
      db: SqlDatabase;
      tenantId: string;
      userId: string;
      membershipRole: TenantMembershipRole;
      ownerOrgUnitId: string;
      badgeTemplateId: string;
      requiredAction: DelegatedIssuingAuthorityAction;
    },
  ) => Promise<Response | null>;
  assertionBelongsToTenant: (tenantId: string, assertionId: string) => boolean;
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

const readFilterFieldsFromForm = (
  formData: FormData,
): ReturnType<typeof parseIssuedBadgesPageQuery>["filters"] => {
  const recipientQuery = readOptionalFormField(formData, "recipientQuery");
  const badgeTemplateId = readOptionalFormField(formData, "badgeTemplateId");
  const state = readOptionalFormField(formData, "state");
  const limitRaw = formData.get("limit");

  return parseIssuedBadgesPageQuery({
    ...(recipientQuery === undefined ? {} : { recipientQuery }),
    ...(badgeTemplateId === undefined ? {} : { badgeTemplateId }),
    ...(state === undefined ? {} : { state }),
    limit: typeof limitRaw === "string" && limitRaw.trim().length > 0 ? limitRaw.trim() : "100",
  }).filters;
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

    if (assertionId.length === 0) {
      return c.redirect(
        issuedBadgesPageUrl(pathParams.tenantId, filters, {
          listError: "Choose a badge before revoking it.",
        }),
        303,
      );
    }

    if (!assertionBelongsToTenant(pathParams.tenantId, assertionId)) {
      return c.redirect(
        issuedBadgesPageUrl(pathParams.tenantId, filters, {
          listError: "Badge not found for this institution.",
        }),
        303,
      );
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
      return c.redirect(
        issuedBadgesPageUrl(pathParams.tenantId, filters, {
          listError: "Choose a reason code before revoking this badge.",
          lifecycle: assertionId,
          lifecycleMode: "revoke",
        }),
        303,
      );
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const assertion = await findAssertionById(db, pathParams.tenantId, assertionId);

    if (assertion === null) {
      return c.redirect(
        issuedBadgesPageUrl(pathParams.tenantId, filters, {
          listError: "Badge not found for this institution.",
        }),
        303,
      );
    }

    const badgeTemplate = await findBadgeTemplateById(
      db,
      pathParams.tenantId,
      assertion.badgeTemplateId,
    );

    if (badgeTemplate === null) {
      return c.redirect(
        issuedBadgesPageUrl(pathParams.tenantId, filters, {
          listError: "Badge template not found for this institution.",
        }),
        303,
      );
    }

    const requiredAction: DelegatedIssuingAuthorityAction = "revoke_badge";
    const delegatedPermission = await requireDelegatedIssuingAuthorityPermission(c, {
      db,
      tenantId: pathParams.tenantId,
      userId: session.userId,
      membershipRole,
      ownerOrgUnitId: badgeTemplate.ownerOrgUnitId,
      badgeTemplateId: badgeTemplate.id,
      requiredAction,
    });

    if (delegatedPermission !== null) {
      return c.redirect(
        issuedBadgesPageUrl(pathParams.tenantId, filters, {
          listError: issuedBadgeRevokePermissionError,
          lifecycle: assertionId,
          lifecycleMode: "revoke",
        }),
        303,
      );
    }

    const transitionResult = await recordAssertionLifecycleTransition(db, {
      tenantId: pathParams.tenantId,
      assertionId,
      toState: request.toState,
      reasonCode: request.reasonCode,
      ...(request.reason === undefined ? {} : { reason: request.reason }),
      transitionSource: "manual",
      actorUserId: session.userId,
      transitionedAt: request.transitionedAt ?? new Date().toISOString(),
    });

    if (transitionResult.status === "invalid_transition") {
      return c.redirect(
        issuedBadgesPageUrl(pathParams.tenantId, filters, {
          listError: transitionResult.message ?? "Lifecycle transition not allowed",
          lifecycle: assertionId,
          lifecycleMode: "revoke",
        }),
        303,
      );
    }

    const notice =
      transitionResult.status === "already_in_state"
        ? "Badge was already revoked."
        : "Badge revoked.";

    return c.redirect(
      issuedBadgesPageUrl(pathParams.tenantId, filters, {
        listNotice: notice,
      }),
      303,
    );
  });
};
