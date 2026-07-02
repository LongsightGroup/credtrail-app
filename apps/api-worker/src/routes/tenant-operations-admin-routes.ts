import {
  createAuditLog,
  findAssertionById,
  findBadgeTemplateById,
  type TenantMembershipRole,
} from "@credtrail/db";
import { parseManualIssueBadgeRequest, parseTenantPathParams } from "@credtrail/validation";
import type { Hono } from "hono";
import { buildOperationsManualIssuePath } from "../admin/access-admin-helpers";
import { readOptionalFormField } from "../admin/admin-form-helpers";
import {
  buildAdminManualIssueSuccessLinks,
  setAdminManualIssueFlash,
} from "../admin/manual-issue-flash";
import type { AppContext, AppEnv } from "../app";
import type {
  RequireDelegatedIssuingAuthorityPermission,
  ResolveDatabase,
} from "../app/route-deps";
import { publicBadgePathForAssertion } from "../badges/public-badge-model";
import { isIssueBadgeHttpError, type IssueBadgeForTenant } from "./badge-rule-evaluation-types";

interface RegisterTenantOperationsAdminRoutesInput {
  app: Hono<AppEnv>;
  issueBadgeForTenant: IssueBadgeForTenant;
  requireDelegatedIssuingAuthorityPermission: RequireDelegatedIssuingAuthorityPermission;
  resolveDatabase: ResolveDatabase;
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

const registerOperationsManualIssuePost = (
  app: Hono<AppEnv>,
  path: string,
  handler: (c: AppContext) => Promise<Response>,
): void => {
  app.post(path, handler);
};

export const registerTenantOperationsAdminRoutes = (
  input: RegisterTenantOperationsAdminRoutesInput,
): void => {
  const {
    app,
    issueBadgeForTenant,
    requireDelegatedIssuingAuthorityPermission,
    resolveDatabase,
    resolveInstitutionAdminAdminRole,
  } = input;

  const handleManualIssuePost = async (c: AppContext): Promise<Response> => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = buildOperationsManualIssuePath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const formData = await c.req.formData();
    const recipientIdentity = (
      readOptionalFormField(formData, "recipientIdentity") ?? ""
    ).toLowerCase();
    const badgeTemplateId = readOptionalFormField(formData, "badgeTemplateId") ?? "";

    let request: ReturnType<typeof parseManualIssueBadgeRequest>;

    try {
      request = parseManualIssueBadgeRequest({
        badgeTemplateId,
        recipientIdentity,
        recipientIdentityType: "email",
        recipientIdentifiers: [
          {
            identifierType: "emailAddress",
            identifier: recipientIdentity,
          },
        ],
      });
    } catch {
      await setAdminManualIssueFlash(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Recipient email and badge template are required.",
      });

      return c.redirect(buildOperationsManualIssuePath(pathParams.tenantId), 303);
    }

    const db = resolveDatabase(c.env);
    const template = await findBadgeTemplateById(db, pathParams.tenantId, request.badgeTemplateId);

    if (template === null) {
      await setAdminManualIssueFlash(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Choose a badge template that belongs to this organization.",
      });

      return c.redirect(buildOperationsManualIssuePath(pathParams.tenantId), 303);
    }

    const delegatedPermission = await requireDelegatedIssuingAuthorityPermission(c, {
      db,
      tenantId: pathParams.tenantId,
      userId: session.userId,
      membershipRole,
      ownerOrgUnitId: template.ownerOrgUnitId,
      badgeTemplateId: template.id,
      requiredAction: "issue_badge",
    });

    if (delegatedPermission !== null) {
      return delegatedPermission;
    }

    try {
      const issueRequest = {
        badgeTemplateId: request.badgeTemplateId,
        recipientIdentity: request.recipientIdentity,
        recipientIdentityType: request.recipientIdentityType,
        idempotencyKey: request.idempotencyKey ?? crypto.randomUUID(),
        ...(request.recipientIdentifiers === undefined
          ? {}
          : { recipientIdentifiers: request.recipientIdentifiers }),
      };
      const result = await issueBadgeForTenant(
        c,
        pathParams.tenantId,
        issueRequest,
        session.userId,
      );
      const assertion = await findAssertionById(db, pathParams.tenantId, result.assertionId);

      if (assertion === null) {
        throw new Error(`Issued assertion "${result.assertionId}" could not be loaded`);
      }

      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "assertion.manual_issued",
        targetType: "assertion",
        targetId: result.assertionId,
        metadata: {
          role: membershipRole,
          badgeTemplateId: request.badgeTemplateId,
          recipientIdentity: request.recipientIdentity,
          status: result.status,
        },
      });

      await setAdminManualIssueFlash(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "success",
        message: `Badge issued for ${request.recipientIdentity}.`,
        successLinks: buildAdminManualIssueSuccessLinks(publicBadgePathForAssertion(assertion)),
      });
    } catch (error: unknown) {
      const message = isIssueBadgeHttpError(error)
        ? error.payload.error
        : "Unable to issue the badge from this form.";

      await setAdminManualIssueFlash(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message,
      });
    }

    return c.redirect(buildOperationsManualIssuePath(pathParams.tenantId), 303);
  };

  registerOperationsManualIssuePost(
    app,
    "/tenants/:tenantId/admin/operations/issue",
    handleManualIssuePost,
  );
  registerOperationsManualIssuePost(
    app,
    "/tenants/:tenantId/admin/operations/manual-issue",
    handleManualIssuePost,
  );
};
