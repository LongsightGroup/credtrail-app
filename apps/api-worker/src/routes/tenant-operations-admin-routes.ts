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
import type { AppContext, AppEnv } from "../app/types";
import type {
  IssueBadgeForTenant,
  RequireDelegatedIssuingAuthorityPermission,
  ResolveDatabase,
} from "../app/route-deps";
import { badgeAchievementSnapshotFromTemplate } from "../badges/badge-achievement-snapshot";
import { isIssueBadgeHttpError } from "../badges/direct-issue";
import { publicBadgePathForAssertion } from "../badges/public-badge-model";

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
        principal: { userId: string };
        membershipRole: TenantMembershipRole;
      }
  >;
}

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

    const { principal, membershipRole } = roleCheck;
    const formData = await c.req.formData();
    const recipientIdentity = (
      readOptionalFormField(formData, "recipientIdentity") ?? ""
    ).toLowerCase();
    const badgeTemplateId = readOptionalFormField(formData, "badgeTemplateId") ?? "";
    const learnerPathwayCompletionHandoffId = readOptionalFormField(
      formData,
      "learnerPathwayCompletionHandoffId",
    );

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
        ...(learnerPathwayCompletionHandoffId === null
          ? {}
          : { learnerPathwayCompletionHandoffId }),
      });
    } catch {
      await setAdminManualIssueFlash(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
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
        userId: principal.userId,
        tone: "error",
        message: "Choose a badge template that belongs to this organization.",
      });

      return c.redirect(buildOperationsManualIssuePath(pathParams.tenantId), 303);
    }

    const delegatedPermission = await requireDelegatedIssuingAuthorityPermission(c, {
      db,
      tenantId: pathParams.tenantId,
      userId: principal.userId,
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
        achievementSource: {
          kind: "template_snapshot" as const,
          snapshot: badgeAchievementSnapshotFromTemplate(template),
          provenance: { source: "manual" as const },
        },
        recipientIdentity: request.recipientIdentity,
        recipientIdentityType: request.recipientIdentityType,
        idempotencyKey: request.idempotencyKey ?? crypto.randomUUID(),
        ...(request.recipientIdentifiers === undefined
          ? {}
          : { recipientIdentifiers: request.recipientIdentifiers }),
        ...(request.learnerPathwayCompletionHandoffId === undefined
          ? {}
          : {
              learnerPathwayCompletionHandoffId: request.learnerPathwayCompletionHandoffId,
            }),
      };
      const result = await issueBadgeForTenant(
        c,
        pathParams.tenantId,
        issueRequest,
        principal.userId,
      );
      const assertion = await findAssertionById(db, pathParams.tenantId, result.assertionId);

      if (assertion === null) {
        throw new Error(`Issued assertion "${result.assertionId}" could not be loaded`);
      }

      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: principal.userId,
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
        userId: principal.userId,
        tone: "success",
        message: `Badge issued for ${request.recipientIdentity}.`,
        successLinks: buildAdminManualIssueSuccessLinks(publicBadgePathForAssertion(assertion)),
      });
    } catch (error: unknown) {
      if (!isIssueBadgeHttpError(error)) {
        throw error;
      }

      await setAdminManualIssueFlash(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "error",
        message: error.payload.error,
      });
    }

    return c.redirect(buildOperationsManualIssuePath(pathParams.tenantId), 303);
  };

  app.post("/tenants/:tenantId/admin/operations/issue", handleManualIssuePost);
};
