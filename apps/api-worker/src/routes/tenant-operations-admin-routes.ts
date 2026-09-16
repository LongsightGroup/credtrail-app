import { issuePreparedBadgePath } from "../admin/badge-awarding-links";
import {
  createAuditLog,
  findAssertionById,
  findBadgeTemplateById,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseManualIssueBadgeRequest,
  manualIssuePageQuerySchema,
  parseTenantPathParams,
  parseAssertionPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import { buildOperationsManualIssuePath } from "../admin/access-admin-helpers";
import { readOptionalFormField } from "../admin/admin-form-helpers";
import { setAdminListMessageFlash } from "../admin/admin-list-message-flash";
import { issuanceReceiptPage, issuanceReceiptPath } from "../admin/issuance-receipt-page";
import { renderInstitutionAdminWorkspacePage } from "../admin/institution-admin-workspace";
import { renderAppPage } from "../ui/render-page";
import type { TenantGovernanceAdminPageDataLoaders } from "./tenant-governance-admin/page-data";
import type { AppContext, AppEnv } from "../app/types";
import type {
  IssueBadgeForTenant,
  RequireDelegatedIssuingAuthorityPermission,
  ResolveDatabase,
} from "../app/route-deps";
import { badgeAchievementSnapshotFromTemplate } from "../badges/badge-achievement-snapshot";
import { isIssueBadgeHttpError } from "../badges/direct-issue";

interface RegisterTenantOperationsAdminRoutesInput {
  app: Hono<AppEnv>;
  loadInstitutionAdminShellData: TenantGovernanceAdminPageDataLoaders["loadInstitutionAdminShellData"];
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

    const handoffQuery = manualIssuePageQuerySchema.safeParse({
      badgeTemplateId,
      pathwayHandoffId: learnerPathwayCompletionHandoffId,
    });
    const returnPath =
      handoffQuery.success && handoffQuery.data.badgeTemplateId !== undefined
        ? issuePreparedBadgePath(
            pathParams.tenantId,
            handoffQuery.data.badgeTemplateId,
            handoffQuery.data.pathwayHandoffId,
          )
        : nextPath;

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
        ...(learnerPathwayCompletionHandoffId === undefined
          ? {}
          : { learnerPathwayCompletionHandoffId }),
      });
    } catch {
      await setAdminListMessageFlash(c, {
        workspace: "operations_manual_issue",
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "error",
        message: "Recipient email and badge template are required.",
      });

      return c.redirect(returnPath, 303);
    }

    const db = resolveDatabase(c.env);
    const template = await findBadgeTemplateById(db, pathParams.tenantId, request.badgeTemplateId);

    if (template === null || template.isArchived) {
      await setAdminListMessageFlash(c, {
        workspace: "operations_manual_issue",
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "error",
        message: "Choose an active badge template that belongs to this organization.",
      });

      return c.redirect(returnPath, 303);
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

      return c.redirect(issuanceReceiptPath(pathParams.tenantId, result.assertionId), 303);
    } catch (error: unknown) {
      if (!isIssueBadgeHttpError(error)) {
        throw error;
      }

      await setAdminListMessageFlash(c, {
        workspace: "operations_manual_issue",
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "error",
        message: error.payload.error,
      });
    }

    return c.redirect(returnPath, 303);
  };

  app.get("/tenants/:tenantId/admin/operations/issue/:assertionId/receipt", async (c) => {
    const { tenantId } = parseTenantPathParams(c.req.param());
    const { assertionId } = parseAssertionPathParams(c.req.param());
    const authorized = await resolveInstitutionAdminAdminRole(c, tenantId, c.req.path);
    if (authorized instanceof Response) return authorized;
    const assertion = await findAssertionById(resolveDatabase(c.env), tenantId, assertionId);
    if (assertion === null) return c.text("Badge not found for this institution.", 404);
    const shell = await input.loadInstitutionAdminShellData(
      c,
      tenantId,
      authorized.principal.userId,
      authorized.membershipRole,
    );
    if (shell instanceof Response) return shell;
    return renderInstitutionAdminWorkspacePage(
      c,
      renderAppPage,
      issuanceReceiptPage({ ...shell, assertion }),
    );
  });

  app.post("/tenants/:tenantId/admin/operations/issue", handleManualIssuePost);
};
