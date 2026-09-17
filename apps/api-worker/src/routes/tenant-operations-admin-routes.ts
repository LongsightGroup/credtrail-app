import { canonicalAppUrl } from "../http/canonical-app-url";
import { publicBadgePathForAssertion } from "../badges/public-badge-model";
import { z } from "zod";
import { manualIssueIdempotencyKey } from "../admin/manual-issue-request";
import { loadIssuanceEmailOutcome } from "../notifications/issuance-email-outcome";
import type { ManualIssueCorrection } from "../admin/manual-issue-correction";
import {
  createAuditLog,
  findAssertionById,
  findAssertionByIdempotencyKey,
  listAssertionsByBadgeTemplatesAndRecipientEmails,
  findBadgeTemplateById,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseManualIssueBadgeRequest,
  parseTenantPathParams,
  parseAssertionPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import { buildOperationsManualIssuePath } from "../admin/access-admin-helpers";
import { readOptionalFormField } from "../admin/admin-form-helpers";
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
  renderManualIssueCorrection: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
    correction: ManualIssueCorrection,
  ) => Promise<Response>;
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

    const parsedRequestId = z
      .uuid()
      .safeParse(readOptionalFormField(formData, "issuanceRequestId"));
    const issuanceRequestId = parsedRequestId.success ? parsedRequestId.data : crypto.randomUUID();
    const correct = (message: string, status: 403 | 422 = 422): Promise<Response> => {
      c.status(status);
      return input.renderManualIssueCorrection(c, pathParams.tenantId, nextPath, {
        issuanceRequestId,
        recipientIdentity,
        badgeTemplateId,
        pathwayHandoffId: learnerPathwayCompletionHandoffId,
        message,
      });
    };

    if (!parsedRequestId.success)
      return correct(
        "This issuance form needs to be refreshed. Review the badge and recipient, then try again.",
      );
    const idempotencyKey = await manualIssueIdempotencyKey({
      tenantId: pathParams.tenantId,
      userId: principal.userId,
      requestId: issuanceRequestId,
      badgeTemplateId,
      recipientIdentity,
      pathwayHandoffId: learnerPathwayCompletionHandoffId,
    });
    let request: ReturnType<typeof parseManualIssueBadgeRequest>;

    if (!z.email().safeParse(recipientIdentity).success) {
      return correct("Enter a valid recipient email address, such as learner@example.edu.");
    }

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
      return correct("Choose a badge and enter a valid recipient email address.");
    }

    const db = resolveDatabase(c.env);
    const template = await findBadgeTemplateById(db, pathParams.tenantId, request.badgeTemplateId);

    if (template === null || template.isArchived) {
      return correct("Choose an available badge from this organization.");
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
      if (delegatedPermission.status === 403)
        return correct(
          "You do not have permission to issue this badge. Choose a badge you can issue or contact an administrator.",
          403,
        );
      return delegatedPermission;
    }

    const issued = await findAssertionByIdempotencyKey(db, pathParams.tenantId, idempotencyKey);
    if (issued !== null)
      return c.redirect(issuanceReceiptPath(pathParams.tenantId, issued.id), 303);

    const previousAwards = await listAssertionsByBadgeTemplatesAndRecipientEmails(db, {
      tenantId: pathParams.tenantId,
      badgeTemplateIds: [request.badgeTemplateId],
      recipientEmails: [request.recipientIdentity],
    });
    const previousAward = previousAwards[0];
    if (previousAward?.idempotencyKey === idempotencyKey)
      return c.redirect(issuanceReceiptPath(pathParams.tenantId, previousAward.id), 303);
    const confirmation = z
      .string()
      .max(200)
      .safeParse(readOptionalFormField(formData, "previousAwardConfirmation"));
    if (
      previousAward !== undefined &&
      (!confirmation.success || confirmation.data !== idempotencyKey)
    ) {
      return input.renderManualIssueCorrection(c, pathParams.tenantId, nextPath, {
        issuanceRequestId,
        recipientIdentity,
        badgeTemplateId,
        pathwayHandoffId: learnerPathwayCompletionHandoffId,
        message: "",
        previousAward: {
          assertionId: previousAward.id,
          issuedAt: previousAward.issuedAt,
          confirmationKey: idempotencyKey,
        },
      });
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
        idempotencyKey,
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
      if (result.status === "issued")
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
      // A simultaneous submission may have committed while this request was issuing.
      const issued = await findAssertionByIdempotencyKey(db, pathParams.tenantId, idempotencyKey);
      if (issued !== null)
        return c.redirect(issuanceReceiptPath(pathParams.tenantId, issued.id), 303);
      if (!isIssueBadgeHttpError(error)) {
        throw error;
      }

      return correct(error.payload.error);
    }
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
    const notificationOutcome = await loadIssuanceEmailOutcome(
      resolveDatabase(c.env),
      tenantId,
      assertionId,
    );
    return renderInstitutionAdminWorkspacePage(
      c,
      renderAppPage,
      issuanceReceiptPage({
        ...shell,
        assertion,
        notificationOutcome,
        publicBadgeUrl: canonicalAppUrl(
          c.env.PUBLIC_APP_ORIGIN,
          publicBadgePathForAssertion(assertion),
        ),
      }),
    );
  });

  app.post("/tenants/:tenantId/admin/operations/issue", handleManualIssuePost);
};
