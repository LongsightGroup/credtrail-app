import type { SessionRecord, TenantMembershipRole } from "@credtrail/db";
import {
  parseResolveBadgeIssuanceRuleReviewRequest,
  parseTenantPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import { readOptionalFormField } from "../admin/admin-form-helpers";
import { setAdminListMessageFlash } from "../admin/admin-list-message-flash";
import {
  buildReviewQueuePagePath,
  tenantReviewQueueAdminResolvePath,
} from "../admin/review-queue-admin-helpers";
import type { AppContext, AppEnv } from "../app";
import type { IssueBadgeForTenant, ResolveDatabase } from "../app/route-deps";
import { resolveBadgeRuleReviewQueueEntry } from "../badge-rule-review-queue-resolve";

interface RegisterTenantReviewQueueAdminRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
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
  issueBadgeForTenant: IssueBadgeForTenant;
}

export const registerTenantReviewQueueAdminRoutes = (
  input: RegisterTenantReviewQueueAdminRoutesInput,
): void => {
  const { app, resolveDatabase, resolveInstitutionAdminAdminRole, issueBadgeForTenant } = input;

  app.post("/tenants/:tenantId/admin/operations/review-queue/resolve", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = tenantReviewQueueAdminResolvePath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session } = roleCheck;
    const redirectToReviewQueue = async (
      tone: "success" | "error",
      message: string,
    ): Promise<Response> => {
      await setAdminListMessageFlash(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        workspace: "operations_review_queue",
        tone,
        message,
      });

      return c.redirect(buildReviewQueuePagePath(pathParams.tenantId), 303);
    };

    const formData = await c.req.formData();
    const evaluationId = readOptionalFormField(formData, "evaluationId") ?? "";
    const decisionRaw = readOptionalFormField(formData, "decision");
    const comment = readOptionalFormField(formData, "comment");

    if (evaluationId.length === 0) {
      return redirectToReviewQueue("error", "Choose a review entry before taking action.");
    }

    let request: ReturnType<typeof parseResolveBadgeIssuanceRuleReviewRequest>;

    try {
      request = parseResolveBadgeIssuanceRuleReviewRequest({
        decision: decisionRaw,
        ...(comment === undefined ? {} : { comment }),
      });
    } catch {
      return redirectToReviewQueue("error", "That review action is not valid.");
    }

    const { membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const result = await resolveBadgeRuleReviewQueueEntry({
      c,
      db,
      tenantId: pathParams.tenantId,
      evaluationId,
      request,
      session,
      membershipRole,
      issueBadgeForTenant,
    });

    if (!result.ok) {
      return redirectToReviewQueue("error", result.error);
    }

    const recipientLabel =
      result.review.recipientIdentity.length > 0 ? result.review.recipientIdentity : evaluationId;

    const listNotice =
      request.decision === "issue"
        ? `Issued badge for ${recipientLabel}.`
        : `Dismissed review for ${recipientLabel}.`;

    return redirectToReviewQueue("success", listNotice);
  });
};
