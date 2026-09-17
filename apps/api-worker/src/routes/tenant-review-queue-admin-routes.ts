import { z } from "zod";
import {
  parseReviewQueuePageQuery,
  reviewQueuePageUrl,
  type ReviewQueueCorrection,
  type ReviewQueuePageQuery,
} from "../admin/review-queue-page-query";
import type { TenantMembershipRole } from "@credtrail/db";
import {
  parseResolveBadgeIssuanceRuleReviewRequest,
  parseTenantPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import { readOptionalFormField } from "../admin/admin-form-helpers";
import { setAdminListMessageFlash } from "../admin/admin-list-message-flash";
import { tenantReviewQueueAdminResolvePath } from "../admin/review-queue-admin-helpers";
import type { AppContext, AppEnv } from "../app/types";
import type { IssueBadgeForTenant, ResolveDatabase } from "../app/route-deps";
import type { AuthenticatedPrincipal } from "../auth/auth-context";
import { resolveBadgeRuleReviewQueueEntry } from "../badge-rule-review-queue-resolve";

interface RegisterTenantReviewQueueAdminRoutesInput {
  app: Hono<AppEnv>;
  renderCorrection: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
    correction: ReviewQueueCorrection,
  ) => Promise<Response>;
  resolveDatabase: ResolveDatabase;
  resolveInstitutionAdminAdminRole: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<
    | Response
    | {
        principal: AuthenticatedPrincipal;
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

    const { principal } = roleCheck;
    const redirectToReviewQueue = async (
      tone: "success" | "error",
      message: string,
    ): Promise<Response> => {
      await setAdminListMessageFlash(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        workspace: "operations_review_queue",
        tone,
        message,
      });

      return c.redirect(reviewQueuePageUrl(pathParams.tenantId, { ...query, review: "" }), 303);
    };

    const formData = await c.req.formData();
    const evaluationId = readOptionalFormField(formData, "evaluationId") ?? "";
    const decisionRaw = readOptionalFormField(formData, "decision");
    const comment = readOptionalFormField(formData, "comment");
    const rawComment = formData.get("comment");

    let query: ReviewQueuePageQuery;
    try {
      query = parseReviewQueuePageQuery({
        sort: readOptionalFormField(formData, "sort") ?? "newest",
        decision: readOptionalFormField(formData, "outcome") ?? "all",
        q: readOptionalFormField(formData, "q") ?? "",
        reviewStatus: readOptionalFormField(formData, "reviewStatus") ?? "pending",
        cursor: readOptionalFormField(formData, "cursor"),
      });
    } catch {
      query = parseReviewQueuePageQuery({});
    }
    const correct = async (message: string): Promise<Response> => {
      c.status(422);
      return input.renderCorrection(
        c,
        pathParams.tenantId,
        reviewQueuePageUrl(pathParams.tenantId, query),
        {
          query,
          evaluationId: z.string().max(256).safeParse(evaluationId).data ?? "",
          comment: typeof rawComment === "string" ? rawComment.slice(0, 10000) : "",
          message,
        },
      );
    };
    if (!z.string().min(1).max(256).safeParse(evaluationId).success)
      return correct("Choose a review entry before taking action.");

    let request: ReturnType<typeof parseResolveBadgeIssuanceRuleReviewRequest>;

    try {
      request = parseResolveBadgeIssuanceRuleReviewRequest({
        decision: decisionRaw,
        ...(comment === undefined ? {} : { comment }),
      });
    } catch {
      return correct(
        "Choose Issue badge or Dismiss review, and keep your decision note within 2,000 characters.",
      );
    }

    const { membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const result = await resolveBadgeRuleReviewQueueEntry({
      c,
      db,
      tenantId: pathParams.tenantId,
      evaluationId,
      request,
      principal,
      membershipRole,
      issueBadgeForTenant,
    });

    if (!result.ok) {
      return correct(result.error);
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
