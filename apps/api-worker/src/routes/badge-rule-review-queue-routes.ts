import {
  createAuditLog,
  findBadgeIssuanceRuleById,
  findBadgeIssuanceRuleEvaluationById,
  listBadgeIssuanceRuleEvaluations,
  resolveBadgeIssuanceRuleEvaluationReview,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { Hono } from "hono";
import {
  parseBadgeIssuanceRuleEvaluationPathParams,
  parseBadgeIssuanceRuleReviewQueueQuery,
  parseResolveBadgeIssuanceRuleReviewRequest,
  parseTenantPathParams,
} from "@credtrail/validation";
import type { AppBindings, AppContext, AppEnv } from "../app";
import {
  evaluateBadgeIssuanceRuleDefinition,
  summarizeBadgeIssuanceRuleEvaluation,
} from "../rules/engine";
import { parseFactsFromEvaluationRecord } from "./badge-rule-evaluation-helpers";
import {
  isIssueBadgeHttpError,
  type DirectIssueBadgeResult,
  type IssueBadgeForTenant,
} from "./badge-rule-evaluation-types";

interface RegisterBadgeRuleReviewQueueRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  requireTenantRole: (
    c: AppContext,
    tenantId: string,
    allowedRoles: readonly TenantMembershipRole[],
  ) => Promise<
    | {
        session: SessionRecord;
        membershipRole: TenantMembershipRole;
      }
    | Response
  >;
  issueBadgeForTenant: IssueBadgeForTenant;
  ISSUER_ROLES: readonly TenantMembershipRole[];
}

export const registerBadgeRuleReviewQueueRoutes = (
  input: RegisterBadgeRuleReviewQueueRoutesInput,
): void => {
  const { app, resolveDatabase, requireTenantRole, issueBadgeForTenant, ISSUER_ROLES } = input;

  app.get("/v1/tenants/:tenantId/badge-rules/review-queue", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let query;

    try {
      query = parseBadgeIssuanceRuleReviewQueueQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid review queue query",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const reviewStatus = query.status ?? "pending";
    const db = resolveDatabase(c.env);
    const evaluations = await listBadgeIssuanceRuleEvaluations(db, {
      tenantId: pathParams.tenantId,
      issuanceStatus: "review_required",
      reviewStatus,
      limit: query.limit ?? 50,
    });
    const ruleCache = new Map<string, Awaited<ReturnType<typeof findBadgeIssuanceRuleById>>>();
    const queue = await Promise.all(
      evaluations.map(async (evaluationRecord) => {
        let rule = ruleCache.get(evaluationRecord.ruleId);

        if (rule === undefined) {
          rule = await findBadgeIssuanceRuleById(db, pathParams.tenantId, evaluationRecord.ruleId);
          ruleCache.set(evaluationRecord.ruleId, rule);
        }

        const facts = parseFactsFromEvaluationRecord(evaluationRecord);
        const parsedPayload = (() => {
          try {
            return JSON.parse(evaluationRecord.evaluationJson) as unknown;
          } catch {
            return null;
          }
        })();
        const evaluation =
          parsedPayload !== null &&
          typeof parsedPayload === "object" &&
          "evaluation" in parsedPayload &&
          parsedPayload.evaluation !== null &&
          typeof parsedPayload.evaluation === "object"
            ? parsedPayload.evaluation
            : null;
        const summary =
          evaluation !== null &&
          "matched" in evaluation &&
          "tree" in evaluation &&
          typeof evaluation.matched === "boolean" &&
          evaluation.tree !== null &&
          typeof evaluation.tree === "object"
            ? summarizeBadgeIssuanceRuleEvaluation(
                evaluation as ReturnType<typeof evaluateBadgeIssuanceRuleDefinition>,
              )
            : null;

        return {
          ...evaluationRecord,
          ruleName: rule?.name ?? null,
          badgeTemplateId: rule?.badgeTemplateId ?? null,
          facts,
          evaluation,
          evaluationSummary: summary,
        };
      }),
    );

    return c.json({
      tenantId: pathParams.tenantId,
      reviewStatus,
      queue,
    });
  });

  app.post("/v1/tenants/:tenantId/badge-rules/review-queue/:evaluationId/resolve", async (c) => {
    const pathParams = parseBadgeIssuanceRuleEvaluationPathParams(c.req.param());
    let request;

    try {
      request = parseResolveBadgeIssuanceRuleReviewRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid review queue resolution payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const evaluationRecord = await findBadgeIssuanceRuleEvaluationById(db, {
      tenantId: pathParams.tenantId,
      evaluationId: pathParams.evaluationId,
    });

    if (evaluationRecord === null) {
      return c.json(
        {
          error: "Review queue entry not found",
        },
        404,
      );
    }

    if (evaluationRecord.reviewStatus !== "pending") {
      return c.json(
        {
          error: "Review queue entry is no longer pending",
        },
        409,
      );
    }

    const rule = await findBadgeIssuanceRuleById(db, pathParams.tenantId, evaluationRecord.ruleId);

    if (rule === null) {
      return c.json(
        {
          error: "Badge rule not found for review queue entry",
        },
        404,
      );
    }

    let issuance: DirectIssueBadgeResult | null = null;

    if (request.decision === "issue") {
      try {
        issuance = await issueBadgeForTenant(
          c,
          pathParams.tenantId,
          {
            badgeTemplateId: rule.badgeTemplateId,
            recipientIdentity: evaluationRecord.recipientIdentity,
            recipientIdentityType: evaluationRecord.recipientIdentityType,
            idempotencyKey: `rule-review:${evaluationRecord.id}`,
          },
          session.userId,
        );
      } catch (error) {
        if (isIssueBadgeHttpError(error)) {
          return c.json(error.payload, error.statusCode);
        }

        return c.json(
          {
            error:
              error instanceof Error ? error.message : "Failed to issue badge from review queue",
          },
          502,
        );
      }
    }

    const resolved = await resolveBadgeIssuanceRuleEvaluationReview(db, {
      tenantId: pathParams.tenantId,
      evaluationId: evaluationRecord.id,
      reviewDecision: request.decision,
      reviewComment: request.comment,
      reviewedByUserId: session.userId,
      issuanceStatus:
        request.decision === "issue" ? (issuance?.status ?? "issued") : "review_dismissed",
      assertionId: request.decision === "issue" ? issuance?.assertionId : undefined,
    });

    if (resolved === null) {
      return c.json(
        {
          error: "Review queue entry is no longer pending",
        },
        409,
      );
    }

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "badge_rule.review_resolved",
      targetType: "badge_rule_evaluation",
      targetId: evaluationRecord.id,
      metadata: {
        role: membershipRole,
        ruleId: evaluationRecord.ruleId,
        versionId: evaluationRecord.versionId,
        decision: request.decision,
        issuanceStatus: resolved.issuanceStatus,
      },
    });

    return c.json({
      tenantId: pathParams.tenantId,
      review: resolved,
      issuance,
    });
  });
};
