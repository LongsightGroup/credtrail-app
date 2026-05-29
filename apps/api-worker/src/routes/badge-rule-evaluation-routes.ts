import {
  createAuditLog,
  createBadgeIssuanceRuleEvaluation,
  findActiveBadgeIssuanceRuleVersion,
  findBadgeIssuanceRuleById,
  findBadgeIssuanceRuleVersionById,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { Hono } from "hono";
import {
  parseBadgeIssuanceRulePathParams,
  parseEvaluateBadgeIssuanceRuleRequest,
  type BadgeIssuanceRuleDefinition,
} from "@credtrail/validation";
import type { AppBindings, AppContext, AppEnv } from "../app";
import {
  evaluateBadgeIssuanceRuleDefinition,
  summarizeBadgeIssuanceRuleEvaluation,
  type BadgeIssuanceRuleEvaluationFacts,
} from "../rules/engine";
import { resolveRuleDefinition, resolveBadgeIssuanceRuleDefinitionValueLists } from "./badge-rule-definition-resolver";
import { badgeRuleEvaluationOutcome } from "./badge-rule-evaluation-helpers";
import { loadRuleFacts } from "./badge-rule-facts-loader";
import { isIssueBadgeHttpError, type DirectIssueBadgeResult, type IssueBadgeForTenant } from "./badge-rule-evaluation-types";
import { registerBadgeRulePreviewRoutes } from "./badge-rule-preview-routes";
import { registerBadgeRuleReviewQueueRoutes } from "./badge-rule-review-queue-routes";

interface RegisterBadgeRuleEvaluationRoutesInput {
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

export const registerBadgeRuleEvaluationRoutes = (input: RegisterBadgeRuleEvaluationRoutesInput): void => {
  const {
    app,
    resolveDatabase,
    requireTenantRole,
    issueBadgeForTenant,
    ISSUER_ROLES,
  } = input;

  registerBadgeRulePreviewRoutes({
    app,
    resolveDatabase,
    requireTenantRole,
    ISSUER_ROLES,
  });

  registerBadgeRuleReviewQueueRoutes({
    app,
    resolveDatabase,
    requireTenantRole,
    issueBadgeForTenant,
    ISSUER_ROLES,
  });

  app.post("/v1/tenants/:tenantId/badge-rules/:ruleId/evaluate", async (c) => {
    const pathParams = parseBadgeIssuanceRulePathParams(c.req.param());
    let request;

    try {
      request = parseEvaluateBadgeIssuanceRuleRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid badge rule evaluation payload",
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
    const rule = await findBadgeIssuanceRuleById(db, pathParams.tenantId, pathParams.ruleId);

    if (rule === null) {
      return c.json(
        {
          error: "Badge rule not found",
        },
        404,
      );
    }

    const selectedVersion =
      request.versionId === undefined
        ? await findActiveBadgeIssuanceRuleVersion(db, {
            tenantId: pathParams.tenantId,
            ruleId: pathParams.ruleId,
          })
        : await findBadgeIssuanceRuleVersionById(db, {
            tenantId: pathParams.tenantId,
            ruleId: pathParams.ruleId,
            versionId: request.versionId,
          });

    if (selectedVersion === null) {
      return c.json(
        {
          error:
            request.versionId === undefined
              ? "No active rule version found. Activate an approved version first."
              : "Badge rule version not found",
        },
        404,
      );
    }

    let definition: BadgeIssuanceRuleDefinition;

    try {
      definition = await resolveBadgeIssuanceRuleDefinitionValueLists(
        db,
        pathParams.tenantId,
        resolveRuleDefinition(selectedVersion.ruleJson),
      );
    } catch (error) {
      return c.json(
        {
          error: error instanceof Error ? error.message : "Failed to resolve rule value lists",
        },
        422,
      );
    }
    const nowIso = new Date().toISOString();

    let facts: BadgeIssuanceRuleEvaluationFacts;

    try {
      facts = await loadRuleFacts({
        db,
        tenantId: pathParams.tenantId,
        lmsProviderKind: rule.lmsProviderKind,
        learnerId: request.learnerId,
        recipientIdentity: request.recipientIdentity,
        recipientIdentityType: request.recipientIdentityType,
        definition,
        requestedFacts: request.facts,
        nowIso,
      });
    } catch (error) {
      return c.json(
        {
          error: error instanceof Error ? error.message : "Failed to load rule facts",
        },
        502,
      );
    }

    const evaluation = evaluateBadgeIssuanceRuleDefinition(definition, facts);
    const evaluationSummary = summarizeBadgeIssuanceRuleEvaluation(evaluation);
    const outcome = badgeRuleEvaluationOutcome(definition, evaluation);
    const dryRun = request.dryRun ?? false;
    let issuance: DirectIssueBadgeResult | null = null;

    if (evaluation.matched && !dryRun) {
      try {
        issuance = await issueBadgeForTenant(
          c,
          pathParams.tenantId,
          {
            badgeTemplateId: rule.badgeTemplateId,
            recipientIdentity: request.recipientIdentity,
            recipientIdentityType: request.recipientIdentityType,
            idempotencyKey: `rule:${rule.id}:v${String(selectedVersion.versionNumber)}:${request.learnerId}`,
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
              error instanceof Error ? error.message : "Failed to issue badge for matched rule",
          },
          502,
        );
      }
    }

    const evaluationRecord = await createBadgeIssuanceRuleEvaluation(db, {
      tenantId: pathParams.tenantId,
      ruleId: rule.id,
      versionId: selectedVersion.id,
      learnerId: request.learnerId,
      recipientIdentity: request.recipientIdentity,
      recipientIdentityType: request.recipientIdentityType,
      matched: evaluation.matched,
      issuanceStatus:
        outcome === "review_required" && !dryRun ? "review_required" : issuance?.status,
      assertionId: issuance?.assertionId,
      evaluationJson: JSON.stringify({
        dryRun,
        outcome,
        evaluation,
        evaluationSummary,
        facts,
      }),
      ...(outcome === "review_required" && !dryRun ? { reviewStatus: "pending" as const } : {}),
      evaluatedAt: facts.nowIso,
    });

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "badge_rule.evaluated",
      targetType: "badge_rule",
      targetId: rule.id,
      metadata: {
        role: membershipRole,
        versionId: selectedVersion.id,
        versionNumber: selectedVersion.versionNumber,
        learnerId: request.learnerId,
        dryRun,
        matched: evaluation.matched,
        outcome,
        issuanceStatus: issuance?.status ?? null,
        assertionId: issuance?.assertionId ?? null,
      },
    });

    return c.json({
      tenantId: pathParams.tenantId,
      rule,
      version: selectedVersion,
      definition,
      evaluation,
      evaluationSummary,
      outcome,
      dryRun,
      issuance,
      evaluationRecord,
    });
  });
};
