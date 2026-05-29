import { listBadgeIssuanceRuleEvaluations, type SessionRecord, type SqlDatabase, type TenantMembershipRole } from "@credtrail/db";
import type { Hono } from "hono";
import {
  parsePreviewEvaluateBadgeIssuanceRuleRequest,
  parsePreviewSimulateBadgeIssuanceRuleRequest,
  parseTenantPathParams,
  type BadgeIssuanceRuleDefinition,
} from "@credtrail/validation";
import type { AppBindings, AppContext, AppEnv } from "../app";
import { evaluateBadgeIssuanceRuleDefinition, summarizeBadgeIssuanceRuleEvaluation, type BadgeIssuanceRuleEvaluationFacts } from "../rules/engine";
import { resolveBadgeIssuanceRuleDefinitionValueLists } from "./badge-rule-definition-resolver";
import { badgeRuleEvaluationOutcome, parseFactsFromEvaluationRecord } from "./badge-rule-evaluation-helpers";
import { loadRuleFacts } from "./badge-rule-facts-loader";

interface RegisterBadgeRulePreviewRoutesInput {
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
  ISSUER_ROLES: readonly TenantMembershipRole[];
}

export const registerBadgeRulePreviewRoutes = (
  input: RegisterBadgeRulePreviewRoutesInput,
): void => {
  const { app, resolveDatabase, requireTenantRole, ISSUER_ROLES } = input;

  app.post("/v1/tenants/:tenantId/badge-rules/preview-evaluate", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let request;

    try {
      request = parsePreviewEvaluateBadgeIssuanceRuleRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid badge rule preview payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const nowIso = new Date().toISOString();
    let definition: BadgeIssuanceRuleDefinition;

    try {
      definition = await resolveBadgeIssuanceRuleDefinitionValueLists(
        db,
        pathParams.tenantId,
        request.definition,
      );
    } catch (error) {
      return c.json(
        {
          error: error instanceof Error ? error.message : "Failed to resolve rule value lists",
        },
        422,
      );
    }

    let facts: BadgeIssuanceRuleEvaluationFacts;

    try {
      facts = await loadRuleFacts({
        db,
        tenantId: pathParams.tenantId,
        lmsProviderKind: request.lmsProviderKind,
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

    return c.json({
      tenantId: pathParams.tenantId,
      definition,
      evaluation,
      evaluationSummary,
      outcome,
      facts,
      dryRun: true,
    });
  });

  app.post("/v1/tenants/:tenantId/badge-rules/preview-simulate", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let request;

    try {
      request = parsePreviewSimulateBadgeIssuanceRuleRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid badge rule simulation payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    let definition: BadgeIssuanceRuleDefinition;

    try {
      definition = await resolveBadgeIssuanceRuleDefinitionValueLists(
        db,
        pathParams.tenantId,
        request.definition,
      );
    } catch (error) {
      return c.json(
        {
          error: error instanceof Error ? error.message : "Failed to resolve rule value lists",
        },
        422,
      );
    }

    const sampleLimit = request.sampleLimit ?? 25;
    const historicalEvaluations = await listBadgeIssuanceRuleEvaluations(db, {
      tenantId: pathParams.tenantId,
      badgeTemplateId: request.badgeTemplateId,
      limit: sampleLimit,
    });
    const samples = historicalEvaluations
      .map((evaluationRecord) => {
        const facts = parseFactsFromEvaluationRecord(evaluationRecord);

        if (facts === null) {
          return null;
        }

        const projectedEvaluation = evaluateBadgeIssuanceRuleDefinition(definition, facts);
        const projectedOutcome = badgeRuleEvaluationOutcome(definition, projectedEvaluation);
        const projectedSummary = summarizeBadgeIssuanceRuleEvaluation(projectedEvaluation);

        return {
          evaluationId: evaluationRecord.id,
          learnerId: evaluationRecord.learnerId,
          recipientIdentity: evaluationRecord.recipientIdentity,
          historicalMatched: evaluationRecord.matched,
          historicalIssuanceStatus: evaluationRecord.issuanceStatus,
          projectedMatched: projectedEvaluation.matched,
          projectedOutcome,
          projectedSummary,
          changed:
            projectedEvaluation.matched !== evaluationRecord.matched ||
            projectedOutcome !==
              (evaluationRecord.issuanceStatus === "review_required"
                ? "review_required"
                : evaluationRecord.matched
                  ? "matched"
                  : "no_match"),
        };
      })
      .filter((sample): sample is NonNullable<typeof sample> => sample !== null);

    const matchedCount = samples.filter((sample) => sample.projectedOutcome === "matched").length;
    const reviewRequiredCount = samples.filter(
      (sample) => sample.projectedOutcome === "review_required",
    ).length;
    const changedCount = samples.filter((sample) => sample.changed).length;

    return c.json({
      tenantId: pathParams.tenantId,
      sampleCount: samples.length,
      summary: {
        matchedCount,
        reviewRequiredCount,
        noMatchCount: samples.length - matchedCount - reviewRequiredCount,
        changedCount,
        historicalMatchedCount: samples.filter((sample) => sample.historicalMatched).length,
        historicalReviewRequiredCount: samples.filter(
          (sample) => sample.historicalIssuanceStatus === "review_required",
        ).length,
      },
      samples,
    });
  });

};
