import { listBadgeIssuanceRuleEvaluations, type TenantMembershipRole } from "@credtrail/db";
import {
  parsePreviewEvaluateBadgeIssuanceRuleRequest,
  parsePreviewSimulateBadgeIssuanceRuleRequest,
  parseTenantPathParams,
  type BadgeIssuanceRuleDefinition,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppEnv } from "../app";
import type { RequireTenantRole, ResolveDatabase } from "../app/route-deps";
import {
  GradebookProviderResolutionError,
  isClientGradebookProviderResolutionError,
  resolveGradebookProviderWithConnection,
  type ResolvedGradebookProvider,
} from "../lms/gradebook-provider-resolution";
import { isGradebookProviderRequestCancelled } from "../lms/gradebook-provider-error";
import { gradebookRequestOptionsWithDeadline } from "../lms/gradebook-request-options";
import { lmsLookupErrorMessage } from "../lms/gradebook-picker";
import { authorizeBadgeRuleCourses } from "../rules/badge-rule-course-authorization";
import { resolveBadgeIssuanceRuleDefinitionValueLists } from "../rules/badge-rule-definition-resolver";
import { loadRuleFacts, MissingRuleRecipientIdentityError } from "../rules/badge-rule-facts-loader";
import {
  evaluateBadgeIssuanceRuleDefinition,
  extractBadgeIssuanceRuleRequirements,
  summarizeBadgeIssuanceRuleEvaluation,
  type BadgeIssuanceRuleEvaluationFacts,
} from "../rules/engine";
import {
  badgeRuleEvaluationOutcome,
  parseFactsFromEvaluationRecord,
} from "./badge-rule-evaluation-helpers";

interface RegisterBadgeRulePreviewRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  requireTenantRole: RequireTenantRole;
  ISSUER_ROLES: readonly TenantMembershipRole[];
}

export const registerBadgeRulePreviewRoutes = (
  input: RegisterBadgeRulePreviewRoutesInput,
): void => {
  const { app, resolveDatabase, requireTenantRole, ISSUER_ROLES } = input;

  app.post("/v1/tenants/:tenantId/badge-rules/preview-evaluate", async (c) => {
    const requestOptions = gradebookRequestOptionsWithDeadline({ signal: c.req.raw.signal });
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

    let resolvedProvider: ResolvedGradebookProvider | undefined;

    if (extractBadgeIssuanceRuleRequirements(definition).courseIds.length > 0) {
      try {
        resolvedProvider = await resolveGradebookProviderWithConnection(
          {
            db,
            tenantId: pathParams.tenantId,
            lmsConnectionId: request.lmsConnectionId,
            nowIso,
          },
          requestOptions,
        );
      } catch (error) {
        return c.json(
          {
            error: error instanceof Error ? error.message : "Unable to use LMS connection",
          },
          (error instanceof GradebookProviderResolutionError && error.reason === "cancelled") ||
            isGradebookProviderRequestCancelled(error, requestOptions)
            ? 408
            : isClientGradebookProviderResolutionError(error)
              ? 422
              : 409,
        );
      }

      try {
        const authorization = await authorizeBadgeRuleCourses(
          {
            db,
            resolvedProvider,
            userId: roleCheck.principal.userId,
            definition,
          },
          requestOptions,
        );

        if (authorization.status !== "authorized") {
          return c.json({ error: authorization.error }, 403);
        }
      } catch (error) {
        return c.json(
          {
            error: lmsLookupErrorMessage(
              resolvedProvider.connection,
              error,
              "Unable to verify LMS course access",
            ),
          },
          isGradebookProviderRequestCancelled(error, requestOptions) ? 408 : 502,
        );
      }
    }

    let facts: BadgeIssuanceRuleEvaluationFacts;

    try {
      facts = await loadRuleFacts(
        {
          db,
          tenantId: pathParams.tenantId,
          lmsProviderKind: request.lmsProviderKind,
          lmsConnectionId: request.lmsConnectionId,
          learnerId: request.learnerId,
          ...(request.recipient === undefined ? {} : { recipient: request.recipient }),
          definition,
          requestedFacts: request.facts,
          ...(resolvedProvider === undefined
            ? {}
            : { gradebookProvider: resolvedProvider.provider }),
          nowIso,
        },
        requestOptions,
      );
    } catch (error) {
      return c.json(
        {
          error: error instanceof Error ? error.message : "Failed to load rule facts",
        },
        isGradebookProviderRequestCancelled(error, requestOptions)
          ? 408
          : isClientGradebookProviderResolutionError(error) ||
              error instanceof MissingRuleRecipientIdentityError
            ? 422
            : 502,
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
