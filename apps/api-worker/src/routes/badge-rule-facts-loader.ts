import {
  findTenantCanvasGradebookIntegration,
  listIssuedBadgeTemplateIdsForRecipient,
  updateTenantCanvasGradebookIntegrationTokens,
  type BadgeIssuanceRuleLmsProviderKind,
  type SqlDatabase,
} from "@credtrail/db";
import {
  parseBadgeIssuanceRuleDefinition,
  parseEvaluateBadgeIssuanceRuleRequest,
} from "@credtrail/validation";
import { refreshCanvasAccessToken } from "../lms/canvas-oauth";
import { createGradebookProvider } from "../lms/gradebook-provider";
import {
  extractBadgeIssuanceRuleRequirements,
  type BadgeIssuanceRuleCompletionFact,
  type BadgeIssuanceRuleCustomFieldFact,
  type BadgeIssuanceRuleEvaluationFacts,
  type BadgeIssuanceRuleGradeFact,
  type BadgeIssuanceRuleSubmissionFact,
  type BadgeIssuanceRuleSurveyCompletionFact,
} from "../rules/engine";

const isAccessTokenExpired = (accessTokenExpiresAt: string | null, nowIso: string): boolean => {
  if (accessTokenExpiresAt === null) {
    return false;
  }

  const expiryMs = Date.parse(accessTokenExpiresAt);
  const nowMs = Date.parse(nowIso);

  if (!Number.isFinite(expiryMs) || !Number.isFinite(nowMs)) {
    return false;
  }

  return nowMs >= expiryMs;
};

export const loadRuleFacts = async (input: {
  db: SqlDatabase;
  tenantId: string;
  lmsProviderKind: BadgeIssuanceRuleLmsProviderKind;
  learnerId: string;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  definition: ReturnType<typeof parseBadgeIssuanceRuleDefinition>;
  requestedFacts?: ReturnType<typeof parseEvaluateBadgeIssuanceRuleRequest>["facts"];
  nowIso: string;
}): Promise<BadgeIssuanceRuleEvaluationFacts> => {
  const requestedFacts = input.requestedFacts;

  if (requestedFacts !== undefined) {
    const earnedBadgeTemplateIds =
      requestedFacts.earnedBadgeTemplateIds ??
      (await listIssuedBadgeTemplateIdsForRecipient(input.db, {
        tenantId: input.tenantId,
        recipientIdentity: input.recipientIdentity,
        recipientIdentityType: input.recipientIdentityType,
      }));

    return {
      learnerId: input.learnerId,
      nowIso: requestedFacts.nowIso ?? input.nowIso,
      grades: (requestedFacts.grades ?? []).map((fact) => ({
        courseId: fact.courseId,
        learnerId: fact.learnerId,
        currentScore: fact.currentScore ?? null,
        finalScore: fact.finalScore ?? null,
      })),
      completions: (requestedFacts.completions ?? []).map((fact) => ({
        courseId: fact.courseId,
        learnerId: fact.learnerId,
        completed: fact.completed,
        completionPercent: fact.completionPercent ?? null,
      })),
      submissions: (requestedFacts.submissions ?? []).map((fact) => ({
        courseId: fact.courseId,
        assignmentId: fact.assignmentId,
        learnerId: fact.learnerId,
        score: fact.score ?? null,
        workflowState: fact.workflowState ?? null,
        submittedAt: fact.submittedAt ?? null,
      })),
      surveyCompletions: (requestedFacts.surveyCompletions ?? []).map((fact) => ({
        surveyId: fact.surveyId,
        learnerId: fact.learnerId,
        source: fact.source ?? null,
        completed: fact.completed,
        completedAt: fact.completedAt ?? null,
      })),
      customFields: (requestedFacts.customFields ?? []).map((fact) => ({
        learnerId: fact.learnerId,
        fieldName: fact.fieldName,
        value: fact.value,
      })),
      earnedBadgeTemplateIds,
    };
  }

  const requirements = extractBadgeIssuanceRuleRequirements(input.definition);
  const providerLabel = input.lmsProviderKind === "sakai" ? "Sakai" : "Canvas";

  if (input.lmsProviderKind !== "canvas" && input.lmsProviderKind !== "sakai") {
    throw new Error(
      `Automated rule evaluation is not implemented for LMS provider "${input.lmsProviderKind}"`,
    );
  }

  const integration = await findTenantCanvasGradebookIntegration(input.db, input.tenantId);

  if (integration === null) {
    throw new Error(
      `${providerLabel} gradebook integration is required for automated rule evaluation`,
    );
  }

  let accessToken = integration.accessToken;

  if (accessToken === null) {
    throw new Error(
      `${providerLabel} gradebook integration has no access token. Connect LMS first.`,
    );
  }

  if (
    isAccessTokenExpired(integration.accessTokenExpiresAt, input.nowIso) &&
    integration.refreshToken !== null
  ) {
    const refresh = await refreshCanvasAccessToken({
      tokenEndpoint: integration.tokenEndpoint,
      clientId: integration.clientId,
      clientSecret: integration.clientSecret,
      refreshToken: integration.refreshToken,
    });
    const refreshed = await updateTenantCanvasGradebookIntegrationTokens(input.db, {
      tenantId: input.tenantId,
      accessToken: refresh.accessToken,
      refreshToken: refresh.refreshToken,
      accessTokenExpiresAt:
        refresh.expiresInSeconds === undefined
          ? undefined
          : new Date(Date.parse(input.nowIso) + refresh.expiresInSeconds * 1000).toISOString(),
      refreshTokenExpiresAt:
        refresh.refreshTokenExpiresInSeconds === undefined
          ? undefined
          : new Date(
              Date.parse(input.nowIso) + refresh.refreshTokenExpiresInSeconds * 1000,
            ).toISOString(),
    });

    if (refreshed !== null && refreshed.accessToken !== null) {
      accessToken = refreshed.accessToken;
    }
  }

  const provider = createGradebookProvider({
    config: {
      kind: input.lmsProviderKind,
      apiBaseUrl: integration.apiBaseUrl,
      accessToken,
    },
  });

  const grades: BadgeIssuanceRuleGradeFact[] = [];
  const completions: BadgeIssuanceRuleCompletionFact[] = [];
  const submissions: BadgeIssuanceRuleSubmissionFact[] = [];
  const surveyCompletions: BadgeIssuanceRuleSurveyCompletionFact[] = [];
  const customFields: BadgeIssuanceRuleCustomFieldFact[] = [];

  for (const courseId of requirements.courseIds) {
    const [courseGrades, courseCompletions] = await Promise.all([
      provider.listGrades({
        courseId,
        learnerId: input.learnerId,
      }),
      provider.listCompletions({
        courseId,
        learnerId: input.learnerId,
      }),
    ]);

    grades.push(
      ...courseGrades.map((grade) => ({
        courseId: grade.courseId,
        learnerId: grade.learnerId,
        currentScore: grade.currentScore,
        finalScore: grade.finalScore,
      })),
    );
    completions.push(
      ...courseCompletions.map((completion) => ({
        courseId: completion.courseId,
        learnerId: completion.learnerId,
        completed: completion.completed,
        completionPercent: completion.completionPercent,
      })),
    );
  }

  for (const assignment of requirements.assignmentRefs) {
    const assignmentSubmissions = await provider.listSubmissions({
      courseId: assignment.courseId,
      assignmentId: assignment.assignmentId,
      learnerId: input.learnerId,
    });

    submissions.push(
      ...assignmentSubmissions.map((submission) => ({
        courseId: submission.courseId,
        assignmentId: submission.assignmentId,
        learnerId: submission.learnerId,
        score: submission.score,
        workflowState: submission.workflowState,
        submittedAt: submission.submittedAt,
      })),
    );
  }

  const earnedBadgeTemplateIds = await listIssuedBadgeTemplateIdsForRecipient(input.db, {
    tenantId: input.tenantId,
    recipientIdentity: input.recipientIdentity,
    recipientIdentityType: input.recipientIdentityType,
  });

  return {
    learnerId: input.learnerId,
    nowIso: input.nowIso,
    grades,
    completions,
    submissions,
    surveyCompletions,
    customFields,
    earnedBadgeTemplateIds,
  };
};
