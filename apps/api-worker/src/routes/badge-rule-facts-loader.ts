import {
  listIssuedBadgeTemplateIdsForRecipient,
  type BadgeIssuanceRuleLmsProviderKind,
  type SqlDatabase,
} from "@credtrail/db";
import {
  parseBadgeIssuanceRuleDefinition,
  parseEvaluateBadgeIssuanceRuleRequest,
} from "@credtrail/validation";
import {
  extractBadgeIssuanceRuleRequirements,
  type BadgeIssuanceRuleCompletionFact,
  type BadgeIssuanceRuleCustomFieldFact,
  type BadgeIssuanceRuleEvaluationFacts,
  type BadgeIssuanceRuleGradeFact,
  type BadgeIssuanceRuleSubmissionFact,
  type BadgeIssuanceRuleSurveyCompletionFact,
} from "../rules/engine";
import { resolveGradebookProvider } from "../lms/gradebook-provider-resolution";

export const loadRuleFacts = async (input: {
  db: SqlDatabase;
  tenantId: string;
  lmsProviderKind: BadgeIssuanceRuleLmsProviderKind;
  lmsConnectionId?: string | undefined;
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

  if (input.lmsProviderKind !== "canvas" && input.lmsProviderKind !== "sakai") {
    throw new Error(
      `Automated rule evaluation is not implemented for LMS provider "${input.lmsProviderKind}"`,
    );
  }

  const provider = await resolveGradebookProvider({
    db: input.db,
    tenantId: input.tenantId,
    lmsConnectionId: input.lmsConnectionId,
    nowIso: input.nowIso,
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
