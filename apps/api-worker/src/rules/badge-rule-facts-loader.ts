import {
  listIssuedBadgeTemplateIdsForRecipient,
  type BadgeIssuanceRuleLmsProviderKind,
  type SqlDatabase,
} from "@credtrail/db";
import {
  type BadgeIssuanceRuleFacts,
  parseBadgeIssuanceRuleDefinition,
} from "@credtrail/validation";
import {
  extractBadgeIssuanceRuleRequirements,
  type BadgeIssuanceRuleCompletionFact,
  type BadgeIssuanceRuleCustomFieldFact,
  type BadgeIssuanceRuleEvaluationFacts,
  type BadgeIssuanceRuleGradeFact,
  type BadgeIssuanceRuleSubmissionFact,
  type BadgeIssuanceRuleSurveyCompletionFact,
} from "./engine";
import { resolveGradebookProvider } from "../lms/gradebook-provider-resolution";
import type { GradebookRuleFactReader } from "../lms/gradebook-types";

export class MissingRuleRecipientIdentityError extends Error {
  public constructor() {
    super("Credential email is required to test a prerequisite badge requirement");
    this.name = "MissingRuleRecipientIdentityError";
  }
}

export const loadRuleFacts = async (input: {
  db: SqlDatabase;
  tenantId: string;
  lmsProviderKind: BadgeIssuanceRuleLmsProviderKind;
  lmsConnectionId?: string | undefined;
  learnerId: string;
  recipient?:
    | {
        identity: string;
        identityType: "email" | "email_sha256" | "did" | "url";
      }
    | undefined;
  definition: ReturnType<typeof parseBadgeIssuanceRuleDefinition>;
  requestedFacts?: BadgeIssuanceRuleFacts | undefined;
  gradebookProvider?: GradebookRuleFactReader | undefined;
  nowIso: string;
}): Promise<BadgeIssuanceRuleEvaluationFacts> => {
  const requestedFacts = input.requestedFacts;
  const requirements = extractBadgeIssuanceRuleRequirements(input.definition);

  const loadEarnedBadgeTemplateIds = async (
    requested: readonly string[] | undefined,
  ): Promise<readonly string[]> => {
    if (requested !== undefined) {
      return requested;
    }

    if (requirements.prerequisiteBadgeTemplateIds.length === 0) {
      return [];
    }

    if (input.recipient === undefined) {
      throw new MissingRuleRecipientIdentityError();
    }

    return listIssuedBadgeTemplateIdsForRecipient(input.db, {
      tenantId: input.tenantId,
      recipientIdentity: input.recipient.identity,
      recipientIdentityType: input.recipient.identityType,
    });
  };

  if (requestedFacts !== undefined) {
    const earnedBadgeTemplateIds = await loadEarnedBadgeTemplateIds(
      requestedFacts.earnedBadgeTemplateIds,
    );

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

  if (input.lmsProviderKind !== "canvas" && input.lmsProviderKind !== "sakai") {
    throw new Error(
      `Automated rule evaluation is not implemented for LMS provider "${input.lmsProviderKind}"`,
    );
  }

  const earnedBadgeTemplateIds = await loadEarnedBadgeTemplateIds(undefined);

  const provider =
    input.gradebookProvider ??
    (await resolveGradebookProvider({
      db: input.db,
      tenantId: input.tenantId,
      lmsConnectionId: input.lmsConnectionId,
      nowIso: input.nowIso,
    }));

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
