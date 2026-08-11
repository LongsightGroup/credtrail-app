import {
  commitAutomatedBadgeRuleEvaluation,
  findBadgeIssuanceRuleById,
  findBadgeIssuanceRuleVersionById,
  listAssertionsByBadgeTemplatesAndRecipientEmails,
  normalizeEmail,
  type SqlDatabase,
} from "@credtrail/db";
import {
  automatedBadgeRuleLifecycleWindowMatches,
  parseBadgeIssuanceRuleDefinitionJson,
  resolveAutomatedBadgeRuleIssuanceTiming,
  type IssueBadgeQueueJob,
  type ProcessAutomatedBadgeRuleQueueJob,
} from "@credtrail/validation";
import type { GradebookLearnerRecord, GradebookProvider } from "../lms/gradebook-types";
import { resolveGradebookProvider } from "../lms/gradebook-provider-resolution";
import { issueBadgeQueueJobFromRequest } from "../queue/job-builders";
import { resolveBadgeIssuanceRuleDefinitionValueLists } from "../rules/badge-rule-definition-resolver";
import { evaluateBadgeRuleLearner } from "../rules/badge-rule-learner-evaluator";
import { extractBadgeIssuanceRuleRequirements } from "../rules/engine";
import { mapConcurrentBounded } from "../utils/map-concurrent-bounded";
import { issuanceProvenanceFromContext } from "./issue-badge-provenance";

const COURSE_ROSTER_CONCURRENCY = 4;
const LEARNER_EVALUATION_CONCURRENCY = 8;

interface AutomatedLearnerCandidate {
  readonly learnerId: string;
  readonly displayName: string;
  readonly email: string | null;
}

interface CandidateLearnerState {
  readonly learnerId: string;
  displayName: string;
  readonly emailsByNormalizedValue: Map<string, string>;
}

interface CandidateLearnerDiscovery {
  readonly candidates: readonly AutomatedLearnerCandidate[];
  readonly identityConflictCount: number;
}

type AutomatedLearnerEvaluationOutcome =
  | { readonly status: "missing_email" }
  | { readonly status: "already_issued" }
  | { readonly status: "unavailable" }
  | { readonly status: "not_matched" }
  | { readonly status: "matched"; readonly issueJob: IssueBadgeQueueJob };

interface AutomatedEvaluationCounts {
  readonly candidateLearnerCount: number;
  readonly matchedLearnerCount: number;
  readonly learnersMissingEmail: number;
  readonly learnersAlreadyIssued: number;
  readonly learnersUnavailable: number;
  readonly learnerIdentityConflicts: number;
}

/** Observable outcome of one automated badge-rule processing job. */
export type ProcessAutomatedBadgeRuleResult =
  | {
      readonly status: "processed";
      readonly candidateLearnerCount: number;
      readonly matchedLearnerCount: number;
      readonly issueJobsEnqueued: number;
      readonly versionExpired: boolean;
      readonly learnersMissingEmail: number;
      readonly learnersAlreadyIssued: number;
      readonly learnersUnavailable: number;
      readonly learnerIdentityConflicts: number;
    }
  | ({
      readonly status: "retry";
      readonly reason: "learner_evaluation_unavailable";
    } & AutomatedEvaluationCounts)
  | {
      readonly status: "noop";
      readonly reason: string;
    };

const countsFromLearnerOutcomes = (
  outcomes: readonly AutomatedLearnerEvaluationOutcome[],
  discovery: CandidateLearnerDiscovery,
): AutomatedEvaluationCounts => {
  let learnersMissingEmail = 0;
  let learnersAlreadyIssued = 0;
  let learnersUnavailable = 0;
  let matchedLearnerCount = 0;

  for (const outcome of outcomes) {
    switch (outcome.status) {
      case "missing_email":
        learnersMissingEmail += 1;
        break;
      case "already_issued":
        learnersAlreadyIssued += 1;
        break;
      case "unavailable":
        learnersUnavailable += 1;
        break;
      case "matched":
        matchedLearnerCount += 1;
        break;
      case "not_matched":
        break;
    }
  }

  return {
    candidateLearnerCount: discovery.candidates.length,
    matchedLearnerCount,
    learnersMissingEmail,
    learnersAlreadyIssued,
    learnersUnavailable,
    learnerIdentityConflicts: discovery.identityConflictCount,
  };
};

const candidateLearnersFromRosters = (
  courseRosters: readonly (readonly GradebookLearnerRecord[])[],
): CandidateLearnerDiscovery => {
  const statesByLearnerId = new Map<string, CandidateLearnerState>();

  for (const roster of courseRosters) {
    for (const learner of roster) {
      const current = statesByLearnerId.get(learner.learnerId);
      const state = current ?? {
        learnerId: learner.learnerId,
        displayName: learner.displayName,
        emailsByNormalizedValue: new Map<string, string>(),
      };

      if (state.displayName.length === 0 && learner.displayName.length > 0) {
        state.displayName = learner.displayName;
      }

      if (learner.email !== null) {
        state.emailsByNormalizedValue.set(normalizeEmail(learner.email), learner.email);
      }

      statesByLearnerId.set(learner.learnerId, state);
    }
  }

  const conflictingLearnerIds = new Set<string>();
  const learnerIdsByRecipientEmail = new Map<string, string[]>();

  for (const state of statesByLearnerId.values()) {
    if (state.emailsByNormalizedValue.size > 1) {
      conflictingLearnerIds.add(state.learnerId);
      continue;
    }

    const normalizedEmail = [...state.emailsByNormalizedValue.keys()][0];

    if (normalizedEmail === undefined) {
      continue;
    }

    const learnerIds = learnerIdsByRecipientEmail.get(normalizedEmail) ?? [];
    learnerIds.push(state.learnerId);
    learnerIdsByRecipientEmail.set(normalizedEmail, learnerIds);
  }

  for (const learnerIds of learnerIdsByRecipientEmail.values()) {
    if (learnerIds.length < 2) {
      continue;
    }

    for (const learnerId of learnerIds) {
      conflictingLearnerIds.add(learnerId);
    }
  }

  const candidates = [...statesByLearnerId.values()]
    .filter((state) => !conflictingLearnerIds.has(state.learnerId))
    .map(
      (state): AutomatedLearnerCandidate => ({
        learnerId: state.learnerId,
        displayName: state.displayName,
        email: state.emailsByNormalizedValue.values().next().value ?? null,
      }),
    )
    .sort((left, right) => left.learnerId.localeCompare(right.learnerId));

  return {
    candidates,
    identityConflictCount: conflictingLearnerIds.size,
  };
};

const listCandidateLearners = async (
  provider: GradebookProvider,
  courseIds: readonly string[],
): Promise<CandidateLearnerDiscovery> => {
  const courseRosters = await mapConcurrentBounded(
    courseIds,
    { concurrency: COURSE_ROSTER_CONCURRENCY },
    (courseId) => provider.listLearners({ courseId }),
  );

  return candidateLearnersFromRosters(courseRosters);
};

const canStartAutomatedEvaluation = (input: {
  readonly activeVersionId: string | null;
  readonly versionId: string;
  readonly versionStatus: string;
  readonly effectiveStartsAt: string | null;
  readonly expiresAt: string | null;
  readonly evaluatedAt: string;
  readonly issuanceTiming: "immediate" | "end_of_term";
}): boolean =>
  input.activeVersionId === input.versionId &&
  input.versionStatus === "active" &&
  automatedBadgeRuleLifecycleWindowMatches({
    effectiveStartsAt: input.effectiveStartsAt,
    expiresAt: input.expiresAt,
    evaluatedAt: input.evaluatedAt,
    issuanceTiming: input.issuanceTiming,
  });

const resultFromCommit = (
  commit: Awaited<ReturnType<typeof commitAutomatedBadgeRuleEvaluation>>,
  counts: AutomatedEvaluationCounts,
): ProcessAutomatedBadgeRuleResult => {
  if (commit.status === "committed") {
    return {
      status: "processed",
      ...counts,
      issueJobsEnqueued: commit.issueJobsEnqueued,
      versionExpired: commit.versionExpired,
    };
  }

  return {
    status: "noop",
    reason:
      commit.status === "not_automated"
        ? "Rule requires instructor confirmation."
        : "Rule version changed before the evaluation could be committed.",
  };
};

/** Evaluates every LMS learner relevant to one active rule and queues idempotent badge issuance. */
export const processAutomatedBadgeRule = async (input: {
  readonly db: SqlDatabase;
  readonly tenantId: string;
  readonly payload: ProcessAutomatedBadgeRuleQueueJob["payload"];
  readonly sha256Hex: (value: string) => Promise<string>;
  readonly gradebookProvider?: GradebookProvider | undefined;
}): Promise<ProcessAutomatedBadgeRuleResult> => {
  const [rule, version] = await Promise.all([
    findBadgeIssuanceRuleById(input.db, input.tenantId, input.payload.ruleId),
    findBadgeIssuanceRuleVersionById(input.db, {
      tenantId: input.tenantId,
      ruleId: input.payload.ruleId,
      versionId: input.payload.versionId,
    }),
  ]);

  if (rule === null || version === null) {
    return { status: "noop", reason: "Rule or version was not found." };
  }

  const definition = await resolveBadgeIssuanceRuleDefinitionValueLists(
    input.db,
    input.tenantId,
    parseBadgeIssuanceRuleDefinitionJson(version.ruleJson),
  );
  const issuanceTiming = resolveAutomatedBadgeRuleIssuanceTiming(definition);

  if (issuanceTiming === null) {
    return { status: "noop", reason: "Rule requires instructor confirmation." };
  }

  if (
    !canStartAutomatedEvaluation({
      activeVersionId: rule.activeVersionId,
      versionId: version.id,
      versionStatus: version.status,
      effectiveStartsAt: version.effectiveStartsAt,
      expiresAt: version.expiresAt,
      evaluatedAt: input.payload.scheduledFor,
      issuanceTiming,
    })
  ) {
    return { status: "noop", reason: "Rule version is not active for this evaluation." };
  }

  const courseIds = extractBadgeIssuanceRuleRequirements(definition).courseIds;

  if (courseIds.length === 0) {
    throw new Error("Active automated badge rule has no complete LMS learner population");
  }

  if (version.snapshot.lmsConnectionId === null) {
    throw new Error("Active automated badge rule has no LMS connection");
  }

  const lmsConnectionId = version.snapshot.lmsConnectionId;

  const provider =
    input.gradebookProvider ??
    (await resolveGradebookProvider({
      db: input.db,
      tenantId: input.tenantId,
      lmsConnectionId,
      nowIso: input.payload.scheduledFor,
    }));
  const discovery = await listCandidateLearners(provider, courseIds);
  const recipientEmails = discovery.candidates.flatMap((learner) =>
    learner.email === null ? [] : [learner.email],
  );
  const existingAssertions = await listAssertionsByBadgeTemplatesAndRecipientEmails(input.db, {
    tenantId: input.tenantId,
    badgeTemplateIds: [version.snapshot.badgeTemplateId],
    recipientEmails,
  });
  const issuedRecipientEmails = new Set(
    existingAssertions
      .filter((assertion) => assertion.revokedAt === null)
      .map((assertion) => normalizeEmail(assertion.recipientIdentity)),
  );
  const learnerOutcomes = await mapConcurrentBounded(
    discovery.candidates,
    { concurrency: LEARNER_EVALUATION_CONCURRENCY },
    async (learner): Promise<AutomatedLearnerEvaluationOutcome> => {
      if (learner.email === null) {
        return { status: "missing_email" };
      }

      if (issuedRecipientEmails.has(normalizeEmail(learner.email))) {
        return { status: "already_issued" };
      }

      const result = await evaluateBadgeRuleLearner({
        db: input.db,
        tenantId: input.tenantId,
        lmsProviderKind: version.snapshot.lmsProviderKind,
        lmsConnectionId,
        learnerId: learner.learnerId,
        recipientEmail: learner.email,
        definition,
        gradebookProvider: provider,
        nowIso: input.payload.scheduledFor,
      });

      if (result.status === "unavailable") {
        return { status: "unavailable" };
      }

      if (!result.evaluation.matched) {
        return { status: "not_matched" };
      }

      const learnerKey = await input.sha256Hex(
        `${input.tenantId}:${version.id}:${learner.learnerId}`,
      );
      const { job } = issueBadgeQueueJobFromRequest({
        tenantId: input.tenantId,
        badgeTemplateId: version.snapshot.badgeTemplateId,
        recipientIdentity: learner.email,
        recipientIdentityType: "email",
        lmsLearnerIdentity: {
          connectionId: lmsConnectionId,
          learnerId: learner.learnerId,
        },
        ...(learner.displayName.length === 0 ? {} : { recipientDisplayName: learner.displayName }),
        idempotencyKey: `rule-evaluate:${version.id}:${learnerKey}`,
        issuanceProvenance: issuanceProvenanceFromContext({
          source: "rule_evaluate",
          ruleId: rule.id,
          versionId: version.id,
          provenanceJson: result.provenanceJson,
        }),
      });

      return { status: "matched", issueJob: job };
    },
  );
  const issueJobs = learnerOutcomes.flatMap((outcome) =>
    outcome.status === "matched" ? [outcome.issueJob] : [],
  );
  const counts = countsFromLearnerOutcomes(learnerOutcomes, discovery);

  if (counts.learnersUnavailable > 0) {
    return {
      status: "retry",
      reason: "learner_evaluation_unavailable",
      ...counts,
    };
  }

  return resultFromCommit(
    await commitAutomatedBadgeRuleEvaluation(input.db, {
      tenantId: input.tenantId,
      ruleId: rule.id,
      versionId: version.id,
      evaluatedAt: input.payload.scheduledFor,
      issueJobs,
    }),
    counts,
  );
};
