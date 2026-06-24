import type { LTISession, LTITool } from "@lti-tool/core";
import type { AppContext } from "../app";
import type { DirectIssueBadgeRequest } from "../badges/recipient-identifiers";
import type { DirectIssueBadgeResult } from "../badges/direct-issue";
import type { SqlDatabase } from "@credtrail/db";
import type { LtiIssuanceActionPayload } from "./issuance-action-token";
import { logLtiWarning } from "./log";
import { ltiNrpsRosterFromCoreMembers, type LtiNrpsMember } from "./nrps";
import { evaluateLtiRosterMemberIssuanceEligibility } from "./roster-eligibility";
import {
  ltiIssuanceIdempotencyKeyFromPrefix,
  ltiIssuanceIdempotencyKeyPrefix,
  ltiRosterIssuedBadgeStatesByUserId,
  skippedLtiIssuanceResult,
} from "./roster-issuance-helpers";
import type { LtiRosterIssuanceResultEntry } from "./view-models";

export class LtiRosterIssuanceError extends Error {
  readonly status: 502;

  constructor(message: string) {
    super(message);
    this.name = "LtiRosterIssuanceError";
    this.status = 502;
  }
}

export interface ExecuteLtiRosterIssuanceInput {
  c: AppContext;
  db: SqlDatabase;
  ltiTool: LTITool;
  ltiSession: LTISession;
  issuanceAction: LtiIssuanceActionPayload;
  selectedLearnerUserIds: readonly string[];
  sha256Hex: (value: string) => Promise<string>;
  issueBadgeForTenant: (
    c: AppContext,
    tenantId: string,
    request: DirectIssueBadgeRequest,
    issuedByUserId?: string,
    options?: {
      recipientDisplayName?: string;
      issuerName?: string;
      issuerUrl?: string;
    },
  ) => Promise<DirectIssueBadgeResult>;
}

export interface ExecuteLtiRosterIssuanceResult {
  tenantId: string;
  badgeTemplateId: string;
  courseContextTitle: string | null;
  selectedCount: number;
  results: readonly LtiRosterIssuanceResultEntry[];
}

export const executeLtiRosterIssuance = async (
  input: ExecuteLtiRosterIssuanceInput,
): Promise<ExecuteLtiRosterIssuanceResult> => {
  let roster;

  try {
    const members = await input.ltiTool.getMembers(input.ltiSession);
    roster = ltiNrpsRosterFromCoreMembers({
      contextId: input.ltiSession.context.id,
      members,
    });
  } catch (error) {
    logLtiWarning("Could not load LMS roster for resource-link badge issuance", {
      tenantId: input.issuanceAction.tenantId,
      ltiSessionId: input.issuanceAction.ltiSessionId,
      detail: error instanceof Error ? error.message : "unknown error",
    });

    throw new LtiRosterIssuanceError(
      "CredTrail could not load the learner roster from the LMS. Check the LMS connection settings.",
    );
  }

  const learnersByUserId = new Map(
    roster.learnerMembers.map((member): [string, LtiNrpsMember] => [member.userId, member]),
  );
  const results: LtiRosterIssuanceResultEntry[] = [];
  const idempotencyKeyPrefix = ltiIssuanceIdempotencyKeyPrefix(input.issuanceAction);
  const issuedBadgeStatesByUserId = await ltiRosterIssuedBadgeStatesByUserId({
    db: input.db,
    sha256Hex: input.sha256Hex,
    action: input.issuanceAction,
    learnerMembers: roster.learnerMembers,
  });
  const nowIso = new Date().toISOString();

  for (const learnerUserId of input.selectedLearnerUserIds) {
    const member = learnersByUserId.get(learnerUserId);

    if (member === undefined) {
      results.push({
        userId: learnerUserId,
        displayName: null,
        email: null,
        status: "skipped",
        message: "Learner is not present in the current LMS roster.",
        assertionId: null,
      });
      continue;
    }

    if (member.email === null) {
      results.push(skippedLtiIssuanceResult(member, "The LMS did not provide an email address."));
      continue;
    }

    const eligibility = await evaluateLtiRosterMemberIssuanceEligibility({
      db: input.db,
      issuanceAction: input.issuanceAction,
      member,
      issuedState: issuedBadgeStatesByUserId.get(member.userId) ?? null,
      nowIso,
    });

    if (eligibility.status === "already_issued") {
      results.push(skippedLtiIssuanceResult(member, "Badge was already issued for this learner."));
      continue;
    }

    if (!eligibility.eligibleForIssuance) {
      results.push(skippedLtiIssuanceResult(member, eligibility.detail));
      continue;
    }

    const request: DirectIssueBadgeRequest = {
      badgeTemplateId: input.issuanceAction.badgeTemplateId,
      recipientIdentity: member.email,
      recipientIdentityType: "email",
      ...(member.sourcedId === null
        ? {}
        : {
            recipientIdentifiers: [
              {
                identifierType: "sourcedId",
                identifier: member.sourcedId,
              },
            ],
          }),
      idempotencyKey: await ltiIssuanceIdempotencyKeyFromPrefix(
        input.sha256Hex,
        idempotencyKeyPrefix,
        member.userId,
      ),
    };
    const issueOptions =
      member.displayName === null ? {} : { recipientDisplayName: member.displayName };

    try {
      const issuance = await input.issueBadgeForTenant(
        input.c,
        input.issuanceAction.tenantId,
        request,
        input.issuanceAction.issuedByUserId,
        issueOptions,
      );

      results.push({
        userId: member.userId,
        displayName: member.displayName,
        email: member.email,
        status: issuance.status,
        message:
          issuance.status === "issued"
            ? "Badge issued."
            : "Badge was already issued for this learner.",
        assertionId: issuance.assertionId,
      });
    } catch (error) {
      results.push({
        userId: member.userId,
        displayName: member.displayName,
        email: member.email,
        status: "failed",
        message: error instanceof Error ? error.message : "Badge issuance failed.",
        assertionId: null,
      });
    }
  }

  return {
    tenantId: input.issuanceAction.tenantId,
    badgeTemplateId: input.issuanceAction.badgeTemplateId,
    courseContextTitle:
      input.ltiSession.context.title.length === 0 ? null : input.ltiSession.context.title,
    selectedCount: input.selectedLearnerUserIds.length,
    results,
  };
};
