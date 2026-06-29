import type { LTISession, LTITool } from "@lti-tool/core";
import type { AppContext } from "../app";
import type { DirectIssueBadgeRequest } from "../badges/recipient-identifiers";
import type { DirectIssueBadgeResult } from "../badges/direct-issue";
import type { SqlDatabase } from "@credtrail/db";
import type { LtiIssuanceActionPayload } from "./issuance-action-token";
import { logLtiWarning } from "./log";
import { loadLtiNrpsRoster, type LtiNrpsMember } from "./nrps";
import {
  ltiIssuanceIdempotencyKeyFromPrefix,
  ltiIssuanceIdempotencyKeyPrefix,
  ltiRosterIssuedBadgeStatesByUserId,
  skippedLtiIssuanceResult,
} from "./roster-issuance-helpers";
import {
  prepareLtiRosterRuleIssuanceContext,
  ltiRosterIssuanceSkipDetail,
} from "./roster-bulk-issuance-context";
import { evaluateLtiRosterMembersEligibility } from "./roster-eligibility";
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
  const rosterResult = await loadLtiNrpsRoster({
    ltiTool: input.ltiTool,
    ltiSession: input.ltiSession,
    contextId: input.ltiSession.context.id,
  });

  if (!rosterResult.success) {
    logLtiWarning("Could not load LMS roster for resource-link badge issuance", {
      tenantId: input.issuanceAction.tenantId,
      ltiSessionId: input.issuanceAction.ltiSessionId,
      ...rosterResult.failure.logDetail,
    });

    throw new LtiRosterIssuanceError(
      "CredTrail could not load the learner roster from the LMS. Check the LMS connection settings.",
    );
  }

  const roster = rosterResult.roster;
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
  const ruleContext = await prepareLtiRosterRuleIssuanceContext({
    db: input.db,
    tenantId: input.issuanceAction.tenantId,
    issuer: input.issuanceAction.issuer,
    clientId: input.issuanceAction.clientId,
    deploymentId: input.issuanceAction.deploymentId,
    resourceLinkId: input.issuanceAction.resourceLinkId,
    launchRuleId: null,
  });
  const eligibilityByUserId = ruleContext.issuanceBehavior.manualIssuanceAllowed
    ? await evaluateLtiRosterMembersEligibility({
        db: input.db,
        tenantId: input.issuanceAction.tenantId,
        ruleResolution: ruleContext.ruleResolution,
        members: roster.learnerMembers,
        issuedStatesByUserId: issuedBadgeStatesByUserId,
        nowIso: new Date().toISOString(),
        prepared: ruleContext.prepared,
      })
    : new Map();

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

    const issuedState = issuedBadgeStatesByUserId.get(member.userId) ?? null;
    const skipDetail = ltiRosterIssuanceSkipDetail({
      issuedState,
      ruleContext,
    });

    if (skipDetail !== null) {
      results.push(skippedLtiIssuanceResult(member, skipDetail));
      continue;
    }

    const eligibility = eligibilityByUserId.get(member.userId);

    if (eligibility === undefined || !eligibility.eligibleForIssuance) {
      results.push(
        skippedLtiIssuanceResult(
          member,
          eligibility?.detail ?? "Learner is not eligible for badge issuance.",
        ),
      );
      continue;
    }

    const recipientEmail = member.email;

    if (recipientEmail === null) {
      results.push(skippedLtiIssuanceResult(member, eligibility.detail));
      continue;
    }

    const request: DirectIssueBadgeRequest = {
      badgeTemplateId: input.issuanceAction.badgeTemplateId,
      recipientIdentity: recipientEmail,
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
    try {
      const issuance = await input.issueBadgeForTenant(
        input.c,
        input.issuanceAction.tenantId,
        request,
        input.issuanceAction.issuedByUserId,
        { recipientDisplayName: member.displayName },
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
