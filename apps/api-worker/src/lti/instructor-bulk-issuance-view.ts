import type { SqlDatabase } from "@credtrail/db";
import {
  LTI_CLAIM_DEPLOYMENT_ID,
  type LTI13JwtPayload as LtiLaunchClaims,
  type LTISession,
} from "@longsightgroup/lti-tool";
import type { AppBindings } from "../app/types";
import type { AppLogger } from "../app/observability";
import { LTI_RESOURCE_LINK_ISSUE_PATH } from "./constants";
import { createLtiIssuanceActionToken } from "./issuance-action-token";
import {
  ltiRosterRulePendingIssuanceBehavior,
  ltiRosterUnavailableIssuanceBehavior,
  type LtiRosterIssuanceBehavior,
} from "./issuance-behavior";
import type { LtiNrpsRoster } from "./nrps";
import type { ResourceLinkLaunchMessage } from "./resource-link-launch-types";
import { prepareLtiRosterBulkIssuanceContext } from "./roster-bulk-issuance-context";
import type {
  LtiRosterEligibilityResult,
  LtiRosterIssuedBadgeStateForEligibility,
} from "./roster-eligibility";
import { ltiRosterIssuedBadgeStatesByUserId } from "./roster-issuance-helpers";
import type { LtiBadgeSummaryCard, LtiBulkIssuanceView } from "./view-models";

type InstructorBulkIssuanceViewDependencies = {
  readonly loadIssuedBadgeStatesByUserId: typeof ltiRosterIssuedBadgeStatesByUserId;
  readonly prepareBulkIssuanceContext: typeof prepareLtiRosterBulkIssuanceContext;
  readonly createIssuanceActionToken: typeof createLtiIssuanceActionToken;
};

/**
 * Input for building the ready instructor bulk issuance view for a selected resource-link launch.
 */
export interface ResolveInstructorBulkIssuanceViewInput {
  db: SqlDatabase;
  env: Pick<AppBindings, "LTI_STATE_SIGNING_SECRET">;
  tenantId: string;
  launchClaims: LtiLaunchClaims;
  launchMessage: ResourceLinkLaunchMessage;
  ltiLaunchSession: LTISession;
  roster: LtiNrpsRoster;
  issuerClientId: string;
  resolvedRuleId: string;
  linkedUserId: string;
  selectedBadge: LtiBadgeSummaryCard;
  courseContextTitle: string | null;
  courseContextId: string | null;
  contextMembershipsUrl: string;
  sha256Hex: (value: string) => Promise<string>;
  sessionHandoffTtlSeconds: number;
  nowIso: string;
  ltiLog?: AppLogger | undefined;
}

const ltiRosterRoleSummary = (roles: readonly string[]): string => {
  if (roles.length === 0) {
    return "";
  }

  return roles.join(", ");
};

const ltiBulkIssuanceViewFromRoster = (input: {
  roster: LtiNrpsRoster;
  message: string;
  selectedBadge: LtiBadgeSummaryCard;
  courseContextTitle: string | null;
  courseContextId: string | null;
  contextMembershipsUrl: string;
  issuanceBehavior: LtiRosterIssuanceBehavior;
  issuedBadgeStatesByUserId: ReadonlyMap<string, LtiRosterIssuedBadgeStateForEligibility>;
  eligibilityByUserId: ReadonlyMap<string, LtiRosterEligibilityResult>;
}): LtiBulkIssuanceView => {
  const learnerMembers = input.roster.learnerMembers.map((member) => {
    const issuedState = input.issuedBadgeStatesByUserId.get(member.userId) ?? null;
    const eligibility = input.eligibilityByUserId.get(member.userId);

    if (eligibility === undefined) {
      throw new Error(`Missing roster eligibility for learner ${member.userId}`);
    }

    return {
      userId: member.userId,
      ...(member.lisPersonSourcedId === undefined
        ? {}
        : { lisPersonSourcedId: member.lisPersonSourcedId }),
      displayName: member.displayName,
      email: member.email ?? null,
      roleSummary: ltiRosterRoleSummary(member.roles),
      status: member.status,
      eligibilityStatus: eligibility.status,
      eligibilityLabel: eligibility.label,
      eligibilityDetail: eligibility.detail,
      eligibleForIssuance: eligibility.eligibleForIssuance,
      issuedAssertionId: issuedState?.assertionId ?? null,
      issuedAt: issuedState?.issuedAt ?? null,
      issuanceLifecycleState: issuedState?.lifecycleState ?? null,
    };
  });

  return {
    status: "ready",
    message: input.message,
    selectedBadge: input.selectedBadge,
    courseContextTitle: input.courseContextTitle,
    courseContextId: input.courseContextId ?? input.roster.contextId,
    contextMembershipsUrl: input.contextMembershipsUrl,
    learnerCount: learnerMembers.length,
    totalCount: input.roster.members.length,
    issuanceBehaviorKey: input.issuanceBehavior.key,
    issuanceBehaviorLabel: input.issuanceBehavior.label,
    issuanceBehaviorDetail: input.issuanceBehavior.detail,
    manualIssuanceAllowed: input.issuanceBehavior.manualIssuanceAllowed,
    issuanceActionPath: null,
    issuanceActionToken: null,
    members: learnerMembers,
  };
};

/**
 * Builds a degraded instructor bulk issuance view when roster data is unavailable.
 */
export const emptyInstructorBulkIssuanceView = (input: {
  status: "unavailable" | "error";
  message: string;
  selectedBadge: LtiBadgeSummaryCard;
  courseContextTitle: string | null;
  courseContextId: string | null;
  contextMembershipsUrl: string | null;
}): LtiBulkIssuanceView => {
  return {
    status: input.status,
    message: input.message,
    selectedBadge: input.selectedBadge,
    courseContextTitle: input.courseContextTitle,
    courseContextId: input.courseContextId,
    contextMembershipsUrl: input.contextMembershipsUrl,
    learnerCount: 0,
    totalCount: 0,
    issuanceBehaviorKey:
      input.status === "unavailable"
        ? ltiRosterUnavailableIssuanceBehavior(input.message).key
        : ltiRosterRulePendingIssuanceBehavior(input.message).key,
    issuanceBehaviorLabel:
      input.status === "unavailable"
        ? ltiRosterUnavailableIssuanceBehavior(input.message).label
        : ltiRosterRulePendingIssuanceBehavior(input.message).label,
    issuanceBehaviorDetail: input.message,
    manualIssuanceAllowed: false,
    issuanceActionPath: null,
    issuanceActionToken: null,
    members: [],
  };
};

const ltiBulkIssuanceViewWithAction = (
  view: LtiBulkIssuanceView,
  input: {
    issuanceActionToken: string;
  },
): LtiBulkIssuanceView => {
  return {
    ...view,
    issuanceActionPath: LTI_RESOURCE_LINK_ISSUE_PATH,
    issuanceActionToken: input.issuanceActionToken,
  };
};

const resolveInstructorBulkIssuanceViewWithDependencies = async (
  dependencies: InstructorBulkIssuanceViewDependencies,
  input: ResolveInstructorBulkIssuanceViewInput,
): Promise<LtiBulkIssuanceView> => {
  const issuanceActionContextId = input.courseContextId ?? input.ltiLaunchSession.context.id;
  const rosterIssuanceLookupContext =
    issuanceActionContextId.length > 0
      ? {
          tenantId: input.tenantId,
          issuer: input.launchClaims.iss,
          clientId: input.issuerClientId,
          deploymentId: input.launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
          contextId: issuanceActionContextId,
          resourceLinkId: input.launchMessage.resourceLinkId,
          badgeTemplateId: input.selectedBadge.badgeTemplateId,
        }
      : null;
  const issuedBadgeStatesByUserId =
    rosterIssuanceLookupContext === null
      ? new Map<string, LtiRosterIssuedBadgeStateForEligibility>()
      : await dependencies.loadIssuedBadgeStatesByUserId({
          db: input.db,
          sha256Hex: input.sha256Hex,
          action: rosterIssuanceLookupContext,
          learnerMembers: input.roster.learnerMembers,
        });
  const issuanceActionInput =
    rosterIssuanceLookupContext === null
      ? null
      : {
          ...rosterIssuanceLookupContext,
          ltiSessionId: input.ltiLaunchSession.id,
          issuedByUserId: input.linkedUserId,
        };
  const bulkContext = await dependencies.prepareBulkIssuanceContext({
    db: input.db,
    tenantId: input.tenantId,
    issuer: input.launchClaims.iss,
    clientId: input.issuerClientId,
    deploymentId: input.launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
    resourceLinkId: input.launchMessage.resourceLinkId,
    launchRuleId: input.resolvedRuleId,
    members: input.roster.learnerMembers,
    issuedStatesByUserId: issuedBadgeStatesByUserId,
    nowIso: input.nowIso,
    ltiLog: input.ltiLog,
  });
  let bulkIssuanceView = ltiBulkIssuanceViewFromRoster({
    roster: input.roster,
    message: bulkContext.rosterLoadedMessage,
    selectedBadge: input.selectedBadge,
    courseContextTitle: input.courseContextTitle,
    courseContextId: input.courseContextId,
    contextMembershipsUrl: input.contextMembershipsUrl,
    issuanceBehavior: bulkContext.issuanceBehavior,
    issuedBadgeStatesByUserId,
    eligibilityByUserId: bulkContext.eligibilityByUserId,
  });

  if (issuanceActionInput !== null && bulkContext.issuanceBehavior.manualIssuanceAllowed) {
    bulkIssuanceView = ltiBulkIssuanceViewWithAction(bulkIssuanceView, {
      issuanceActionToken: await dependencies.createIssuanceActionToken(input.env, {
        ...issuanceActionInput,
        ttlSeconds: input.sessionHandoffTtlSeconds,
      }),
    });
  }

  return bulkIssuanceView;
};

const defaultInstructorBulkIssuanceViewDependencies: InstructorBulkIssuanceViewDependencies = {
  loadIssuedBadgeStatesByUserId: ltiRosterIssuedBadgeStatesByUserId,
  prepareBulkIssuanceContext: prepareLtiRosterBulkIssuanceContext,
  createIssuanceActionToken: createLtiIssuanceActionToken,
};

/**
 * Creates an instructor bulk issuance view resolver with explicit dependency replacements.
 */
export const createInstructorBulkIssuanceViewResolver = (
  dependencies: InstructorBulkIssuanceViewDependencies,
): ((input: ResolveInstructorBulkIssuanceViewInput) => Promise<LtiBulkIssuanceView>) => {
  return (input) => resolveInstructorBulkIssuanceViewWithDependencies(dependencies, input);
};

/**
 * Builds the ready instructor bulk issuance view for a selected resource-link launch.
 */
export const resolveInstructorBulkIssuanceView = createInstructorBulkIssuanceViewResolver(
  defaultInstructorBulkIssuanceViewDependencies,
);
