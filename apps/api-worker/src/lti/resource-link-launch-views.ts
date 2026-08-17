import type { SqlDatabase } from "@credtrail/db";
import type { AppBindings } from "../app/types";
import type { AppLogger } from "../app/observability";
import { resolveInstructorResourceLinkViews } from "./instructor-launch-views";
import { resolveLearnerResourceLinkView } from "./learner-launch-views";
import type { LinkedLtiLaunchAccount } from "./launch-account-linking";
import type { ResolvedLtiLaunch } from "./launch-verification";
import type { ValidatedResourceLinkLaunch } from "./resource-link-launch-types";
import type { InstructorResourceLinkViews, LtiLearnerBadgeSummaryView } from "./view-models";

/**
 * Product view models rendered for a Resource Link launch response.
 */
export interface LtiResourceLinkLaunchViews {
  readonly instructorViews: InstructorResourceLinkViews | null;
  readonly learnerView: LtiLearnerBadgeSummaryView | null;
}

/**
 * Verified Resource Link launch context needed to resolve role-specific product views.
 */
export interface ResolveLtiResourceLinkLaunchViewsInput {
  readonly db: SqlDatabase;
  readonly env: AppBindings;
  readonly tenantId: string;
  readonly launchClaims: ResolvedLtiLaunch["launchClaims"];
  readonly resolvedLaunch: ResolvedLtiLaunch;
  readonly validatedResourceLinkLaunch: ValidatedResourceLinkLaunch;
  readonly linkedAccount: LinkedLtiLaunchAccount;
  readonly ltiLog?: AppLogger | undefined;
  readonly sha256Hex: (value: string) => Promise<string>;
  readonly sessionHandoffTtlSeconds: number;
}

/**
 * Resolves role-specific Resource Link launch views from a single launch context.
 */
export const resolveLtiResourceLinkLaunchViews = async (
  input: ResolveLtiResourceLinkLaunchViewsInput,
): Promise<LtiResourceLinkLaunchViews> => {
  if (input.validatedResourceLinkLaunch.launchMessage.roleKind === "instructor") {
    return {
      instructorViews: await resolveInstructorResourceLinkViews({
        db: input.db,
        env: input.env,
        tenantId: input.tenantId,
        launchClaims: input.launchClaims,
        launch: input.validatedResourceLinkLaunch,
        ltiLaunchSession: input.resolvedLaunch.ltiLaunchSession,
        ltiTool: input.resolvedLaunch.ltiTool,
        issuerClientId: input.resolvedLaunch.issuerEntry.clientId,
        linkedUserId: input.linkedAccount.userId,
        membershipRole: input.linkedAccount.membershipRole,
        ltiLog: input.ltiLog,
        sha256Hex: input.sha256Hex,
        sessionHandoffTtlSeconds: input.sessionHandoffTtlSeconds,
      }),
      learnerView: null,
    };
  }

  if (input.validatedResourceLinkLaunch.launchMessage.roleKind === "learner") {
    return {
      instructorViews: null,
      learnerView: await resolveLearnerResourceLinkView({
        db: input.db,
        tenantId: input.tenantId,
        launchClaims: input.launchClaims,
        launch: input.validatedResourceLinkLaunch,
        ltiLaunchSession: input.resolvedLaunch.ltiLaunchSession,
        issuerClientId: input.resolvedLaunch.issuerEntry.clientId,
        linkedUserId: input.linkedAccount.userId,
        ltiLog: input.ltiLog,
      }),
    };
  }

  return {
    instructorViews: null,
    learnerView: null,
  };
};
