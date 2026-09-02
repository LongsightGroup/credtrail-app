import {
  findTenantLmsConnectionByLtiRegistration,
  observeVerifiedLtiCourseContext,
  placeStableLtiBadgeRule,
  type PlaceStableLtiBadgeRuleResult,
  type SqlDatabase,
} from "@credtrail/db";
import { LTI_CLAIM_DEPLOYMENT_ID } from "@longsightgroup/lti-tool";
import type { AppContext } from "../app/types";
import { renderAppPage } from "../ui/render-page";
import { LTI_SESSION_HANDOFF_TTL_SECONDS } from "./constants";
import type { LinkedLtiLaunchAccount } from "./launch-account-linking";
import {
  type EstablishedLtiLaunchSession,
  type PreparedResourceLinkLaunch,
  type PrepareLaunchedResourceLinkPlacementInput,
  type ProductFlowResult,
  productFlowFailure,
  productFlowSuccess,
} from "./launch-product-types";
import type { ResolvedLtiLaunch } from "./launch-verification";
import { ltiDisplayNameFromClaims, ltiLearnerDashboardPath } from "./lti-helpers";
import { resolveLtiResourceLinkLaunchViews } from "./resource-link-launch-views";
import type {
  CourseResourceLinkLaunchMessage,
  SelectedResourceLinkLaunchMessage,
  ValidatedResourceLinkLaunch,
} from "./resource-link-launch-types";
import { createLtiSessionHandoffToken } from "./session-handoff";
import { ltiLaunchResultPage } from "./pages";

const courseCode = (label: string | undefined): string | null => {
  const normalized = label?.trim() ?? "";
  return normalized.length === 0 ? null : normalized;
};

const placementDenialMessage = (
  result: Exclude<
    PlaceStableLtiBadgeRuleResult,
    { readonly status: "placed" | "reactivated" | "existing" }
  >,
): string => {
  switch (result.status) {
    case "replace_link_required":
      return "This older LMS link does not identify a governed badge rule. Replace the link from the LMS add-content workflow.";
    case "placement_conflict":
      return "This LMS link conflicts with its saved CredTrail placement. Replace the link or contact your administrator.";
    case "rule_not_found":
      return "The governed badge rule for this LMS link could not be found.";
    case "rule_not_active":
      return "The governed badge rule for this LMS link is not currently active.";
    case "template_mismatch":
      return "The badge attached to this LMS link no longer matches its governed rule.";
    case "course_context_not_found":
      return "CredTrail could not verify this LMS course against the connected registration.";
    case "course_unmapped":
      return "This LMS course must be mapped to an organizational area before this badge rule can be used here.";
    case "outside_availability":
      return "This badge rule is not currently offered in this course.";
    case "course_relative_rule_not_supported":
      return "This older course-specific rule cannot be copied into a new LMS placement.";
  }
};

/**
 * Reauthorizes and records the stable rule implied by a verified Resource Link launch.
 */
export const prepareLaunchedResourceLinkPlacement = async (
  input: PrepareLaunchedResourceLinkPlacementInput,
): Promise<ProductFlowResult<PreparedResourceLinkLaunch>> => {
  const deploymentId = input.launchClaims[LTI_CLAIM_DEPLOYMENT_ID];
  const lmsConnection = await findTenantLmsConnectionByLtiRegistration(input.db, {
    tenantId: input.tenantId,
    issuer: input.launchClaims.iss,
    clientId: input.issuerEntryClientId,
    deploymentId,
  });

  if (lmsConnection === null) {
    return productFlowFailure({
      status: 403,
      surface: "lti_rule_unavailable",
      body: {
        error: "This LTI registration is not connected to an LMS in CredTrail.",
        reason: "course_context_not_found",
      },
    });
  }

  const sessionContextId = input.resolvedLaunch.ltiLaunchSession.context.id.trim();
  const messageContextId = input.launch.launchMessage.resourceContextId?.trim() ?? "";
  const contextId = messageContextId.length === 0 ? sessionContextId : messageContextId;

  if (contextId.length === 0 || (sessionContextId.length > 0 && contextId !== sessionContextId)) {
    return productFlowFailure({
      status: 403,
      surface: "lti_rule_unavailable",
      body: {
        error: "CredTrail could not verify the LMS course for this link.",
        reason: "course_context_not_found",
      },
    });
  }

  const contextTitle = input.resolvedLaunch.ltiLaunchSession.context.title.trim();
  await observeVerifiedLtiCourseContext(input.db, {
    tenantId: input.tenantId,
    lmsConnectionId: lmsConnection.id,
    contextId,
    displayName: contextTitle.length === 0 ? "LMS course" : contextTitle,
    courseCode: courseCode(input.resolvedLaunch.ltiLaunchSession.context.label),
  });
  const placement = await placeStableLtiBadgeRule(input.db, {
    tenantId: input.tenantId,
    lmsConnectionId: lmsConnection.id,
    contextId,
    issuer: input.launchClaims.iss,
    clientId: input.issuerEntryClientId,
    deploymentId,
    resourceLinkId: input.launch.launchMessage.resourceLinkId,
    incomingRuleId: input.launch.launchMessage.ruleId,
    incomingBadgeTemplateId: input.launch.launchMessage.badgeTemplateId,
    linkedUserId: input.linkedUserId,
    roleKind: input.launch.launchMessage.roleKind,
  });

  if (placement.status === "replace_link_required") {
    if (
      input.launch.launchMessage.ruleId === null &&
      input.launch.launchMessage.badgeTemplateId === null
    ) {
      return productFlowSuccess({
        launch: {
          kind: "course",
          launchMessage: {
            ...input.launch.launchMessage,
            badgeTemplateId: null,
          } satisfies CourseResourceLinkLaunchMessage,
        },
      });
    }
  }

  if (
    placement.status !== "placed" &&
    placement.status !== "reactivated" &&
    placement.status !== "existing"
  ) {
    return productFlowFailure({
      status: 403,
      surface: "lti_rule_unavailable",
      body: {
        error: placementDenialMessage(placement),
        reason: placement.status,
      },
    });
  }

  return productFlowSuccess({
    launch: {
      kind: "selected",
      launchMessage: {
        ...input.launch.launchMessage,
        badgeTemplateId: placement.badgeTemplate.id,
        ruleId: placement.rule.id,
      } satisfies SelectedResourceLinkLaunchMessage,
      launchedBadgeTemplate: placement.badgeTemplate,
      rule: placement.rule,
      version: placement.version,
      placement: placement.placement,
    },
  });
};

const buildLtiLaunchDashboardPath = async (input: {
  c: AppContext;
  tenantId: string;
  createdSession: EstablishedLtiLaunchSession["createdSession"];
}): Promise<string> => {
  const basePath = ltiLearnerDashboardPath(input.tenantId);

  if (input.createdSession.browserSessionToken === undefined) {
    return basePath;
  }

  const dashboardUrl = new URL(basePath, input.c.req.url);
  dashboardUrl.searchParams.set(
    "lti_session_handoff",
    await createLtiSessionHandoffToken(input.c.env, {
      tenantId: input.tenantId,
      sessionToken: input.createdSession.browserSessionToken,
      ttlSeconds: LTI_SESSION_HANDOFF_TTL_SECONDS,
    }),
  );

  return `${dashboardUrl.pathname}${dashboardUrl.search}`;
};

/**
 * Renders CredTrail's product UI for a verified LTI Resource Link launch.
 */
export const renderLtiResourceLinkLaunchResponse = async (input: {
  c: AppContext;
  db: SqlDatabase;
  tenantId: string;
  launchClaims: ResolvedLtiLaunch["launchClaims"];
  launchMessage: ValidatedResourceLinkLaunch["launchMessage"];
  linkedAccount: LinkedLtiLaunchAccount;
  establishedSession: EstablishedLtiLaunchSession;
  resolvedLaunch: ResolvedLtiLaunch;
  validatedResourceLinkLaunch: ValidatedResourceLinkLaunch;
  sha256Hex: (value: string) => Promise<string>;
}): Promise<Response> => {
  const [dashboardPath, resourceLinkViews] = await Promise.all([
    buildLtiLaunchDashboardPath({
      c: input.c,
      tenantId: input.tenantId,
      createdSession: input.establishedSession.createdSession,
    }),
    resolveLtiResourceLinkLaunchViews({
      db: input.db,
      env: input.c.env,
      tenantId: input.tenantId,
      launchClaims: input.launchClaims,
      resolvedLaunch: input.resolvedLaunch,
      validatedResourceLinkLaunch: input.validatedResourceLinkLaunch,
      linkedAccount: input.linkedAccount,
      sha256Hex: input.sha256Hex,
      sessionHandoffTtlSeconds: LTI_SESSION_HANDOFF_TTL_SECONDS,
    }),
  ]);

  return renderAppPage(
    input.c,
    ltiLaunchResultPage({
      roleKind: input.launchMessage.roleKind,
      tenantId: input.tenantId,
      userId: input.linkedAccount.userId,
      membershipRole: input.linkedAccount.membershipRole,
      learnerProfileId: input.linkedAccount.learnerProfileId,
      issuer: input.launchClaims.iss,
      deploymentId: input.launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
      subjectId: input.launchClaims.sub,
      targetLinkUri: input.launchMessage.resolvedTargetLinkUri,
      messageType: input.launchMessage.messageType,
      launchDisplayName: ltiDisplayNameFromClaims(input.launchClaims) ?? null,
      dashboardPath,
      instructorViews: resourceLinkViews.instructorViews,
      learnerView: resourceLinkViews.learnerView,
    }),
  );
};
