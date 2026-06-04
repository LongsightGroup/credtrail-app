import {
  findBadgeTemplateById,
  listAssertionsByBadgeTemplatesAndRecipientEmails,
  listAssertionLifecycleStatesByAssertionIds,
  listAssertionsByIdempotencyKeys,
  listBadgeTemplates,
  listBadgeTemplatesByIds,
  listLtiResourceLinkPlacementsForContext,
  normalizeEmail,
  upsertLtiDeployment,
  upsertLtiResourceLinkPlacement,
  type AssertionRecord,
  type AssertionLifecycleState,
  type BadgeTemplateRecord,
  type LtiResourceLinkPlacementRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { DeepLinkingContentItem, LTISession } from "@lti-tool/core";
import {
  LTI_CLAIM_CONTEXT,
  LTI_CLAIM_DEPLOYMENT_ID,
  parseLtiOidcLoginInitiationRequest,
} from "@credtrail/lti";
import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app";
import { renderAppPage } from "../ui/render-page";
import type { LtiAuthenticatedPrincipal, LtiSessionInput } from "../auth/auth-provider";
import type { DirectIssueBadgeRequest } from "../badges/recipient-identifiers";
import type { DirectIssueBadgeResult } from "../badges/direct-issue";
import { LTI_LAUNCH_PATH, LTI_OIDC_LOGIN_PATH } from "../lti/constants";
import {
  ltiLaunchFormInputFromRequest,
  ltiLearnerDashboardPath,
  ltiLoginInputFromRequest,
  ltiDisplayNameFromClaims,
  normalizeLtiIssuer,
  type LtiIssuerRegistryEntry,
  type LtiIssuerRegistry,
} from "../lti/lti-helpers";
import { createCredTrailLtiTool } from "../lti/credtrail-lti-tool";
import { linkLtiLaunchAccount } from "../lti/launch-account-linking";
import { LtiLaunchMessageError, resolveLtiLaunchMessage } from "../lti/launch-message";
import {
  LtiLaunchVerificationError,
  ltiIssuerHasSignedLaunchConfig,
  resolveLtiLaunch,
} from "../lti/launch-verification";
import { createLtiSessionHandoffToken } from "../lti/session-handoff";
import {
  createLtiIssuanceActionToken,
  verifyLtiIssuanceActionToken,
  type LtiIssuanceActionPayload,
} from "../lti/issuance-action-token";
import {
  type LtiNrpsRoster,
  type LtiNrpsMember,
  ltiNrpsRosterFromCoreMembers,
  parseLtiNrpsNamesRoleServiceClaim,
} from "../lti/nrps";
import {
  ltiDeepLinkSelectionPage,
  ltiLaunchResultPage,
  ltiRosterIssuanceResultPage,
  ltiPostMessageStorageRedirectPage,
  type LtiBulkIssuanceView,
  type LtiCourseBadgeSummaryView,
  type LtiRosterIssuanceResultEntry,
  type LtiDeepLinkSelectionPageInput,
} from "../lti/pages";
import { asJsonObject, asNonEmptyString } from "../utils/value-parsers";

interface RegisterLtiRoutesInput {
  app: Hono<AppEnv>;
  resolveLtiIssuerRegistry: (context: AppContext) => Promise<LtiIssuerRegistry>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  upsertTenantMembershipRole: (
    db: SqlDatabase,
    input: {
      tenantId: string;
      userId: string;
      role: TenantMembershipRole;
    },
  ) => Promise<{
    membership: {
      role: TenantMembershipRole;
    };
  }>;
  sha256Hex: (value: string) => Promise<string>;
  createLtiSession: (
    context: AppContext,
    input: LtiSessionInput,
  ) => Promise<LtiAuthenticatedPrincipal>;
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

const LTI_DEEP_LINKING_SELECT_PATH = "/v1/lti/deep-linking/select";
const LTI_RESOURCE_LINK_ISSUE_PATH = "/v1/lti/resource-link/issue";
const LTI_SESSION_HANDOFF_TTL_SECONDS = 10 * 60;

interface LtiRosterIssuedBadgeState {
  assertionId: string;
  issuedAt: string;
  lifecycleState: AssertionLifecycleState | null;
}

type LtiIssuanceIdempotencyKeyContext = Pick<
  LtiIssuanceActionPayload,
  "issuer" | "clientId" | "deploymentId" | "contextId" | "resourceLinkId" | "badgeTemplateId"
>;

type LtiRosterIssuanceLookupContext = LtiIssuanceIdempotencyKeyContext &
  Pick<LtiIssuanceActionPayload, "tenantId">;

interface LtiIssuanceIdempotencyKeyPrefix {
  value: string;
}

const ltiPostMessageStorageRedirectInput = (input: {
  authorizationRedirectUrl: string;
  storageTarget: string | undefined;
}): {
  authorizationRedirectUrl: string;
  platformOrigin: string;
  storageTarget: string;
  state: string;
  nonce: string;
} | null => {
  if (input.storageTarget === undefined || input.storageTarget.trim().length === 0) {
    return null;
  }

  const redirectUrl = new URL(input.authorizationRedirectUrl);
  const state = redirectUrl.searchParams.get("state");
  const nonce = redirectUrl.searchParams.get("nonce");

  if (state === null || nonce === null) {
    return null;
  }

  return {
    authorizationRedirectUrl: redirectUrl.toString(),
    platformOrigin: redirectUrl.origin,
    storageTarget: input.storageTarget,
    state,
    nonce,
  };
};

const ltiBulkIssuanceViewFromRoster = (input: {
  roster: LtiNrpsRoster;
  message: string;
  badgeTemplateId: string | null;
  courseContextTitle: string | null;
  courseContextId: string | null;
  contextMembershipsUrl: string;
  issuedBadgeStatesByUserId: ReadonlyMap<string, LtiRosterIssuedBadgeState>;
}): LtiBulkIssuanceView => {
  const learnerMembers = input.roster.learnerMembers.map((member) => {
    const issuedState = input.issuedBadgeStatesByUserId.get(member.userId) ?? null;

    return {
      userId: member.userId,
      sourcedId: member.sourcedId,
      displayName: member.displayName,
      email: member.email,
      roleSummary: member.roleSummary,
      status: member.status,
      issuedAssertionId: issuedState?.assertionId ?? null,
      issuedAt: issuedState?.issuedAt ?? null,
      issuanceLifecycleState: issuedState?.lifecycleState ?? null,
    };
  });

  return {
    status: "ready",
    message: input.message,
    badgeTemplateId: input.badgeTemplateId,
    courseContextTitle: input.courseContextTitle,
    courseContextId: input.courseContextId ?? input.roster.contextId,
    contextMembershipsUrl: input.contextMembershipsUrl,
    learnerCount: learnerMembers.length,
    totalCount: input.roster.members.length,
    issuanceActionPath: null,
    issuanceActionToken: null,
    members: learnerMembers,
  };
};

const ltiEmptyBulkIssuanceView = (input: {
  status: "unavailable" | "error";
  message: string;
  badgeTemplateId: string | null;
  courseContextTitle: string | null;
  courseContextId: string | null;
  contextMembershipsUrl: string | null;
}): LtiBulkIssuanceView => {
  return {
    status: input.status,
    message: input.message,
    badgeTemplateId: input.badgeTemplateId,
    courseContextTitle: input.courseContextTitle,
    courseContextId: input.courseContextId,
    contextMembershipsUrl: input.contextMembershipsUrl,
    learnerCount: 0,
    totalCount: 0,
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

const ltiEmptyCourseBadgeSummaryView = (input: {
  status: "unavailable" | "error";
  message: string;
  courseContextTitle: string | null;
}): LtiCourseBadgeSummaryView => {
  return {
    status: input.status,
    message: input.message,
    courseContextTitle: input.courseContextTitle,
    learnerCount: 0,
    badgeCount: 0,
    issuedCount: 0,
    rows: [],
  };
};

const courseBadgeSummaryStatus = (
  lifecycleState: AssertionLifecycleState | null,
): LtiCourseBadgeSummaryView["rows"][number]["status"] => {
  if (lifecycleState === null || lifecycleState === "active") {
    return "issued";
  }

  return lifecycleState;
};

const courseBadgeSummaryStatusLabel = (
  status: LtiCourseBadgeSummaryView["rows"][number]["status"],
): string => {
  if (status === "not_issued") {
    return "Not issued";
  }

  if (status === "issued") {
    return "Issued";
  }

  return status.charAt(0).toUpperCase() + status.slice(1);
};

const ltiLearnerIssuedBadgesPath = (input: {
  tenantId: string;
  email: string;
  badgeTemplateId?: string;
  assertionId?: string;
}): string => {
  const query = new URLSearchParams({ recipientQuery: input.email });

  if (input.badgeTemplateId !== undefined) {
    query.set("badgeTemplateId", input.badgeTemplateId);
  }

  if (input.assertionId !== undefined) {
    query.set("lifecycle", input.assertionId);
    query.set("lifecycleMode", "audit");
  }

  query.set("source", "lti-course-summary");

  return `/tenants/${encodeURIComponent(input.tenantId)}/admin/operations/issued-badges?${query.toString()}`;
};

const ltiBadgeCourseSetupPath = (input: {
  tenantId: string;
  badgeTemplateId: string;
  contextId: string;
  resourceLinkId: string;
  courseContextTitle: string | null;
}): string => {
  const query = new URLSearchParams({
    ltiContextId: input.contextId,
    ltiResourceLinkId: input.resourceLinkId,
    source: "lti-course-summary",
  });

  if (input.courseContextTitle !== null) {
    query.set("ltiCourse", input.courseContextTitle);
  }

  return `/tenants/${encodeURIComponent(input.tenantId)}/admin/rules/templates/${encodeURIComponent(
    input.badgeTemplateId,
  )}?${query.toString()}`;
};

const ltiBadgeRecipientKey = (badgeTemplateId: string, recipientEmail: string): string => {
  return `${badgeTemplateId}:${normalizeEmail(recipientEmail)}`;
};

const newestAssertion = (
  current: AssertionRecord | undefined,
  candidate: AssertionRecord,
): AssertionRecord => {
  if (current === undefined) {
    return candidate;
  }

  const currentIssuedAt = Date.parse(current.issuedAt);
  const candidateIssuedAt = Date.parse(candidate.issuedAt);

  if (Number.isFinite(candidateIssuedAt) && Number.isFinite(currentIssuedAt)) {
    if (candidateIssuedAt !== currentIssuedAt) {
      return candidateIssuedAt > currentIssuedAt ? candidate : current;
    }
  } else if (Number.isFinite(candidateIssuedAt)) {
    return candidate;
  } else if (Number.isFinite(currentIssuedAt)) {
    return current;
  } else if (candidate.issuedAt !== current.issuedAt) {
    return candidate.issuedAt > current.issuedAt ? candidate : current;
  }

  return candidate.id > current.id ? candidate : current;
};

const ltiCanOpenAdminDetailLinks = (membershipRole: TenantMembershipRole): boolean => {
  return membershipRole === "owner" || membershipRole === "admin";
};

interface LtiCourseBadgeTemplatePlacementGroup {
  badgeTemplateId: string;
  template: BadgeTemplateRecord;
  placements: readonly LtiResourceLinkPlacementRecord[];
}

const ltiCoursePlacementGroupsByBadgeTemplate = (input: {
  placements: readonly LtiResourceLinkPlacementRecord[];
  templatesById: ReadonlyMap<string, BadgeTemplateRecord>;
}): LtiCourseBadgeTemplatePlacementGroup[] => {
  const placementsByBadgeTemplateId = new Map<string, LtiResourceLinkPlacementRecord[]>();

  for (const placement of input.placements) {
    if (!input.templatesById.has(placement.badgeTemplateId)) {
      continue;
    }

    const placementsForTemplate = placementsByBadgeTemplateId.get(placement.badgeTemplateId) ?? [];
    placementsForTemplate.push(placement);
    placementsByBadgeTemplateId.set(placement.badgeTemplateId, placementsForTemplate);
  }

  const groups: LtiCourseBadgeTemplatePlacementGroup[] = [];

  for (const [badgeTemplateId, placementsForTemplate] of placementsByBadgeTemplateId.entries()) {
    const template = input.templatesById.get(badgeTemplateId);

    if (template === undefined) {
      continue;
    }

    groups.push({
      badgeTemplateId,
      template,
      placements: placementsForTemplate,
    });
  }

  return groups;
};

const ltiCourseBadgeSummaryViewFromRoster = async (input: {
  db: SqlDatabase;
  tenantId: string;
  contextId: string;
  courseContextTitle: string | null;
  roster: LtiNrpsRoster;
  placements: readonly LtiResourceLinkPlacementRecord[];
  badgeTemplates: readonly BadgeTemplateRecord[];
  canOpenAdminLinks: boolean;
}): Promise<LtiCourseBadgeSummaryView> => {
  const learnerMembers = input.roster.learnerMembers;
  const templatesById = new Map(input.badgeTemplates.map((template) => [template.id, template]));
  const placementGroups = ltiCoursePlacementGroupsByBadgeTemplate({
    placements: input.placements,
    templatesById,
  });
  const candidates = placementGroups.flatMap((placementGroup) => {
    return learnerMembers.map((member) => ({
      member,
      placementGroup,
      template: placementGroup.template,
    }));
  });
  const matchingRecipientAssertions = await listAssertionsByBadgeTemplatesAndRecipientEmails(
    input.db,
    {
      tenantId: input.tenantId,
      badgeTemplateIds: placementGroups.map((placementGroup) => placementGroup.badgeTemplateId),
      recipientEmails: learnerMembers
        .map((member) => member.email)
        .filter((email): email is string => email !== null),
    },
  );
  const matchingRecipientAssertionsByBadgeRecipient = new Map<string, AssertionRecord>();

  for (const assertion of matchingRecipientAssertions) {
    const key = ltiBadgeRecipientKey(assertion.badgeTemplateId, assertion.recipientIdentity);

    matchingRecipientAssertionsByBadgeRecipient.set(
      key,
      newestAssertion(matchingRecipientAssertionsByBadgeRecipient.get(key), assertion),
    );
  }
  const lifecycleStates = await listAssertionLifecycleStatesByAssertionIds(input.db, {
    tenantId: input.tenantId,
    assertionIds: Array.from(
      new Set(
        Array.from(matchingRecipientAssertionsByBadgeRecipient.values()).map(
          (assertion) => assertion.id,
        ),
      ),
    ),
  });
  const lifecycleStatesByAssertionId = new Map(
    lifecycleStates.map((lifecycle) => [lifecycle.assertionId, lifecycle]),
  );
  const rows: Array<LtiCourseBadgeSummaryView["rows"][number]> = [];

  for (const candidate of candidates) {
    const matchingRecipientAssertion =
      candidate.member.email === null
        ? null
        : (matchingRecipientAssertionsByBadgeRecipient.get(
            ltiBadgeRecipientKey(candidate.template.id, candidate.member.email),
          ) ?? null);
    const assertion = matchingRecipientAssertion;
    const lifecycle = assertion === null ? null : lifecycleStatesByAssertionId.get(assertion.id);
    const status =
      assertion === null ? "not_issued" : courseBadgeSummaryStatus(lifecycle?.state ?? null);
    const learnerName =
      candidate.member.displayName ?? candidate.member.email ?? candidate.member.userId;
    const assertionId = assertion?.id;
    const linkedPlacement = candidate.placementGroup.placements[0] ?? null;
    const placementContextId = linkedPlacement?.contextId ?? input.contextId;

    rows.push({
      learnerUserId: candidate.member.userId,
      learnerName,
      learnerEmail: candidate.member.email,
      learnerDetailPath:
        !input.canOpenAdminLinks || candidate.member.email === null
          ? null
          : ltiLearnerIssuedBadgesPath({
              tenantId: input.tenantId,
              email: candidate.member.email,
              badgeTemplateId: candidate.template.id,
              ...(assertionId === undefined ? {} : { assertionId }),
            }),
      badgeTemplateId: candidate.template.id,
      badgeTitle: candidate.template.title,
      badgeDetailPath: input.canOpenAdminLinks
        ? ltiBadgeCourseSetupPath({
            tenantId: input.tenantId,
            badgeTemplateId: candidate.template.id,
            contextId: placementContextId,
            resourceLinkId: linkedPlacement?.resourceLinkId ?? "",
            courseContextTitle: input.courseContextTitle,
          })
        : null,
      status,
      statusLabel: courseBadgeSummaryStatusLabel(status),
      statusDetail:
        assertion === null
          ? "No issued badge record found for this learner and badge."
          : "Issued for this learner and badge.",
      assertionId: assertionId ?? null,
      issuedAt: assertion?.issuedAt ?? null,
    });
  }

  return {
    status: "ready",
    message:
      placementGroups.length === 0
        ? "No badges have been placed in this LMS course yet."
        : `Showing badge progress for ${String(placementGroups.length)} badge${
            placementGroups.length === 1 ? "" : "s"
          } in this course.`,
    courseContextTitle: input.courseContextTitle,
    learnerCount: learnerMembers.length,
    badgeCount: placementGroups.length,
    issuedCount: rows.filter((row) => row.status === "issued").length,
    rows,
  };
};

const findLtiIssuerRegistryEntry = (
  registry: LtiIssuerRegistry,
  issuer: string,
  clientId: string,
): { issuer: string; entry: LtiIssuerRegistryEntry } | null => {
  const normalizedIssuer = normalizeLtiIssuer(issuer);

  for (const [candidateIssuer, entry] of Object.entries(registry)) {
    if (normalizeLtiIssuer(candidateIssuer) === normalizedIssuer && entry.clientId === clientId) {
      return {
        issuer: normalizeLtiIssuer(candidateIssuer),
        entry,
      };
    }
  }

  return null;
};

const badgeTemplateDeepLinkContentItem = (input: {
  title: string;
  description: string | null;
  launchUrl: string;
  badgeTemplateId: string;
}): DeepLinkingContentItem => {
  return {
    type: "ltiResourceLink",
    title: input.title,
    text: input.description ?? `CredTrail badge template ${input.title} (${input.badgeTemplateId})`,
    url: input.launchUrl,
    custom: {
      badgeTemplateId: input.badgeTemplateId,
    },
  };
};

const ltiDeepLinkSelectionInput = (input: {
  requestUrl: string;
  tenantId: string;
  userId: string;
  membershipRole: TenantMembershipRole;
  issuer: string;
  deploymentId: string;
  deepLinkReturnUrl: string;
  targetLinkUri: string;
  ltiLaunchSession: LTISession;
  badgeTemplates: readonly {
    id: string;
    title: string;
    description: string | null;
  }[];
}): LtiDeepLinkSelectionPageInput => {
  const options = input.badgeTemplates.map((badgeTemplate) => {
    const launchUrl = new URL(input.targetLinkUri);
    launchUrl.searchParams.set("badgeTemplateId", badgeTemplate.id);

    return {
      badgeTemplateId: badgeTemplate.id,
      title: badgeTemplate.title,
      description: badgeTemplate.description,
      launchUrl: launchUrl.toString(),
    };
  });
  const common = {
    tenantId: input.tenantId,
    userId: input.userId,
    membershipRole: input.membershipRole,
    issuer: input.issuer,
    deploymentId: input.deploymentId,
    deepLinkReturnUrl: input.deepLinkReturnUrl,
    targetLinkUri: input.targetLinkUri,
  };

  return {
    ...common,
    mode: "signed",
    signedSelectionActionUrl: new URL(LTI_DEEP_LINKING_SELECT_PATH, input.requestUrl).toString(),
    ltiSessionId: input.ltiLaunchSession.id,
    options,
  };
};

const selectedLearnerUserIdsFromForm = (form: FormData): string[] => {
  const selected = form
    .getAll("learner_user_id")
    .map((entry) => asNonEmptyString(entry))
    .filter((entry): entry is string => entry !== null);

  return Array.from(new Set(selected));
};

const ltiSessionMatchesIssuanceAction = (
  ltiSession: LTISession,
  action: LtiIssuanceActionPayload,
): boolean => {
  return (
    ltiSession.id === action.ltiSessionId &&
    ltiSession.platform.issuer === action.issuer &&
    ltiSession.platform.clientId === action.clientId &&
    ltiSession.platform.deploymentId === action.deploymentId &&
    ltiSession.context.id === action.contextId &&
    ltiSession.resourceLink?.id === action.resourceLinkId
  );
};

const ltiIssuanceIdempotencyKeyPrefix = (
  action: LtiIssuanceIdempotencyKeyContext,
): LtiIssuanceIdempotencyKeyPrefix => {
  return {
    value: [
      action.issuer,
      action.clientId,
      action.deploymentId,
      action.contextId,
      action.resourceLinkId,
      action.badgeTemplateId,
    ].join("|"),
  };
};

const ltiIssuanceIdempotencyKeyFromPrefix = async (
  sha256Hex: (value: string) => Promise<string>,
  prefix: LtiIssuanceIdempotencyKeyPrefix,
  learnerUserId: string,
): Promise<string> => {
  const digest = await sha256Hex(`${prefix.value}|${learnerUserId}`);

  return `lti:${digest}`;
};

const ltiRosterIssuedBadgeStatesByUserId = async (input: {
  db: SqlDatabase;
  sha256Hex: (value: string) => Promise<string>;
  action: LtiRosterIssuanceLookupContext;
  learnerMembers: readonly LtiNrpsMember[];
}): Promise<Map<string, LtiRosterIssuedBadgeState>> => {
  const statesByUserId = new Map<string, LtiRosterIssuedBadgeState>();
  const idempotencyKeyPrefix = ltiIssuanceIdempotencyKeyPrefix(input.action);
  const keyedMembers = await Promise.all(
    input.learnerMembers.map(async (member) => {
      const idempotencyKey = await ltiIssuanceIdempotencyKeyFromPrefix(
        input.sha256Hex,
        idempotencyKeyPrefix,
        member.userId,
      );

      return {
        member,
        idempotencyKey,
      };
    }),
  );
  const assertions = await listAssertionsByIdempotencyKeys(input.db, {
    tenantId: input.action.tenantId,
    idempotencyKeys: keyedMembers.map((keyedMember) => keyedMember.idempotencyKey),
  });
  const assertionsByIdempotencyKey = new Map(
    assertions.map((assertion) => [assertion.idempotencyKey, assertion]),
  );
  const lifecycleStates = await listAssertionLifecycleStatesByAssertionIds(input.db, {
    tenantId: input.action.tenantId,
    assertionIds: assertions.map((assertion) => assertion.id),
  });
  const lifecycleStatesByAssertionId = new Map(
    lifecycleStates.map((lifecycle) => [lifecycle.assertionId, lifecycle]),
  );

  for (const keyedMember of keyedMembers) {
    const assertion = assertionsByIdempotencyKey.get(keyedMember.idempotencyKey) ?? null;

    if (assertion === null) {
      continue;
    }

    const lifecycle = lifecycleStatesByAssertionId.get(assertion.id);

    statesByUserId.set(keyedMember.member.userId, {
      assertionId: assertion.id,
      issuedAt: assertion.issuedAt,
      lifecycleState: lifecycle?.state ?? null,
    });
  }

  return statesByUserId;
};

const skippedLtiIssuanceResult = (
  member: Pick<LtiNrpsMember, "userId" | "displayName" | "email">,
  message: string,
): LtiRosterIssuanceResultEntry => {
  return {
    userId: member.userId,
    displayName: member.displayName,
    email: member.email,
    status: "skipped",
    message,
    assertionId: null,
  };
};

export const registerLtiRoutes = (input: RegisterLtiRoutesInput): void => {
  const {
    app,
    resolveLtiIssuerRegistry,
    resolveDatabase,
    upsertTenantMembershipRole: upsertTenantMembershipRoleWithInput,
    sha256Hex,
    createLtiSession,
    issueBadgeForTenant,
  } = input;

  const ltiOidcLoginHandler = async (c: AppContext): Promise<Response> => {
    let registry: LtiIssuerRegistry;

    try {
      registry = await resolveLtiIssuerRegistry(c);
    } catch {
      return c.json(
        {
          error: "LTI issuer registry configuration is invalid",
        },
        500,
      );
    }

    let loginRequest;

    try {
      loginRequest = parseLtiOidcLoginInitiationRequest(await ltiLoginInputFromRequest(c));
    } catch {
      return c.json(
        {
          error: "Invalid LTI OIDC login initiation request",
        },
        400,
      );
    }

    const issuerEntry = registry[normalizeLtiIssuer(loginRequest.iss)];

    if (issuerEntry === undefined) {
      return c.json(
        {
          error: "Unknown LTI issuer",
        },
        400,
      );
    }

    const clientId = loginRequest.client_id ?? issuerEntry.clientId;

    if (loginRequest.client_id !== undefined && loginRequest.client_id !== issuerEntry.clientId) {
      return c.json(
        {
          error: "client_id does not match configured issuer registration",
        },
        400,
      );
    }

    if (!ltiIssuerHasSignedLaunchConfig(issuerEntry)) {
      return c.json(
        {
          error:
            "LTI issuer requires platform JWKS and token endpoint configuration for signed launches",
        },
        501,
      );
    }

    const db = resolveDatabase(c.env);
    const deploymentId = loginRequest.lti_deployment_id ?? "default";
    await upsertLtiDeployment(db, {
      issuer: loginRequest.iss,
      clientId,
      deploymentId,
    });
    const ltiTool = await createCredTrailLtiTool({
      db,
      env: c.env,
      defaultTenantId: issuerEntry.tenantId,
    });
    const authRedirectUrl = await ltiTool.handleLogin({
      iss: normalizeLtiIssuer(loginRequest.iss),
      client_id: clientId,
      launchUrl: new URL(LTI_LAUNCH_PATH, c.req.url),
      login_hint: loginRequest.login_hint,
      target_link_uri: loginRequest.target_link_uri,
      lti_deployment_id: deploymentId,
      ...(loginRequest.lti_message_hint === undefined
        ? {}
        : { lti_message_hint: loginRequest.lti_message_hint }),
    });
    const postMessageStorageInput = ltiPostMessageStorageRedirectInput({
      authorizationRedirectUrl: authRedirectUrl,
      storageTarget: loginRequest.lti_storage_target,
    });

    if (postMessageStorageInput !== null) {
      c.header("Cache-Control", "no-store");
      return renderAppPage(c, ltiPostMessageStorageRedirectPage(postMessageStorageInput));
    }

    return c.redirect(authRedirectUrl, 302);
  };

  app.get(LTI_OIDC_LOGIN_PATH, ltiOidcLoginHandler);
  app.post(LTI_OIDC_LOGIN_PATH, ltiOidcLoginHandler);

  app.get("/v1/lti/jwks", async (c): Promise<Response> => {
    const ltiTool = await createCredTrailLtiTool({
      db: resolveDatabase(c.env),
      env: c.env,
    });
    return c.json(await ltiTool.getJWKS());
  });

  app.post(LTI_DEEP_LINKING_SELECT_PATH, async (c): Promise<Response> => {
    const form = await c.req.formData();
    const ltiSessionId = asNonEmptyString(form.get("lti_session_id"));
    const badgeTemplateId = asNonEmptyString(form.get("badge_template_id"));

    if (ltiSessionId === null || badgeTemplateId === null) {
      return c.json(
        {
          error: "lti_session_id and badge_template_id are required",
        },
        400,
      );
    }

    const db = resolveDatabase(c.env);
    const ltiTool = await createCredTrailLtiTool({
      db,
      env: c.env,
    });
    const ltiSession = await ltiTool.getSession(ltiSessionId);

    if (ltiSession === undefined || ltiSession.services?.deepLinking === undefined) {
      return c.json(
        {
          error: "LTI Deep Linking session was not found or is no longer active",
        },
        404,
      );
    }

    const issuerRegistry = await resolveLtiIssuerRegistry(c);
    const issuerMatch = findLtiIssuerRegistryEntry(
      issuerRegistry,
      ltiSession.platform.issuer,
      ltiSession.platform.clientId,
    );

    if (issuerMatch === null) {
      return c.json(
        {
          error: "LTI issuer registration was not found for this Deep Linking session",
        },
        404,
      );
    }

    const badgeTemplates = await listBadgeTemplates(db, {
      tenantId: issuerMatch.entry.tenantId,
      includeArchived: false,
    });
    const badgeTemplate = badgeTemplates.find((template) => template.id === badgeTemplateId);

    if (badgeTemplate === undefined) {
      return c.json(
        {
          error: "Badge template is not available for this LTI tenant",
        },
        404,
      );
    }

    const launchUrl = new URL(ltiSession.launch.target);
    launchUrl.searchParams.set("badgeTemplateId", badgeTemplate.id);
    const responseHtml = await ltiTool.createDeepLinkingResponse(ltiSession, [
      badgeTemplateDeepLinkContentItem({
        badgeTemplateId: badgeTemplate.id,
        title: badgeTemplate.title,
        description: badgeTemplate.description,
        launchUrl: launchUrl.toString(),
      }),
    ]);

    c.header("Cache-Control", "no-store");
    return c.body(responseHtml, 200, {
      "Content-Type": "text/html; charset=UTF-8",
    });
  });

  app.post(LTI_RESOURCE_LINK_ISSUE_PATH, async (c): Promise<Response> => {
    const form = await c.req.formData();
    const actionToken = asNonEmptyString(form.get("issuance_action_token"));
    const selectedLearnerUserIds = selectedLearnerUserIdsFromForm(form);

    if (actionToken === null) {
      return c.json(
        {
          error: "issuance_action_token is required",
        },
        400,
      );
    }

    const issuanceAction = await verifyLtiIssuanceActionToken(c.env, actionToken);

    if (issuanceAction === null) {
      return c.json(
        {
          error: "LTI issuance action token is invalid or expired",
        },
        403,
      );
    }

    const db = resolveDatabase(c.env);
    const ltiTool = await createCredTrailLtiTool({
      db,
      env: c.env,
    });
    const ltiSession = await ltiTool.getSession(issuanceAction.ltiSessionId);

    if (ltiSession === undefined) {
      return c.json(
        {
          error: "LTI launch session was not found or is no longer active",
        },
        404,
      );
    }

    if (!ltiSessionMatchesIssuanceAction(ltiSession, issuanceAction)) {
      return c.json(
        {
          error: "LTI launch session does not match issuance action",
        },
        403,
      );
    }

    if (!ltiSession.isInstructor) {
      return c.json(
        {
          error: "LTI roster badge issuance requires an instructor launch",
        },
        403,
      );
    }

    const badgeTemplate = await findBadgeTemplateById(
      db,
      issuanceAction.tenantId,
      issuanceAction.badgeTemplateId,
    );

    if (badgeTemplate === null || badgeTemplate.isArchived) {
      return c.json(
        {
          error: "LTI resource-link badge template is not available for this tenant",
        },
        404,
      );
    }

    let roster: LtiNrpsRoster;

    try {
      const members = await ltiTool.getMembers(ltiSession);
      roster = ltiNrpsRosterFromCoreMembers({
        contextId: ltiSession.context.id,
        members,
      });
    } catch {
      return c.json(
        {
          error:
            "CredTrail could not load the learner roster from the LMS. Check the LMS connection settings.",
        },
        502,
      );
    }

    const learnersByUserId = new Map(
      roster.learnerMembers.map((member): [string, LtiNrpsMember] => [member.userId, member]),
    );
    const results: LtiRosterIssuanceResultEntry[] = [];
    const idempotencyKeyPrefix = ltiIssuanceIdempotencyKeyPrefix(issuanceAction);

    for (const learnerUserId of selectedLearnerUserIds) {
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

      const request: DirectIssueBadgeRequest = {
        badgeTemplateId: issuanceAction.badgeTemplateId,
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
          sha256Hex,
          idempotencyKeyPrefix,
          member.userId,
        ),
      };
      const issueOptions =
        member.displayName === null ? {} : { recipientDisplayName: member.displayName };

      try {
        const issuance = await issueBadgeForTenant(
          c,
          issuanceAction.tenantId,
          request,
          issuanceAction.issuedByUserId,
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

    c.header("Cache-Control", "no-store");
    return renderAppPage(
      c,
      ltiRosterIssuanceResultPage({
        tenantId: issuanceAction.tenantId,
        badgeTemplateId: issuanceAction.badgeTemplateId,
        courseContextTitle: ltiSession.context.title.length === 0 ? null : ltiSession.context.title,
        selectedCount: selectedLearnerUserIds.length,
        results,
      }),
    );
  });

  app.post(LTI_LAUNCH_PATH, async (c): Promise<Response> => {
    const formInput = await ltiLaunchFormInputFromRequest(c);

    if (formInput.idToken === null || formInput.idToken.trim().length === 0) {
      return c.json(
        {
          error: "id_token is required",
        },
        400,
      );
    }

    if (formInput.state === null || formInput.state.trim().length === 0) {
      return c.json(
        {
          error: "state is required",
        },
        400,
      );
    }

    let registry: LtiIssuerRegistry;

    try {
      registry = await resolveLtiIssuerRegistry(c);
    } catch {
      return c.json(
        {
          error: "LTI issuer registry configuration is invalid",
        },
        500,
      );
    }

    const nowIso = new Date().toISOString();
    const db = resolveDatabase(c.env);
    const resolvedLaunch = await resolveLtiLaunch({
      idToken: formInput.idToken,
      state: formInput.state,
      registry,
      db,
      env: c.env,
      nowIso,
    }).catch(async (error: unknown) => {
      if (!(error instanceof LtiLaunchVerificationError)) {
        throw error;
      }

      return c.json(
        {
          error: error.message,
          ...(error.detail === undefined ? {} : { detail: error.detail }),
        },
        error.status,
      );
    });

    if (resolvedLaunch instanceof Response) {
      return resolvedLaunch;
    }

    const { issuerEntry, launchClaims, ltiLaunchSession, ltiTool } = resolvedLaunch;
    const launchMessage = (() => {
      try {
        return resolveLtiLaunchMessage({
          launchClaims,
          launchState: resolvedLaunch.launchState,
        });
      } catch (error) {
        if (error instanceof LtiLaunchMessageError) {
          return c.json({ error: error.message }, error.status);
        }
        throw error;
      }
    })();

    if (launchMessage instanceof Response) {
      return launchMessage;
    }
    const tenantId = issuerEntry.tenantId;

    if (launchMessage.kind === "resource-link" && launchMessage.badgeTemplateId !== null) {
      const launchedBadgeTemplate = await findBadgeTemplateById(
        db,
        tenantId,
        launchMessage.badgeTemplateId,
      );

      if (launchedBadgeTemplate === null || launchedBadgeTemplate.isArchived) {
        return c.json(
          {
            error: "LTI resource-link badge template is not available for this tenant",
          },
          400,
        );
      }
    }

    let linkedAccount;

    try {
      linkedAccount = await linkLtiLaunchAccount({
        db,
        tenantId,
        launchClaims,
        roleKind: launchMessage.roleKind,
        sha256Hex,
        upsertTenantMembershipRole: upsertTenantMembershipRoleWithInput,
      });
    } catch {
      return c.json(
        {
          error: "Unable to link LTI launch to local account",
        },
        500,
      );
    }

    const createdSession = await createLtiSession(c, {
      tenantId,
      userId: linkedAccount.userId,
    });

    if (launchMessage.kind === "resource-link" && launchMessage.badgeTemplateId !== null) {
      try {
        await upsertLtiResourceLinkPlacement(db, {
          tenantId,
          issuer: launchClaims.iss,
          clientId: issuerEntry.clientId,
          deploymentId: launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
          contextId: launchMessage.resourceContextId,
          resourceLinkId: launchMessage.resourceLinkId,
          badgeTemplateId: launchMessage.badgeTemplateId,
          createdByUserId: linkedAccount.userId,
        });
      } catch {
        // Resource-link placement is best-effort; the launch session can still proceed.
      }
    }

    const dashboardPath = await (async (): Promise<string> => {
      const basePath = ltiLearnerDashboardPath(tenantId);

      if (createdSession.browserSessionToken === undefined) {
        return basePath;
      }

      const dashboardUrl = new URL(basePath, c.req.url);
      dashboardUrl.searchParams.set(
        "lti_session_handoff",
        await createLtiSessionHandoffToken(c.env, {
          tenantId,
          sessionToken: createdSession.browserSessionToken,
          ttlSeconds: LTI_SESSION_HANDOFF_TTL_SECONDS,
        }),
      );
      return `${dashboardUrl.pathname}${dashboardUrl.search}`;
    })();
    c.header("Cache-Control", "no-store");
    let bulkIssuanceView: LtiBulkIssuanceView | null = null;
    let courseBadgeSummaryView: LtiCourseBadgeSummaryView | null = null;

    if (launchMessage.kind === "resource-link" && launchMessage.roleKind === "instructor") {
      const nrpsClaim = parseLtiNrpsNamesRoleServiceClaim(launchClaims);
      const contextClaim = asJsonObject(launchClaims[LTI_CLAIM_CONTEXT]);
      const courseContextTitle =
        asNonEmptyString(contextClaim?.title) ?? asNonEmptyString(contextClaim?.label) ?? null;
      const courseContextId = asNonEmptyString(contextClaim?.id);

      if (launchMessage.badgeTemplateId !== null && nrpsClaim === null) {
        bulkIssuanceView = ltiEmptyBulkIssuanceView({
          status: "unavailable",
          message:
            "This LMS launch did not include a learner roster, so CredTrail cannot issue badges from this tool yet.",
          badgeTemplateId: launchMessage.badgeTemplateId,
          courseContextTitle,
          courseContextId,
          contextMembershipsUrl: null,
        });
      } else if (launchMessage.badgeTemplateId !== null && nrpsClaim !== null) {
        try {
          const members = await ltiTool.getMembers(ltiLaunchSession);
          const roster = ltiNrpsRosterFromCoreMembers({
            contextId: courseContextId ?? ltiLaunchSession.context.id ?? null,
            members,
          });
          const issuanceActionContextId = courseContextId ?? ltiLaunchSession.context.id;
          const issuanceActionInput =
            launchMessage.badgeTemplateId !== null && issuanceActionContextId.length > 0
              ? {
                  tenantId,
                  ltiSessionId: ltiLaunchSession.id,
                  issuer: launchClaims.iss,
                  clientId: issuerEntry.clientId,
                  deploymentId: launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
                  contextId: issuanceActionContextId,
                  resourceLinkId: launchMessage.resourceLinkId,
                  badgeTemplateId: launchMessage.badgeTemplateId,
                  issuedByUserId: linkedAccount.userId,
                }
              : null;
          const issuedBadgeStatesByUserId =
            issuanceActionInput === null
              ? new Map<string, LtiRosterIssuedBadgeState>()
              : await ltiRosterIssuedBadgeStatesByUserId({
                  db,
                  sha256Hex,
                  action: issuanceActionInput,
                  learnerMembers: roster.learnerMembers,
                });
          bulkIssuanceView = ltiBulkIssuanceViewFromRoster({
            roster,
            message: `Loaded ${String(roster.learnerMembers.length)} learner${
              roster.learnerMembers.length === 1 ? "" : "s"
            } from LMS roster.`,
            badgeTemplateId: launchMessage.badgeTemplateId,
            courseContextTitle,
            courseContextId,
            contextMembershipsUrl: nrpsClaim.contextMembershipsUrl,
            issuedBadgeStatesByUserId,
          });
          if (issuanceActionInput !== null) {
            bulkIssuanceView = ltiBulkIssuanceViewWithAction(bulkIssuanceView, {
              issuanceActionToken: await createLtiIssuanceActionToken(c.env, {
                ...issuanceActionInput,
                ttlSeconds: LTI_SESSION_HANDOFF_TTL_SECONDS,
              }),
            });
          }
        } catch {
          bulkIssuanceView = ltiEmptyBulkIssuanceView({
            status: "error",
            message:
              "CredTrail could not load the learner roster from the LMS. Check the LMS connection settings.",
            badgeTemplateId: launchMessage.badgeTemplateId,
            courseContextTitle,
            courseContextId,
            contextMembershipsUrl: nrpsClaim.contextMembershipsUrl,
          });
        }
      } else if (nrpsClaim === null) {
        courseBadgeSummaryView = ltiEmptyCourseBadgeSummaryView({
          status: "unavailable",
          message:
            "CredTrail could not load the learner roster from the LMS. Ask an administrator to check the LMS connection settings.",
          courseContextTitle,
        });
      } else {
        const summaryContextId = courseContextId ?? ltiLaunchSession.context.id;

        if (summaryContextId.length === 0) {
          courseBadgeSummaryView = ltiEmptyCourseBadgeSummaryView({
            status: "unavailable",
            message:
              "CredTrail could not identify this LMS course. Ask an administrator to check the LMS tool setup.",
            courseContextTitle,
          });
        } else {
          try {
            const members = await ltiTool.getMembers(ltiLaunchSession);
            const roster = ltiNrpsRosterFromCoreMembers({
              contextId: summaryContextId,
              members,
            });
            const placements = await listLtiResourceLinkPlacementsForContext(db, {
              tenantId,
              issuer: launchClaims.iss,
              clientId: issuerEntry.clientId,
              deploymentId: launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
              contextId: summaryContextId,
            });
            const badgeTemplates = await listBadgeTemplatesByIds(db, {
              tenantId,
              badgeTemplateIds: placements.map((placement) => placement.badgeTemplateId),
              includeArchived: false,
            });

            courseBadgeSummaryView = await ltiCourseBadgeSummaryViewFromRoster({
              db,
              tenantId,
              contextId: summaryContextId,
              courseContextTitle,
              roster,
              placements,
              badgeTemplates,
              canOpenAdminLinks: ltiCanOpenAdminDetailLinks(linkedAccount.membershipRole),
            });
          } catch {
            courseBadgeSummaryView = ltiEmptyCourseBadgeSummaryView({
              status: "error",
              message:
                "CredTrail could not load badge progress for this course. Ask an administrator to check the LMS connection settings.",
              courseContextTitle,
            });
          }
        }
      }
    }

    if (launchMessage.kind === "deep-linking") {
      const badgeTemplates = await listBadgeTemplates(db, {
        tenantId,
        includeArchived: false,
      });

      return renderAppPage(
        c,
        ltiDeepLinkSelectionPage(
          ltiDeepLinkSelectionInput({
            requestUrl: c.req.url,
            tenantId,
            userId: linkedAccount.userId,
            membershipRole: linkedAccount.membershipRole,
            issuer: launchClaims.iss,
            deploymentId: launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
            deepLinkReturnUrl: launchMessage.deepLinkingSettings.deepLinkReturnUrl,
            targetLinkUri: launchMessage.resolvedTargetLinkUri,
            ltiLaunchSession,
            badgeTemplates,
          }),
        ),
      );
    }

    return renderAppPage(
      c,
      ltiLaunchResultPage({
        roleKind: launchMessage.roleKind,
        tenantId,
        userId: linkedAccount.userId,
        membershipRole: linkedAccount.membershipRole,
        learnerProfileId: linkedAccount.learnerProfileId,
        issuer: launchClaims.iss,
        deploymentId: launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
        subjectId: launchClaims.sub,
        targetLinkUri: launchMessage.resolvedTargetLinkUri,
        messageType: launchMessage.messageType,
        launchDisplayName: ltiDisplayNameFromClaims(launchClaims) ?? null,
        dashboardPath,
        bulkIssuanceView,
        courseBadgeSummaryView,
      }),
    );
  });
};
