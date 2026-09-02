import {
  findActiveBadgeIssuanceRuleVersion,
  findActiveLtiLaunchSessionByOpaqueId,
  findBadgeIssuanceRuleById,
  findBadgeTemplateById,
  findTenantLmsConnectionByLtiRegistration,
  isCourseRelativeLtiAuthoredBadgeRule,
  observeVerifiedLtiCourseContext,
  resolveBadgeRulePlacementAvailabilityForContext,
} from "@credtrail/db";
import {
  formatLtiServiceError,
  parsePersistedLtiSession,
  resolveLtiServiceCapabilities,
} from "@longsightgroup/lti-tool";
import type { AppContext } from "../app/types";
import type { ResolveDatabase } from "../app/route-deps";
import { asNonEmptyString } from "../utils/value-parsers";
import { createCredTrailLtiTool } from "./credtrail-lti-tool";
import { badgeRuleDeepLinkContentItem } from "./deep-linking-helpers";
import { secureLtiDeepLinkingHtmlResponse } from "./deep-linking-response-security";
import { findLtiIssuerRegistryEntry, type LtiIssuerRegistry } from "./lti-issuer-registry";

/**
 * Dependencies required to handle the product Deep Linking selection POST.
 */
export interface HandleLtiDeepLinkingSelectInput {
  readonly c: AppContext;
  readonly resolveLtiIssuerRegistry: (context: AppContext) => Promise<LtiIssuerRegistry>;
  resolveDatabase: ResolveDatabase;
}

const hasExactSelectionFields = (form: FormData): boolean => {
  const keys = [...form.keys()];
  return (
    keys.every((key) => key === "lti_session_id" || key === "rule_id") &&
    form.getAll("lti_session_id").length === 1 &&
    form.getAll("rule_id").length === 1
  );
};

const courseCode = (label: string | undefined): string | null => {
  const normalized = label?.trim() ?? "";
  return normalized.length === 0 ? null : normalized;
};

const unavailableRuleResponse = (
  c: AppContext,
  status: 400 | 403 | 404,
  error: string,
  reason: string,
): Response => {
  return c.json({ error, reason }, status);
};

/**
 * Handles CredTrail's stable-rule Deep Linking selection POST.
 */
export const handleLtiDeepLinkingSelect = async (
  input: HandleLtiDeepLinkingSelectInput,
): Promise<Response> => {
  const { c, resolveLtiIssuerRegistry, resolveDatabase } = input;
  const form = await c.req.formData();
  const ltiSessionId = asNonEmptyString(form.get("lti_session_id"));
  const ruleId = asNonEmptyString(form.get("rule_id"));

  if (!hasExactSelectionFields(form) || ltiSessionId === null || ruleId === null) {
    return c.json({ error: "lti_session_id and rule_id are required" }, 400);
  }

  const db = resolveDatabase(c.env);
  const persistedSession = await findActiveLtiLaunchSessionByOpaqueId(db, ltiSessionId);

  if (persistedSession === null) {
    return c.json({ error: "LTI Deep Linking session was not found or is no longer active" }, 404);
  }

  const tenantId = persistedSession.tenantId;
  let ltiSession: ReturnType<typeof parsePersistedLtiSession>;

  try {
    ltiSession = parsePersistedLtiSession(persistedSession.dataJson);
  } catch {
    return c.json({ error: "LTI launch session data is invalid" }, 400);
  }

  const ltiCapabilities =
    ltiSession === undefined ? null : resolveLtiServiceCapabilities(ltiSession);

  if (ltiSession === undefined || ltiCapabilities?.deepLinking.available !== true) {
    return c.json({ error: "LTI Deep Linking session was not found or is no longer active" }, 404);
  }

  if (!ltiSession.isInstructor) {
    return c.json({ error: "Selecting a badge rule requires an instructor launch" }, 403);
  }

  if (persistedSession.userId === null) {
    return c.json({ error: "LTI launch session is missing linked user context" }, 400);
  }

  const issuerRegistry = await resolveLtiIssuerRegistry(c);
  const issuerMatch = findLtiIssuerRegistryEntry(
    issuerRegistry,
    ltiSession.platform.issuer,
    ltiSession.platform.clientId,
  );

  if (issuerMatch === null || issuerMatch.entry.tenantId !== tenantId) {
    return c.json(
      { error: "LTI issuer registration was not found for this Deep Linking session" },
      404,
    );
  }

  const lmsConnection = await findTenantLmsConnectionByLtiRegistration(db, {
    tenantId,
    issuer: ltiSession.platform.issuer,
    clientId: ltiSession.platform.clientId,
    deploymentId: ltiSession.platform.deploymentId,
  });
  const contextId = ltiSession.context.id.trim();

  if (lmsConnection === null) {
    return unavailableRuleResponse(
      c,
      403,
      "This LTI registration is not connected to an LMS in CredTrail.",
      "connection_unavailable",
    );
  }

  if (contextId.length === 0) {
    return c.json({ error: "LTI course context is required to place a badge rule" }, 400);
  }

  const contextTitle = ltiSession.context.title.trim();
  await observeVerifiedLtiCourseContext(db, {
    tenantId,
    lmsConnectionId: lmsConnection.id,
    contextId,
    displayName: contextTitle.length === 0 ? "LMS course" : contextTitle,
    courseCode: courseCode(ltiSession.context.label),
  });
  const rule = await findBadgeIssuanceRuleById(db, tenantId, ruleId);

  if (rule === null || rule.lmsConnectionId !== lmsConnection.id) {
    return unavailableRuleResponse(
      c,
      404,
      "This badge rule is not available for this LTI tenant.",
      "rule_not_found",
    );
  }

  if (
    await isCourseRelativeLtiAuthoredBadgeRule(db, {
      tenantId,
      ruleId: rule.id,
    })
  ) {
    return unavailableRuleResponse(
      c,
      403,
      "This course-specific rule cannot be reused in another LMS placement.",
      "course_relative_rule_not_supported",
    );
  }

  const version = await findActiveBadgeIssuanceRuleVersion(db, {
    tenantId,
    ruleId: rule.id,
  });

  if (version === null || rule.activeVersionId !== version.id) {
    return unavailableRuleResponse(c, 403, "This badge rule is not active.", "rule_not_active");
  }

  const availability = await resolveBadgeRulePlacementAvailabilityForContext(db, {
    tenantId,
    ruleId: rule.id,
    lmsConnectionId: lmsConnection.id,
    contextId,
  });

  if (availability.status !== "allowed") {
    return unavailableRuleResponse(
      c,
      403,
      availability.status === "course_unmapped"
        ? "This LMS course must be mapped to an organizational area before adding this rule."
        : "This badge rule is not offered in this course.",
      availability.status === "course_unmapped" ? "course_unmapped" : "outside_availability",
    );
  }

  const badgeTemplate = await findBadgeTemplateById(db, tenantId, rule.badgeTemplateId);

  if (
    badgeTemplate === null ||
    badgeTemplate.isArchived ||
    version.snapshot.badgeTemplateId !== badgeTemplate.id
  ) {
    return unavailableRuleResponse(
      c,
      403,
      "The badge for this rule is no longer available.",
      "template_mismatch",
    );
  }

  const launchUrl = new URL(ltiSession.launch.target);
  launchUrl.searchParams.set("ruleId", rule.id);
  launchUrl.searchParams.set("badgeTemplateId", badgeTemplate.id);
  const ltiTool = await createCredTrailLtiTool({ db, env: c.env, tenantId });
  const deepLinkingResult = await ltiTool
    .createAdvantage(ltiSession)
    .createDeepLinkingHtmlResponse([
      badgeRuleDeepLinkContentItem({
        badgeTemplateId: badgeTemplate.id,
        ruleId: rule.id,
        title: version.snapshot.name,
        description: version.snapshot.description,
        launchUrl: launchUrl.toString(),
      }),
    ]);

  if (!deepLinkingResult.success) {
    return c.json({ error: formatLtiServiceError(deepLinkingResult.error) }, 502);
  }

  return secureLtiDeepLinkingHtmlResponse(
    deepLinkingResult.data,
    ltiCapabilities.deepLinking.returnUrl,
  );
};
