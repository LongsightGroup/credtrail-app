import { findLtiLaunchSessionById, listBadgeTemplates } from "@credtrail/db";
import { formatLtiServiceError, resolveLtiServiceCapabilities } from "@longsightgroup/lti-tool";
import type { AppContext } from "../app";
import type { ResolveDatabase } from "../app/route-deps";
import { asNonEmptyString, normalizeUniqueStringList } from "../utils/value-parsers";
import { resolveLtiCourseBadgeAuthority } from "./course-badge-governance";
import {
  ltiCourseBadgeSetupRuleDefinition,
  parseLtiCourseBadgeSetupPreset,
} from "./course-badge-setup";
import { createLtiCourseBadgeSetupToken } from "./course-badge-setup-token";
import { createCredTrailLtiTool } from "./credtrail-lti-tool";
import { badgeTemplateDeepLinkContentItem } from "./deep-linking-helpers";
import { findLtiIssuerRegistryEntry, type LtiIssuerRegistry } from "./lti-issuer-registry";

const LTI_COURSE_BADGE_SETUP_TOKEN_TTL_SECONDS = 60 * 60;

const optionalNumberFromForm = (value: FormDataEntryValue | null): number | undefined => {
  const normalized = asNonEmptyString(value);

  if (normalized === null) {
    return undefined;
  }

  const parsed = Number(normalized);
  return Number.isFinite(parsed) ? parsed : undefined;
};

/**
 * Dependencies required to handle the product Deep Linking selection POST.
 */
export interface HandleLtiDeepLinkingSelectInput {
  readonly c: AppContext;
  readonly resolveLtiIssuerRegistry: (context: AppContext) => Promise<LtiIssuerRegistry>;
  resolveDatabase: ResolveDatabase;
}

/**
 * Handles CredTrail's Deep Linking selection POST after a verified LTI launch session.
 */
export const handleLtiDeepLinkingSelect = async (
  input: HandleLtiDeepLinkingSelectInput,
): Promise<Response> => {
  const { c, resolveLtiIssuerRegistry, resolveDatabase } = input;
  const form = await c.req.formData();
  const ltiSessionId = asNonEmptyString(form.get("lti_session_id"));
  const badgeTemplateId = asNonEmptyString(form.get("badge_template_id"));
  const criteriaPreset = parseLtiCourseBadgeSetupPreset(
    asNonEmptyString(form.get("criteria_preset")),
  );

  if (ltiSessionId === null || badgeTemplateId === null || criteriaPreset === null) {
    return c.json(
      {
        error: "lti_session_id, badge_template_id, and criteria_preset are required",
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
  const ltiCapabilities =
    ltiSession === undefined ? null : resolveLtiServiceCapabilities(ltiSession);

  if (ltiSession === undefined || ltiCapabilities?.deepLinking.available !== true) {
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

  const contextId = ltiSession.context.id.trim();

  if (contextId.length === 0) {
    return c.json(
      {
        error: "LTI course context is required for course badge setup",
      },
      400,
    );
  }

  const setupRequest = {
    preset: criteriaPreset,
    scoreThreshold: optionalNumberFromForm(form.get("score_threshold")),
    gradebookItemId: asNonEmptyString(form.get("gradebook_item_id")) ?? undefined,
    completionPercent: optionalNumberFromForm(form.get("completion_percent")),
    workflowStates: normalizeUniqueStringList(form.getAll("workflow_states")),
  };
  const ruleDefinition = ltiCourseBadgeSetupRuleDefinition(contextId, setupRequest);

  if (ruleDefinition === null) {
    return c.json(
      {
        error: "Choose a criterion and provide the required threshold or gradebook item.",
      },
      400,
    );
  }

  const persistedSession = await findLtiLaunchSessionById(db, ltiSession.id);

  if (persistedSession?.userId === null || persistedSession?.userId === undefined) {
    return c.json(
      {
        error: "LTI launch session is missing linked user context",
      },
      400,
    );
  }

  if (!ltiSession.isInstructor) {
    return c.json(
      {
        error: "LTI course badge setup requires an instructor Deep Linking session",
      },
      403,
    );
  }

  const authority = await resolveLtiCourseBadgeAuthority(db, {
    tenantId: issuerMatch.entry.tenantId,
    userId: persistedSession.userId,
    badgeTemplate,
  });

  if (!authority.ok) {
    return c.json(
      {
        error: authority.message,
        reason: authority.reason,
      },
      403,
    );
  }

  const setupToken = await createLtiCourseBadgeSetupToken(c.env, {
    tenantId: issuerMatch.entry.tenantId,
    issuer: ltiSession.platform.issuer,
    clientId: ltiSession.platform.clientId,
    deploymentId: ltiSession.platform.deploymentId,
    contextId,
    badgeTemplateId: badgeTemplate.id,
    setupRequest: {
      ...setupRequest,
    },
    ttlSeconds: LTI_COURSE_BADGE_SETUP_TOKEN_TTL_SECONDS,
  });

  const launchUrl = new URL(ltiSession.launch.target);
  launchUrl.searchParams.set("badgeTemplateId", badgeTemplate.id);
  launchUrl.searchParams.set("setupToken", setupToken);
  const deepLinkingResult = await ltiTool.createAdvantage(ltiSession).createDeepLinkingResponse([
    badgeTemplateDeepLinkContentItem({
      badgeTemplateId: badgeTemplate.id,
      setupToken,
      title: badgeTemplate.title,
      description: badgeTemplate.description,
      launchUrl: launchUrl.toString(),
    }),
  ]);

  if (!deepLinkingResult.success) {
    return c.json(
      {
        error: formatLtiServiceError(deepLinkingResult.error),
      },
      502,
    );
  }

  c.header("Cache-Control", "no-store");
  return c.body(deepLinkingResult.data, 200, {
    "Content-Type": "text/html; charset=UTF-8",
  });
};
