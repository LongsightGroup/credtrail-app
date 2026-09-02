import {
  findBadgeIssuanceRuleVersionById,
  findBadgeTemplateById,
  findTenantLmsConnectionByLtiRegistration,
  isCourseRelativeLtiAuthoredBadgeRule,
  listActiveBadgeRulesAvailableForContext,
  observeVerifiedLtiCourseContext,
  type SqlDatabase,
} from "@credtrail/db";
import {
  parseBadgeIssuanceRuleDefinitionJson,
  type BadgeIssuanceRuleCondition,
} from "@credtrail/validation";
import { LTI_CLAIM_DEPLOYMENT_ID } from "@longsightgroup/lti-tool";
import type { AppContext } from "../app/types";
import { canonicalAppRequestUrl } from "../http/canonical-app-url";
import { renderAppPage } from "../ui/render-page";
import { ltiDeepLinkSelectionInput } from "./deep-linking-helpers";
import type { LinkedLtiLaunchAccount } from "./launch-account-linking";
import type { DeepLinkingLaunchMessage } from "./launch-product-types";
import type { ResolvedLtiLaunch } from "./launch-verification";
import { ltiDeepLinkSelectionPage } from "./pages";
import type { LtiDeepLinkSelectionOption } from "./view-models";

const requirementSummary = (condition: BadgeIssuanceRuleCondition): string => {
  if ("all" in condition) {
    return `Meet all requirements: ${condition.all.map(requirementSummary).join("; ")}`;
  }

  if ("any" in condition) {
    return `Meet at least one requirement: ${condition.any.map(requirementSummary).join("; ")}`;
  }

  if ("not" in condition) {
    return `Do not meet this condition: ${requirementSummary(condition.not)}`;
  }

  switch (condition.type) {
    case "grade_threshold": {
      if (condition.minScore !== undefined && condition.maxScore !== undefined) {
        return `Earn a course score from ${String(condition.minScore)}% to ${String(condition.maxScore)}%`;
      }

      if (condition.minScore !== undefined) {
        return `Earn a course score of at least ${String(condition.minScore)}%`;
      }

      return `Earn a course score of at most ${String(condition.maxScore)}%`;
    }
    case "course_completion":
      return `Complete at least ${String(condition.minCompletionPercent)}% of the configured course work`;
    case "program_completion":
      return condition.minimumCompleted === undefined
        ? "Complete every configured program course"
        : `Complete at least ${String(condition.minimumCompleted)} configured program courses`;
    case "assignment_submission":
      return condition.minScore === undefined
        ? "Submit the configured assignment or assessment"
        : `Submit the configured assignment or assessment and earn at least ${String(condition.minScore)}%`;
    case "survey_completion":
      return "Complete the configured survey";
    case "time_window":
      return "Complete the qualifying activity during the configured time window";
    case "prerequisite_badge":
      return "Earn the configured prerequisite badge";
    case "custom_field":
      return "Meet the configured institutional record requirement";
  }
};

const courseCode = (label: string | undefined): string | null => {
  const normalized = label?.trim() ?? "";
  return normalized.length === 0 ? null : normalized;
};

/**
 * Renders CredTrail's product UI for a verified LTI Deep Linking launch.
 */
export const renderLtiDeepLinkingLaunchResponse = async (input: {
  c: AppContext;
  db: SqlDatabase;
  tenantId: string;
  launchClaims: ResolvedLtiLaunch["launchClaims"];
  launchMessage: DeepLinkingLaunchMessage;
  resolvedLaunch: ResolvedLtiLaunch;
  linkedAccount: LinkedLtiLaunchAccount;
}): Promise<Response> => {
  const deploymentId = input.launchClaims[LTI_CLAIM_DEPLOYMENT_ID];
  const lmsConnection = await findTenantLmsConnectionByLtiRegistration(input.db, {
    tenantId: input.tenantId,
    issuer: input.launchClaims.iss,
    clientId: input.resolvedLaunch.issuerEntry.clientId,
    deploymentId,
  });

  if (lmsConnection === null) {
    return input.c.json(
      { error: "This LTI registration is not connected to an LMS in CredTrail." },
      403,
    );
  }

  const contextId = input.resolvedLaunch.ltiLaunchSession.context.id.trim();

  if (contextId.length === 0) {
    return input.c.json({ error: "LTI course context is required to place a badge rule." }, 400);
  }

  const contextTitle = input.resolvedLaunch.ltiLaunchSession.context.title.trim();
  await observeVerifiedLtiCourseContext(input.db, {
    tenantId: input.tenantId,
    lmsConnectionId: lmsConnection.id,
    contextId,
    displayName: contextTitle.length === 0 ? "LMS course" : contextTitle,
    courseCode: courseCode(input.resolvedLaunch.ltiLaunchSession.context.label),
  });
  const available = await listActiveBadgeRulesAvailableForContext(input.db, {
    tenantId: input.tenantId,
    lmsConnectionId: lmsConnection.id,
    contextId,
  });
  const options: LtiDeepLinkSelectionOption[] = [];

  for (const rule of available.rules) {
    if (
      rule.activeVersionId === null ||
      (await isCourseRelativeLtiAuthoredBadgeRule(input.db, {
        tenantId: input.tenantId,
        ruleId: rule.id,
      }))
    ) {
      continue;
    }

    const [version, badgeTemplate] = await Promise.all([
      findBadgeIssuanceRuleVersionById(input.db, {
        tenantId: input.tenantId,
        ruleId: rule.id,
        versionId: rule.activeVersionId,
      }),
      findBadgeTemplateById(input.db, input.tenantId, rule.badgeTemplateId),
    ]);

    if (
      version === null ||
      version.status !== "active" ||
      badgeTemplate === null ||
      badgeTemplate.isArchived ||
      version.snapshot.badgeTemplateId !== badgeTemplate.id
    ) {
      continue;
    }

    try {
      const definition = parseBadgeIssuanceRuleDefinitionJson(version.ruleJson);
      options.push({
        ruleId: rule.id,
        ruleName: version.snapshot.name,
        badgeTitle: version.snapshot.badgeTemplateTitle,
        badgeDescription: version.snapshot.badgeTemplateDescription,
        requirementSummary: requirementSummary(definition.conditions),
        versionNumber: version.versionNumber,
      });
    } catch {
      continue;
    }
  }

  return renderAppPage(
    input.c,
    ltiDeepLinkSelectionPage(
      ltiDeepLinkSelectionInput({
        requestUrl: canonicalAppRequestUrl(input.c.env.PUBLIC_APP_ORIGIN, input.c.req.url),
        ltiLaunchSession: input.resolvedLaunch.ltiLaunchSession,
        options,
      }),
    ),
  );
};
