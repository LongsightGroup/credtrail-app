import {
  listBadgeTemplatesByIds,
  listLtiResourceLinkPlacementsForContext,
  listLtiResourceLinkPlacementRuleStates,
  type BadgeTemplateRecord,
  type LtiResourceLinkPlacementRecord,
  type SqlDatabase,
} from "@credtrail/db";
import {
  LTI_CLAIM_DEPLOYMENT_ID,
  type LTI13JwtPayload as LtiLaunchClaims,
  type LTISession,
} from "@longsightgroup/lti-tool";
import type { ResourceLinkLaunchMessage } from "./resource-link-launch-types";

export interface LtiCourseBadgeTemplatePlacementGroup {
  badgeTemplateId: string;
  template: BadgeTemplateRecord;
  primaryPlacement: LtiResourceLinkPlacementRecord;
  placements: readonly LtiResourceLinkPlacementRecord[];
}

export interface LtiCourseBadgePlacementResolution {
  contextId: string;
  placements: readonly LtiResourceLinkPlacementRecord[];
  orderedTemplates: readonly BadgeTemplateRecord[];
  placementGroups: readonly LtiCourseBadgeTemplatePlacementGroup[];
  status:
    | {
        kind: "usable";
        counts: LtiCourseBadgePlacementResolutionCounts;
      }
    | {
        kind: "empty";
        reason: "no_placements" | "only_retired" | "no_active_rules" | "no_available_templates";
        counts: LtiCourseBadgePlacementResolutionCounts;
      };
}

export interface LtiCourseBadgePlacementResolutionCounts {
  queriedPlacements: number;
  activePlacements: number;
  retiredPlacements: number;
  usablePlacements: number;
  inactiveRulePlacements: number;
  missingRulePlacements: number;
  archivedTemplatePlacements: number;
  missingTemplatePlacements: number;
}

export const ltiCourseContextIdFromLaunch = (input: {
  launchMessage: ResourceLinkLaunchMessage;
  ltiLaunchSession: LTISession;
}): string => {
  return input.launchMessage.resourceContextId ?? input.ltiLaunchSession.context.id;
};

const orderedUniqueBadgeTemplateIds = (
  placements: readonly LtiResourceLinkPlacementRecord[],
): string[] => {
  const seen = new Set<string>();
  const uniqueIds: string[] = [];

  for (const placement of placements) {
    if (seen.has(placement.badgeTemplateId)) {
      continue;
    }

    seen.add(placement.badgeTemplateId);
    uniqueIds.push(placement.badgeTemplateId);
  }

  return uniqueIds;
};

const ltiCoursePlacementGroupsByBadgeTemplate = (input: {
  placements: readonly LtiResourceLinkPlacementRecord[];
  orderedTemplates: readonly BadgeTemplateRecord[];
}): LtiCourseBadgeTemplatePlacementGroup[] => {
  const placementsByBadgeTemplateId = new Map<string, LtiResourceLinkPlacementRecord[]>();

  for (const placement of input.placements) {
    const placementsForTemplate = placementsByBadgeTemplateId.get(placement.badgeTemplateId) ?? [];
    placementsForTemplate.push(placement);
    placementsByBadgeTemplateId.set(placement.badgeTemplateId, placementsForTemplate);
  }

  const groups: LtiCourseBadgeTemplatePlacementGroup[] = [];

  for (const template of input.orderedTemplates) {
    const placements = placementsByBadgeTemplateId.get(template.id) ?? [];
    const primaryPlacement = placements[0];

    if (primaryPlacement === undefined) {
      continue;
    }

    groups.push({
      badgeTemplateId: template.id,
      template,
      primaryPlacement,
      placements,
    });
  }

  return groups;
};

export const resolveOrderedCourseBadgeTemplatesForContext = async (input: {
  db: SqlDatabase;
  tenantId: string;
  launchClaims: LtiLaunchClaims;
  issuerClientId: string;
  contextId: string;
}): Promise<LtiCourseBadgePlacementResolution> => {
  const queriedPlacements = await listLtiResourceLinkPlacementsForContext(input.db, {
    tenantId: input.tenantId,
    issuer: input.launchClaims.iss,
    clientId: input.issuerClientId,
    deploymentId: input.launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
    contextId: input.contextId,
    includeRetired: true,
  });
  const activePlacements = queriedPlacements.filter((placement) => placement.status === "active");
  const linkedRuleIds = activePlacements
    .map((placement) => placement.ruleId)
    .filter((ruleId): ruleId is string => ruleId !== null);
  const ruleStates = await listLtiResourceLinkPlacementRuleStates(input.db, {
    tenantId: input.tenantId,
    ruleIds: linkedRuleIds,
  });
  const ruleStatesById = new Map(ruleStates.map((rule) => [rule.ruleId, rule]));
  const missingRulePlacements = activePlacements.filter(
    (placement) => placement.ruleId === null || !ruleStatesById.has(placement.ruleId),
  );
  const inactiveRulePlacements = activePlacements.filter((placement) => {
    if (placement.ruleId === null) {
      return false;
    }

    return ruleStatesById.get(placement.ruleId)?.isActive === false;
  });
  const activeRulePlacements = activePlacements.filter((placement) => {
    if (placement.ruleId === null) {
      return false;
    }

    return ruleStatesById.get(placement.ruleId)?.isActive === true;
  });
  const orderedBadgeTemplateIds = orderedUniqueBadgeTemplateIds(activeRulePlacements);
  const badgeTemplates = await listBadgeTemplatesByIds(input.db, {
    tenantId: input.tenantId,
    badgeTemplateIds: orderedBadgeTemplateIds,
    includeArchived: true,
  });
  const templatesById = new Map(badgeTemplates.map((template) => [template.id, template]));
  const orderedTemplates = orderedBadgeTemplateIds
    .map((badgeTemplateId) => templatesById.get(badgeTemplateId) ?? null)
    .filter(
      (badgeTemplate): badgeTemplate is BadgeTemplateRecord =>
        badgeTemplate !== null && !badgeTemplate.isArchived,
    );
  const availableTemplateIds = new Set(orderedTemplates.map((template) => template.id));
  const placements = activeRulePlacements.filter((placement) =>
    availableTemplateIds.has(placement.badgeTemplateId),
  );
  const archivedTemplateIds = new Set(
    badgeTemplates.filter((template) => template.isArchived).map((template) => template.id),
  );
  const archivedTemplatePlacements = activeRulePlacements.filter((placement) =>
    archivedTemplateIds.has(placement.badgeTemplateId),
  );
  const knownTemplateIds = new Set(badgeTemplates.map((template) => template.id));
  const missingTemplatePlacements = activeRulePlacements.filter(
    (placement) => !knownTemplateIds.has(placement.badgeTemplateId),
  );
  const counts: LtiCourseBadgePlacementResolutionCounts = {
    queriedPlacements: queriedPlacements.length,
    activePlacements: activePlacements.length,
    retiredPlacements: queriedPlacements.length - activePlacements.length,
    usablePlacements: placements.length,
    inactiveRulePlacements: inactiveRulePlacements.length,
    missingRulePlacements: missingRulePlacements.length,
    archivedTemplatePlacements: archivedTemplatePlacements.length,
    missingTemplatePlacements: missingTemplatePlacements.length,
  };
  const emptyReason = (): Extract<
    LtiCourseBadgePlacementResolution["status"],
    { kind: "empty" }
  >["reason"] => {
    if (queriedPlacements.length === 0) {
      return "no_placements";
    }

    if (activePlacements.length === 0) {
      return "only_retired";
    }

    if (activeRulePlacements.length === 0) {
      return "no_active_rules";
    }

    return "no_available_templates";
  };

  return {
    contextId: input.contextId,
    placements,
    orderedTemplates,
    placementGroups: ltiCoursePlacementGroupsByBadgeTemplate({
      placements,
      orderedTemplates,
    }),
    status:
      placements.length > 0
        ? { kind: "usable", counts }
        : { kind: "empty", reason: emptyReason(), counts },
  };
};
