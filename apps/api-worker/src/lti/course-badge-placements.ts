import {
  listBadgeTemplatesByIds,
  listLtiResourceLinkPlacementsForContext,
  type BadgeTemplateRecord,
  type LtiResourceLinkPlacementRecord,
  type SqlDatabase,
} from "@credtrail/db";
import {
  LTI_CLAIM_DEPLOYMENT_ID,
  type LTI13JwtPayload as LtiLaunchClaims,
  type LTISession,
} from "@lti-tool/core";
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
  const placements = await listLtiResourceLinkPlacementsForContext(input.db, {
    tenantId: input.tenantId,
    issuer: input.launchClaims.iss,
    clientId: input.issuerClientId,
    deploymentId: input.launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
    contextId: input.contextId,
  });
  const orderedBadgeTemplateIds = orderedUniqueBadgeTemplateIds(placements);
  const badgeTemplates = await listBadgeTemplatesByIds(input.db, {
    tenantId: input.tenantId,
    badgeTemplateIds: orderedBadgeTemplateIds,
    includeArchived: false,
  });
  const templatesById = new Map(badgeTemplates.map((template) => [template.id, template]));
  const orderedTemplates = orderedBadgeTemplateIds
    .map((badgeTemplateId) => templatesById.get(badgeTemplateId) ?? null)
    .filter((badgeTemplate): badgeTemplate is BadgeTemplateRecord => badgeTemplate !== null);

  return {
    contextId: input.contextId,
    placements,
    orderedTemplates,
    placementGroups: ltiCoursePlacementGroupsByBadgeTemplate({
      placements,
      orderedTemplates,
    }),
  };
};
