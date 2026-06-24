import {
  findActiveDelegatedIssuingAuthorityGrantForAction,
  findDelegatedIssuingAuthorityGrantFromActiveGrants,
  listActiveDelegatedIssuingAuthorityGrantsForUser,
  type BadgeTemplateRecord,
  type DelegatedIssuingAuthorityGrantRecord,
  type SqlDatabase,
} from "@credtrail/db";
import { isLtiInstructorPlacementEnabled } from "@credtrail/validation";

export const LTI_COURSE_BADGE_SETUP_ACTION = "configure_course_rule" as const;

export type LtiCourseBadgeAuthorityFailureReason =
  | "template_not_placeable"
  | "missing_delegated_authority";

export type LtiCourseBadgeAuthorityResult =
  | {
      ok: true;
      grant: DelegatedIssuingAuthorityGrantRecord;
    }
  | {
      ok: false;
      reason: LtiCourseBadgeAuthorityFailureReason;
      message: string;
    };

export const isLtiInstructorPlaceableBadgeTemplate = (
  badgeTemplate: BadgeTemplateRecord,
): boolean => {
  return (
    !badgeTemplate.isArchived &&
    isLtiInstructorPlacementEnabled(badgeTemplate.governanceMetadataJson)
  );
};

export const resolveLtiCourseBadgeAuthority = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    userId: string;
    badgeTemplate: BadgeTemplateRecord;
    atIso?: string | undefined;
  },
): Promise<LtiCourseBadgeAuthorityResult> => {
  if (!isLtiInstructorPlaceableBadgeTemplate(input.badgeTemplate)) {
    return {
      ok: false,
      reason: "template_not_placeable",
      message: "This badge template is not available for instructor LTI course placement.",
    };
  }

  const grant = await findActiveDelegatedIssuingAuthorityGrantForAction(db, {
    tenantId: input.tenantId,
    userId: input.userId,
    orgUnitId: input.badgeTemplate.ownerOrgUnitId,
    badgeTemplateId: input.badgeTemplate.id,
    requiredAction: LTI_COURSE_BADGE_SETUP_ACTION,
    ...(input.atIso === undefined ? {} : { atIso: input.atIso }),
  });

  if (grant === null) {
    return {
      ok: false,
      reason: "missing_delegated_authority",
      message:
        "You are not authorized to place or configure this badge template from this LTI course.",
    };
  }

  return {
    ok: true,
    grant,
  };
};

export const listLtiInstructorPlaceableBadgeTemplates = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    userId: string;
    badgeTemplates: readonly BadgeTemplateRecord[];
    atIso?: string | undefined;
  },
): Promise<BadgeTemplateRecord[]> => {
  const placeableByMetadata = input.badgeTemplates.filter(isLtiInstructorPlaceableBadgeTemplate);

  if (placeableByMetadata.length === 0) {
    return [];
  }

  const grants = await listActiveDelegatedIssuingAuthorityGrantsForUser(db, {
    tenantId: input.tenantId,
    userId: input.userId,
    ...(input.atIso === undefined ? {} : { atIso: input.atIso }),
  });
  const orgUnitScopeCache = new Map<string, boolean>();
  const authorizedTemplates: BadgeTemplateRecord[] = [];

  for (const badgeTemplate of placeableByMetadata) {
    const grant = await findDelegatedIssuingAuthorityGrantFromActiveGrants(
      db,
      grants,
      {
        tenantId: input.tenantId,
        orgUnitId: badgeTemplate.ownerOrgUnitId,
        badgeTemplateId: badgeTemplate.id,
        requiredAction: LTI_COURSE_BADGE_SETUP_ACTION,
      },
      orgUnitScopeCache,
    );

    if (grant !== null) {
      authorizedTemplates.push(badgeTemplate);
    }
  }

  return authorizedTemplates;
};
