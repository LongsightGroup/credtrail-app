import {
  findActiveDelegatedIssuingAuthorityGrantForAction,
  type BadgeTemplateRecord,
  type DelegatedIssuingAuthorityAction,
  type DelegatedIssuingAuthorityGrantRecord,
  type SqlDatabase,
} from "@credtrail/db";

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

const isRecord = (value: unknown): value is Record<string, unknown> => {
  return value !== null && typeof value === "object" && !Array.isArray(value);
};

export const parseLtiInstructorPlacementEnabled = (
  governanceMetadataJson: string | null,
): boolean => {
  if (governanceMetadataJson === null) {
    return false;
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(governanceMetadataJson) as unknown;
  } catch {
    return false;
  }

  if (!isRecord(parsed)) {
    return false;
  }

  const placement = parsed.ltiInstructorPlacement;

  if (!isRecord(placement)) {
    return false;
  }

  return placement.enabled === true;
};

export const isLtiInstructorPlaceableBadgeTemplate = (
  badgeTemplate: BadgeTemplateRecord,
): boolean => {
  return (
    !badgeTemplate.isArchived &&
    parseLtiInstructorPlacementEnabled(badgeTemplate.governanceMetadataJson)
  );
};

export const resolveLtiCourseBadgeAuthority = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    userId: string;
    badgeTemplate: BadgeTemplateRecord;
    requiredAction: DelegatedIssuingAuthorityAction;
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
    requiredAction: input.requiredAction,
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
