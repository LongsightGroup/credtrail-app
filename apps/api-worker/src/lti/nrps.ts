import { LTI_CLAIM_NRPS_NAMES_ROLE_SERVICE, type LtiLaunchClaims } from "@credtrail/lti";
import { asJsonObject, asNonEmptyString } from "../utils/value-parsers";

const NRPS_LEARNER_ROLE_MARKERS = ["#learner", "#student"];

const asJsonArray = (value: unknown): readonly unknown[] | null => {
  return Array.isArray(value) ? value : null;
};

const isAbsoluteHttpUrl = (value: string): boolean => {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
};

const roleSummary = (roles: readonly string[]): string => {
  if (roles.length === 0) {
    return "";
  }

  return roles.join(", ");
};

export interface LtiNrpsNamesRoleServiceClaim {
  contextMembershipsUrl: string;
  serviceVersions: readonly string[];
}

export interface LtiNrpsMember {
  userId: string;
  sourcedId: string | null;
  displayName: string | null;
  email: string | null;
  status: string | null;
  pictureUrl: string | null;
  roles: readonly string[];
  roleSummary: string;
  isLearner: boolean;
}

export interface LtiNrpsRoster {
  contextId: string | null;
  members: readonly LtiNrpsMember[];
  learnerMembers: readonly LtiNrpsMember[];
}

interface CoreNrpsMember {
  status: string;
  name?: string | undefined;
  picture?: string | undefined;
  givenName?: string | undefined;
  familyName?: string | undefined;
  email?: string | undefined;
  userId: string;
  lisPersonSourcedId?: string | undefined;
  roles: string[];
}

const ltiNrpsMemberFromCoreMember = (member: CoreNrpsMember): LtiNrpsMember => {
  const normalizedRoles = member.roles.map((role) => role.toLowerCase());
  const isLearner = normalizedRoles.some((role) =>
    NRPS_LEARNER_ROLE_MARKERS.some((marker) => role.includes(marker)),
  );
  const derivedDisplayName = [member.givenName, member.familyName]
    .filter((entry): entry is string => entry !== undefined && entry.trim().length > 0)
    .join(" ")
    .trim();

  return {
    userId: member.userId,
    sourcedId: member.lisPersonSourcedId ?? null,
    displayName: member.name ?? (derivedDisplayName.length === 0 ? null : derivedDisplayName),
    email: member.email ?? null,
    status: member.status,
    pictureUrl: member.picture ?? null,
    roles: member.roles,
    roleSummary: roleSummary(member.roles),
    isLearner,
  };
};

export const ltiNrpsRosterFromCoreMembers = (input: {
  contextId: string | null;
  members: readonly CoreNrpsMember[];
}): LtiNrpsRoster => {
  const members = input.members.map((member) => ltiNrpsMemberFromCoreMember(member));

  return {
    contextId: input.contextId,
    members,
    learnerMembers: members.filter((member) => member.isLearner),
  };
};

export const parseLtiNrpsNamesRoleServiceClaim = (
  claims: LtiLaunchClaims,
): LtiNrpsNamesRoleServiceClaim | null => {
  const claim = asJsonObject(claims[LTI_CLAIM_NRPS_NAMES_ROLE_SERVICE]);

  if (claim === null) {
    return null;
  }

  const contextMembershipsUrl = asNonEmptyString(claim.context_memberships_url);

  if (contextMembershipsUrl === null || !isAbsoluteHttpUrl(contextMembershipsUrl)) {
    return null;
  }

  const versions = asJsonArray(claim.service_versions);
  const serviceVersions =
    versions === null
      ? []
      : versions
          .map((entry) => asNonEmptyString(entry))
          .filter((entry): entry is string => entry !== null);

  return {
    contextMembershipsUrl,
    serviceVersions,
  };
};
