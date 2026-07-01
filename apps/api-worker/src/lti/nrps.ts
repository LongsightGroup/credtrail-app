import {
  type LtiServiceError,
  type LtiServiceErrorCode,
  type LTISession,
  type LTITool,
  resolveLtiNrpsRoster,
  type ResolvedLtiNrpsRosterMember,
} from "@longsightgroup/lti-tool";

const roleSummary = (roles: readonly string[]): string => {
  if (roles.length === 0) {
    return "";
  }

  return roles.join(", ");
};

export interface LtiNrpsMember {
  userId: string;
  sourcedId: string | null;
  displayName: string;
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

export interface LtiNrpsRosterLoadFailureLogDetail {
  code: LtiServiceErrorCode;
  serviceKind: LtiServiceError["serviceKind"];
  operation: string;
  message: string;
  endpointType?: string;
  status?: number;
  statusText?: string;
  responseBodySummary?: string;
}

export interface LtiNrpsRosterLoadFailure {
  status: "unavailable" | "error";
  logDetail: LtiNrpsRosterLoadFailureLogDetail;
}

export type LtiNrpsRosterLoadResult =
  | {
      success: true;
      roster: LtiNrpsRoster;
    }
  | {
      success: false;
      failure: LtiNrpsRosterLoadFailure;
    };

const ltiNrpsMemberFromResolvedMember = (member: ResolvedLtiNrpsRosterMember): LtiNrpsMember => {
  return {
    userId: member.userId,
    sourcedId: member.lisPersonSourcedId ?? null,
    displayName: member.displayName,
    email: member.email ?? null,
    status: member.status,
    pictureUrl: member.picture ?? null,
    roles: member.roles,
    roleSummary: roleSummary(member.roles),
    isLearner: member.isLearner,
  };
};

const ltiNrpsRosterFromCoreMembers = (input: {
  contextId: string | null;
  members: Parameters<typeof resolveLtiNrpsRoster>[0];
}): LtiNrpsRoster => {
  const resolvedRoster = resolveLtiNrpsRoster(input.members);
  const members = resolvedRoster.members.map((member) => ltiNrpsMemberFromResolvedMember(member));
  const learnerUserIds = new Set(resolvedRoster.learnerMembers.map((member) => member.userId));

  return {
    contextId: input.contextId,
    members,
    learnerMembers: members.filter((member) => learnerUserIds.has(member.userId)),
  };
};

const ltiNrpsRosterLoadFailureLogDetail = (
  error: LtiServiceError,
): LtiNrpsRosterLoadFailureLogDetail => {
  return {
    code: error.code,
    serviceKind: error.serviceKind,
    operation: error.operation,
    message: error.message,
    ...(error.endpointType === undefined ? {} : { endpointType: error.endpointType }),
    ...(error.status === undefined ? {} : { status: error.status }),
    ...(error.statusText === undefined ? {} : { statusText: error.statusText }),
    ...(error.responseBodySummary === undefined
      ? {}
      : { responseBodySummary: error.responseBodySummary }),
  };
};

export const loadLtiNrpsRoster = async (input: {
  ltiTool: LTITool;
  ltiSession: LTISession;
  contextId: string | null;
}): Promise<LtiNrpsRosterLoadResult> => {
  const membersResult = await input.ltiTool.createAdvantage(input.ltiSession).getMembers();

  if (!membersResult.success) {
    return {
      success: false,
      failure: {
        status: membersResult.error.code === "service_not_available" ? "unavailable" : "error",
        logDetail: ltiNrpsRosterLoadFailureLogDetail(membersResult.error),
      },
    };
  }

  return {
    success: true,
    roster: ltiNrpsRosterFromCoreMembers({
      contextId: input.contextId,
      members: membersResult.data,
    }),
  };
};
