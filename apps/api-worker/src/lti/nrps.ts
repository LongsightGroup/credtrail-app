import {
  type LtiServiceError,
  type LtiServiceErrorCode,
  type LTISession,
  type LtiToolPort,
  resolveLtiNrpsRoster,
  type ResolvedLtiNrpsRosterMember,
} from "@longsightgroup/lti-tool";

export type LtiNrpsMember = ResolvedLtiNrpsRosterMember;

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

const ltiNrpsRosterFromCoreMembers = (input: {
  contextId: string | null;
  members: Parameters<typeof resolveLtiNrpsRoster>[0];
}): LtiNrpsRoster => {
  const resolvedRoster = resolveLtiNrpsRoster(input.members);

  return {
    contextId: input.contextId,
    members: resolvedRoster.members,
    learnerMembers: resolvedRoster.learnerMembers,
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
  ltiTool: LtiToolPort;
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
