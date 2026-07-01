import {
  LtiServiceError,
  type LtiServiceErrorCode,
  type LTISession,
  type LTITool,
} from "@longsightgroup/lti-tool";
import { describe, expect, it, vi } from "vitest";
import { loadLtiNrpsRoster } from "./nrps";

const ltiSession = {
  id: "lti-session-123",
  context: {
    id: "course-123",
    title: "Course 123",
  },
  platform: {
    issuer: "https://sakai.example.edu",
    clientId: "client-123",
    deploymentId: "deployment-123",
  },
} as LTISession;

const ltiToolWithMembersResult = (getMembers: ReturnType<typeof vi.fn>): LTITool =>
  ({
    createAdvantage: vi.fn(() => ({
      getMembers,
    })),
  }) as unknown as LTITool;

describe("loadLtiNrpsRoster", () => {
  it("maps core members into the CredTrail roster view model", async () => {
    const getMembers = vi.fn().mockResolvedValue({
      success: true,
      data: [
        {
          userId: "learner-001",
          name: "Learner One",
          email: "learner-one@example.edu",
          lisPersonSourcedId: "sourced-learner-001",
          roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
          status: "Active",
        },
        {
          userId: "instructor-001",
          name: "Instructor One",
          roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"],
          status: "Active",
        },
      ],
    });

    const result = await loadLtiNrpsRoster({
      ltiTool: ltiToolWithMembersResult(getMembers),
      ltiSession,
      contextId: "course-123",
    });

    expect(result).toMatchObject({
      success: true,
      roster: {
        contextId: "course-123",
        learnerMembers: [
          {
            userId: "learner-001",
            sourcedId: "sourced-learner-001",
            displayName: "Learner One",
            email: "learner-one@example.edu",
            isLearner: true,
          },
        ],
      },
    });
  });

  it("returns unavailable when core reports no NRPS service", async () => {
    const getMembers = vi.fn().mockResolvedValue({
      success: false,
      error: new LtiServiceError({
        code: "service_not_available",
        serviceKind: "nrps",
        operation: "getMembers",
        message: "NRPS membership service is not available for this session",
      }),
    });

    const result = await loadLtiNrpsRoster({
      ltiTool: ltiToolWithMembersResult(getMembers),
      ltiSession,
      contextId: "course-123",
    });

    expect(result).toEqual({
      success: false,
      failure: {
        status: "unavailable",
        logDetail: {
          code: "service_not_available",
          serviceKind: "nrps",
          operation: "getMembers",
          message: "NRPS membership service is not available for this session",
        },
      },
    });
  });

  it("preserves structured core service error detail for LMS failures", async () => {
    const getMembers = vi.fn().mockResolvedValue({
      success: false,
      error: new LtiServiceError({
        code: "platform_request_failed",
        serviceKind: "nrps",
        operation: "getMembers",
        message: "NRPS request failed",
        endpointType: "context_memberships_url",
        status: 503,
        statusText: "Service Unavailable",
        responseBodySummary: "upstream unavailable",
      }),
    });

    const result = await loadLtiNrpsRoster({
      ltiTool: ltiToolWithMembersResult(getMembers),
      ltiSession,
      contextId: "course-123",
    });

    expect(result).toEqual({
      success: false,
      failure: {
        status: "error",
        logDetail: {
          code: "platform_request_failed",
          serviceKind: "nrps",
          operation: "getMembers",
          message: "NRPS request failed",
          endpointType: "context_memberships_url",
          status: 503,
          statusText: "Service Unavailable",
          responseBodySummary: "upstream unavailable",
        },
      },
    });
  });

  it.each([
    "missing_required_scope",
    "token_request_failed",
    "platform_response_invalid",
  ] satisfies readonly LtiServiceErrorCode[])("maps %s to an error roster state", async (code) => {
    const getMembers = vi.fn().mockResolvedValue({
      success: false,
      error: new LtiServiceError({
        code,
        serviceKind: "nrps",
        operation: "getMembers",
        message: `NRPS failed with ${code}`,
      }),
    });

    const result = await loadLtiNrpsRoster({
      ltiTool: ltiToolWithMembersResult(getMembers),
      ltiSession,
      contextId: "course-123",
    });

    expect(result).toEqual({
      success: false,
      failure: {
        status: "error",
        logDetail: {
          code,
          serviceKind: "nrps",
          operation: "getMembers",
          message: `NRPS failed with ${code}`,
        },
      },
    });
  });
});
