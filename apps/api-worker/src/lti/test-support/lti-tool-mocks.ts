import { LtiServiceError, type LTISession, type LTITool } from "@longsightgroup/lti-tool";
import { vi } from "vitest";

type VitestMock = ReturnType<typeof vi.fn>;

export const mockLtiToolWithGetMembers = (getMembers: VitestMock): LTITool =>
  ({
    createAdvantage: vi.fn(() => ({
      getMembers,
    })),
  }) as unknown as LTITool;

export const mockLtiToolWithDeepLinking = (input: {
  getSession: VitestMock;
  createDeepLinkingResponse: VitestMock;
}): LTITool =>
  ({
    getSession: input.getSession,
    createAdvantage: vi.fn(() => ({
      createDeepLinkingResponse: input.createDeepLinkingResponse,
    })),
  }) as unknown as LTITool;

export const defaultNrpsGetMembersForSession = (session: LTISession): VitestMock =>
  vi.fn(async () => {
    if (session.services?.nrps?.membershipUrl === undefined) {
      return {
        success: false,
        error: new LtiServiceError({
          code: "service_not_available",
          serviceKind: "nrps",
          operation: "getMembers",
          message: "NRPS membership service is not available for this session",
        }),
      };
    }

    return {
      success: true,
      data: [],
    };
  });

export const mockLtiToolCreateAdvantageForSession = (input: {
  getMembers?: VitestMock;
  createDeepLinkingResponse?: VitestMock;
}): ReturnType<typeof vi.fn> =>
  vi.fn((session: LTISession) => ({
    getMembers: input.getMembers ?? defaultNrpsGetMembersForSession(session),
    ...(input.createDeepLinkingResponse === undefined
      ? {}
      : { createDeepLinkingResponse: input.createDeepLinkingResponse }),
  }));
