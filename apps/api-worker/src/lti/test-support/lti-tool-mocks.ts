import { createFakeLtiAdvantage, createTestServiceError } from "@longsightgroup/lti-tool/testing";
import type { LTISession, LtiAdvantagePort, LtiToolPort } from "@longsightgroup/lti-tool";
import { vi } from "vitest";

type VitestMock = ReturnType<typeof vi.fn>;

export const mockLtiToolWithGetMembers = (getMembers: VitestMock): LtiToolPort =>
  ({
    createAdvantage: vi.fn(() => ({
      ...createFakeLtiAdvantage(),
      getMembers,
    })),
  }) as unknown as LtiToolPort;

export const mockLtiToolWithDeepLinking = (input: {
  createDeepLinkingResponse: VitestMock;
}): LtiToolPort =>
  ({
    createAdvantage: vi.fn(() => ({
      ...createFakeLtiAdvantage(),
      createDeepLinkingResponse: input.createDeepLinkingResponse,
    })),
  }) as unknown as LtiToolPort;

export const defaultNrpsGetMembersForSession = (session: LTISession): VitestMock =>
  vi.fn(async () => {
    if (session.services?.nrps?.membershipUrl === undefined) {
      return {
        success: false,
        error: createTestServiceError({
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
  vi.fn((session: LTISession) =>
    createFakeLtiAdvantage({
      getMembers: input.getMembers ?? defaultNrpsGetMembersForSession(session),
      ...(input.createDeepLinkingResponse === undefined
        ? {}
        : { createDeepLinkingResponse: input.createDeepLinkingResponse }),
    } as Partial<LtiAdvantagePort>),
  );
