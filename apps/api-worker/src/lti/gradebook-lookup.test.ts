import { describe, expect, it } from "vitest";
import { parsePersistedLtiSessionDataJson } from "./gradebook-lookup";

describe("parsePersistedLtiSessionDataJson", () => {
  it("returns null for invalid JSON", () => {
    expect(parsePersistedLtiSessionDataJson("{not-json")).toBeNull();
  });

  it("returns null when required session fields are missing", () => {
    expect(
      parsePersistedLtiSessionDataJson(JSON.stringify({ context: { id: "course-1" } })),
    ).toBeNull();
  });

  it("parses a persisted deep linking session", () => {
    const session = {
      id: "lti-session-123",
      jwtPayload: {},
      user: { id: "user-1", roles: [] },
      context: { id: "course-123", label: "TS101", title: "TypeScript 101" },
      platform: {
        issuer: "https://canvas.example.edu",
        clientId: "canvas-client-123",
        deploymentId: "deployment-123",
        name: "Canvas",
      },
      launch: { target: "https://tool.example.edu/v1/lti/launch" },
      services: {
        deepLinking: {
          returnUrl: "https://canvas.example.edu/deep-link-return",
          acceptTypes: ["ltiResourceLink"],
          acceptPresentationDocumentTargets: [],
          acceptMultiple: false,
          autoCreate: false,
        },
      },
      customParameters: {},
      isAdmin: false,
      isInstructor: true,
      isStudent: false,
      isAssignmentAndGradesAvailable: false,
      isDeepLinkingAvailable: true,
      isNameAndRolesAvailable: false,
    };

    expect(parsePersistedLtiSessionDataJson(JSON.stringify(session))).toEqual({
      context: {
        id: "course-123",
      },
      platform: {
        issuer: "https://canvas.example.edu",
        clientId: "canvas-client-123",
        deploymentId: "deployment-123",
      },
      services: {
        deepLinking: session.services.deepLinking,
      },
      isInstructor: true,
    });
  });
});
