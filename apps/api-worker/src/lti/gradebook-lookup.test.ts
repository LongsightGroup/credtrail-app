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
      jwtPayload: {
        iss: "https://canvas.example.edu",
        sub: "user-1",
        aud: "canvas-client-123",
        exp: 1_800_000_000,
        iat: 1_700_000_000,
        nonce: "nonce-123",
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": "deployment-123",
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiDeepLinkingRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri":
          "https://tool.example.edu/v1/lti/launch",
        "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings": {
          deep_link_return_url: "https://canvas.example.edu/deep-link-return",
          accept_types: ["ltiResourceLink"],
          accept_presentation_document_targets: [],
        },
      },
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
      hasDeepLinkingService: true,
      isInstructor: true,
    });
  });
});
