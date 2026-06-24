import { beforeEach, describe, expect, it, vi } from "vitest";

const mockedCreateGradebookProvider = vi.hoisted(() => vi.fn());

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    findLtiLaunchSessionById: vi.fn(),
    listLtiIssuerRegistrations: vi.fn(),
    listTenantLmsConnections: vi.fn(),
    updateTenantLmsConnectionTokens: vi.fn(),
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

vi.mock("./lms/gradebook-provider", () => {
  return {
    createGradebookProvider: mockedCreateGradebookProvider,
  };
});

import {
  findLtiLaunchSessionById,
  listLtiIssuerRegistrations,
  listTenantLmsConnections,
  type LtiLaunchSessionRecord,
  type SqlDatabase,
  type TenantLmsConnectionRecord,
} from "@credtrail/db";
import type { LTISession } from "@lti-tool/core";
import { createPostgresDatabase } from "@credtrail/db/postgres";
import { app } from "./index";

const mockedFindLtiLaunchSessionById = vi.mocked(findLtiLaunchSessionById);
const mockedListLtiIssuerRegistrations = vi.mocked(listLtiIssuerRegistrations);
const mockedListTenantLmsConnections = vi.mocked(listTenantLmsConnections);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);

interface ErrorResponse {
  error: string;
}

const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  LTI_ISSUER_REGISTRY_JSON: string;
  LTI_STATE_SIGNING_SECRET: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
    LTI_ISSUER_REGISTRY_JSON: JSON.stringify({
      "https://canvas.example.edu": {
        authorizationEndpoint: "https://canvas.example.edu/api/lti/authorize_redirect",
        clientId: "canvas-client-123",
        tenantId: "tenant_123",
        platformJwksEndpoint: "https://canvas.example.edu/api/lti/security/jwks",
        tokenEndpoint: "https://canvas.example.edu/login/oauth2/token",
      },
    }),
    LTI_STATE_SIGNING_SECRET: "test-lti-state-secret",
  };
};

const sampleLtiLaunchSessionRecord = (
  overrides?: Partial<LtiLaunchSessionRecord>,
): LtiLaunchSessionRecord => {
  return {
    id: "lti-session-123",
    issuer: "https://canvas.example.edu",
    clientId: "canvas-client-123",
    deploymentId: "deployment-123",
    tenantId: "tenant_123",
    userId: "usr_lti_123",
    dataJson: "{}",
    expiresAt: "2026-02-10T23:00:00.000Z",
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleDeepLinkingLtiSession = (overrides?: Partial<LTISession>): LTISession => {
  return {
    id: "lti-session-123",
    jwtPayload: {},
    user: {
      id: "user-999",
      roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"],
    },
    context: {
      id: "course-123",
      label: "TS101",
      title: "TypeScript 101",
    },
    platform: {
      issuer: "https://canvas.example.edu",
      clientId: "canvas-client-123",
      deploymentId: "deployment-123",
      name: "Canvas",
    },
    launch: {
      target: "https://tool.example.edu/v1/lti/launch",
    },
    services: {
      deepLinking: {
        returnUrl: "https://canvas.example.edu/api/lti/deep_link_return",
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
    ...overrides,
  };
};

const sampleTenantLmsConnection = (
  overrides?: Partial<TenantLmsConnectionRecord>,
): TenantLmsConnectionRecord => {
  return {
    id: "lms_sakai_001",
    tenantId: "tenant_123",
    displayName: "Sakai LTI connection",
    providerKind: "sakai",
    apiBaseUrl: "https://canvas.example.edu",
    authorizationEndpoint: null,
    tokenEndpoint: null,
    clientId: null,
    clientSecret: null,
    scope: null,
    accessToken: null,
    refreshToken: null,
    accessTokenExpiresAt: null,
    refreshTokenExpiresAt: null,
    connectedAt: "2026-02-10T22:00:00.000Z",
    ltiIssuer: "https://canvas.example.edu",
    ltiClientId: "canvas-client-123",
    ltiDeploymentId: "deployment-123",
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

describe("LTI deep linking gradebook lookup routes", () => {
  beforeEach(() => {
    mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
    mockedListLtiIssuerRegistrations.mockResolvedValue([]);
    mockedCreateGradebookProvider.mockReset();
    mockedCreateGradebookProvider.mockReturnValue({
      kind: "sakai",
      listCourses: () => Promise.resolve([]),
      listAssignments: () =>
        Promise.resolve([
          {
            assignmentId: "assignment_1",
            courseId: "course-123",
            title: "Final project",
            workflowState: "published",
            pointsPossible: 100,
            dueAt: null,
          },
        ]),
      listEnrollments: () => Promise.resolve([]),
      listSubmissions: () =>
        Promise.resolve([
          {
            courseId: "course-123",
            assignmentId: "assignment_1",
            learnerId: "learner-001",
            workflowState: "returned",
            score: 95,
            submittedAt: "2026-02-10T22:00:00.000Z",
            gradedAt: "2026-02-10T22:00:00.000Z",
            late: null,
            missing: null,
          },
        ]),
      listGrades: () => Promise.resolve([]),
      listCompletions: () => Promise.resolve([]),
    });
  });

  it("lists Sakai gradebook items for an instructor Deep Linking setup session", async () => {
    const env = createEnv();
    mockedFindLtiLaunchSessionById.mockResolvedValue(
      sampleLtiLaunchSessionRecord({
        dataJson: JSON.stringify(sampleDeepLinkingLtiSession()),
      }),
    );
    mockedListTenantLmsConnections.mockResolvedValue([
      sampleTenantLmsConnection({
        accessToken: "JSESSIONID=sakai-session.Sakai",
      }),
    ]);

    const response = await app.request(
      "/v1/lti/deep-linking/sessions/lti-session-123/gradebook-items?q=final",
      undefined,
      env,
    );
    const body = await response.json<{
      tenantId: string;
      connectionId: string;
      courseId: string;
      items: Array<{ assignmentId: string; title: string }>;
    }>();

    expect(response.status).toBe(200);
    expect(body.tenantId).toBe("tenant_123");
    expect(body.connectionId).toBe("lms_sakai_001");
    expect(body.courseId).toBe("course-123");
    expect(body.items).toEqual([
      expect.objectContaining({
        assignmentId: "assignment_1",
        title: "Final project",
      }),
    ]);
  });

  it("lists known workflow states for a selected Sakai gradebook item", async () => {
    const env = createEnv();
    mockedFindLtiLaunchSessionById.mockResolvedValue(
      sampleLtiLaunchSessionRecord({
        dataJson: JSON.stringify(sampleDeepLinkingLtiSession()),
      }),
    );
    mockedListTenantLmsConnections.mockResolvedValue([
      sampleTenantLmsConnection({
        accessToken: "JSESSIONID=sakai-session.Sakai",
      }),
    ]);

    const response = await app.request(
      "/v1/lti/deep-linking/sessions/lti-session-123/gradebook-items/assignment_1/workflow-states",
      undefined,
      env,
    );
    const body = await response.json<{
      states: Array<{ value: string; source: string; preselected: boolean }>;
    }>();

    expect(response.status).toBe(200);
    expect(body.states).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ value: "graded", source: "default", preselected: true }),
        expect.objectContaining({ value: "returned", source: "observed", preselected: false }),
      ]),
    );
  });

  it("returns fallback guidance when no matching Sakai gradebook connection exists", async () => {
    const env = createEnv();
    mockedFindLtiLaunchSessionById.mockResolvedValue(
      sampleLtiLaunchSessionRecord({
        dataJson: JSON.stringify(sampleDeepLinkingLtiSession()),
      }),
    );
    mockedListTenantLmsConnections.mockResolvedValue([]);

    const response = await app.request(
      "/v1/lti/deep-linking/sessions/lti-session-123/gradebook-items",
      undefined,
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(409);
    expect(body.error).toContain("could not find a Sakai gradebook connection");
    expect(body.error).toContain("matching issuer, client, and deployment");
  });

  it("returns fallback guidance when the Sakai connection lacks usable credentials", async () => {
    const env = createEnv();
    mockedFindLtiLaunchSessionById.mockResolvedValue(
      sampleLtiLaunchSessionRecord({
        dataJson: JSON.stringify(sampleDeepLinkingLtiSession()),
      }),
    );
    mockedListTenantLmsConnections.mockResolvedValue([sampleTenantLmsConnection()]);

    const response = await app.request(
      "/v1/lti/deep-linking/sessions/lti-session-123/gradebook-items",
      undefined,
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(409);
    expect(body.error).toContain("Sakai username and password");
    expect(mockedCreateGradebookProvider).not.toHaveBeenCalled();
  });

  it("returns actionable Sakai permission guidance when gradebook lookup is blocked", async () => {
    const env = createEnv();
    mockedFindLtiLaunchSessionById.mockResolvedValue(
      sampleLtiLaunchSessionRecord({
        dataJson: JSON.stringify(sampleDeepLinkingLtiSession()),
      }),
    );
    mockedListTenantLmsConnections.mockResolvedValue([
      sampleTenantLmsConnection({
        accessToken: "JSESSIONID=sakai-session.Sakai",
      }),
    ]);
    mockedCreateGradebookProvider.mockReturnValue({
      kind: "sakai",
      listCourses: () => Promise.resolve([]),
      listAssignments: () =>
        Promise.reject(
          new Error("Sakai gradebook API request failed (403) for /api/users/me/sites"),
        ),
      listEnrollments: () => Promise.resolve([]),
      listSubmissions: () => Promise.resolve([]),
      listGrades: () => Promise.resolve([]),
      listCompletions: () => Promise.resolve([]),
    });

    const response = await app.request(
      "/v1/lti/deep-linking/sessions/lti-session-123/gradebook-items",
      undefined,
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(502);
    expect(body.error).toContain("Sakai blocked CredTrail from reading your site list (403).");
    expect(body.error).toContain("Save a Sakai username and password");
    expect(body.error).toContain("allow REST API access to Sites and Gradebook");
  });
});
