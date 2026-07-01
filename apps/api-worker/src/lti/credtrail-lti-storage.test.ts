import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  mockedFindLtiDynamicRegistrationSessionById,
  mockedFindLtiLaunchSessionById,
  mockedListLtiDeploymentsForIssuer,
  mockedListLtiIssuerRegistrations,
  mockedRecordLtiLaunchNonceUse,
  mockedUpsertLtiDeployment,
  mockedUpsertLtiIssuerRegistration,
} = vi.hoisted(() => {
  return {
    mockedFindLtiDynamicRegistrationSessionById: vi.fn(),
    mockedFindLtiLaunchSessionById: vi.fn(),
    mockedListLtiDeploymentsForIssuer: vi.fn(),
    mockedListLtiIssuerRegistrations: vi.fn(),
    mockedRecordLtiLaunchNonceUse: vi.fn(),
    mockedUpsertLtiDeployment: vi.fn(),
    mockedUpsertLtiIssuerRegistration: vi.fn(),
  };
});

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    findLtiDynamicRegistrationSessionById: mockedFindLtiDynamicRegistrationSessionById,
    findLtiLaunchSessionById: mockedFindLtiLaunchSessionById,
    listLtiDeploymentsForIssuer: mockedListLtiDeploymentsForIssuer,
    listLtiIssuerRegistrations: mockedListLtiIssuerRegistrations,
    recordLtiLaunchNonceUse: mockedRecordLtiLaunchNonceUse,
    upsertLtiDeployment: mockedUpsertLtiDeployment,
    upsertLtiIssuerRegistration: mockedUpsertLtiIssuerRegistration,
  };
});

import {
  LtiIssuerTenantConflictError,
  type LtiDeploymentRecord,
  type LtiDynamicRegistrationSessionRecord,
  type LtiIssuerRegistrationRecord,
  type LtiLaunchSessionRecord,
  type SqlDatabase,
} from "@credtrail/db";
import {
  LtiStorageConflictError,
  type LTIDynamicRegistrationSession,
  type LTISession,
} from "@longsightgroup/lti-tool";
import { CredTrailLtiStorage } from "./credtrail-lti-storage";

const fakeDb = {} as SqlDatabase;

const sampleRegistration = (
  overrides?: Partial<LtiIssuerRegistrationRecord>,
): LtiIssuerRegistrationRecord => {
  return {
    issuer: "https://canvas.test",
    tenantId: "tenant-a",
    authorizationEndpoint: "https://canvas.test/api/lti/authorize_redirect",
    clientId: "client-1",
    platformJwksEndpoint: "https://canvas.test/api/lti/security/jwks",
    tokenEndpoint: "https://canvas.test/login/oauth2/token",
    clientSecret: null,
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
};

const sampleDeployment = (overrides?: Partial<LtiDeploymentRecord>): LtiDeploymentRecord => {
  return {
    id: "deployment-row-1",
    issuer: "https://canvas.test",
    clientId: "client-1",
    deploymentId: "deployment-1",
    name: null,
    description: null,
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
};

const sampleLtiSession = (overrides?: Partial<LTISession>): LTISession => {
  const session: LTISession = {
    jwtPayload: {
      iss: "https://canvas.test",
      sub: "user-1",
      aud: "client-1",
      exp: 1_800_000_000,
      iat: 1_700_000_000,
      nonce: "nonce-1",
      "https://purl.imsglobal.org/spec/lti/claim/deployment_id": "deployment-1",
      "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
      "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
      "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": "https://tool.test/lti/launch",
      "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
        id: "resource-link-1",
      },
    },
    id: "lti-session-1",
    user: {
      id: "user-1",
      roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"],
    },
    context: {
      id: "course-1",
      label: "COURSE1",
      title: "Course 1",
    },
    platform: {
      issuer: "https://canvas.test",
      clientId: "client-1",
      deploymentId: "deployment-1",
      name: "Canvas",
    },
    launch: {
      target: "https://tool.test/lti/launch",
    },
    resourceLink: {
      id: "resource-link-1",
    },
    customParameters: {},
    isAdmin: false,
    isInstructor: true,
    isStudent: false,
    isAssignmentAndGradesAvailable: false,
    isDeepLinkingAvailable: false,
    isNameAndRolesAvailable: false,
    ...overrides,
  };

  return session;
};

const sampleLtiLaunchSessionRecord = (
  overrides?: Partial<LtiLaunchSessionRecord>,
): LtiLaunchSessionRecord => {
  return {
    id: "lti-session-1",
    issuer: "https://canvas.test",
    clientId: "client-1",
    deploymentId: "deployment-1",
    tenantId: "tenant-a",
    userId: "user-1",
    dataJson: JSON.stringify(sampleLtiSession()),
    expiresAt: "2026-01-01T01:00:00.000Z",
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
};

const sampleDynamicRegistrationSession = (
  overrides?: Partial<LTIDynamicRegistrationSession>,
): LTIDynamicRegistrationSession => {
  return {
    openIdConfiguration: {
      issuer: "https://canvas.test",
      authorization_endpoint: "https://canvas.test/api/lti/authorize_redirect",
      registration_endpoint: "https://canvas.test/api/lti/registrations",
      jwks_uri: "https://canvas.test/api/lti/security/jwks",
      token_endpoint: "https://canvas.test/login/oauth2/token",
      token_endpoint_auth_methods_supported: ["private_key_jwt"],
      token_endpoint_auth_signing_alg_values_supported: ["RS256"],
      scopes_supported: [],
      response_types_supported: ["id_token"],
      id_token_signing_alg_values_supported: ["RS256"],
      claims_supported: ["iss", "sub"],
      subject_types_supported: ["public"],
      "https://purl.imsglobal.org/spec/lti-platform-configuration": {
        product_family_code: "canvas",
        version: "cloud",
        messages_supported: [
          {
            type: "LtiResourceLinkRequest",
          },
        ],
      },
    },
    registrationToken: "registration-token-1",
    expiresAt: 1_800_000_000_000,
    ...overrides,
  };
};

const sampleDynamicRegistrationSessionRecord = (
  overrides?: Partial<LtiDynamicRegistrationSessionRecord>,
): LtiDynamicRegistrationSessionRecord => {
  return {
    id: "dynamic-registration-session-1",
    dataJson: JSON.stringify(sampleDynamicRegistrationSession()),
    expiresAt: "2026-01-01T01:00:00.000Z",
    createdAt: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
};

describe("CredTrailLtiStorage dynamic registration writes", () => {
  beforeEach(() => {
    mockedFindLtiDynamicRegistrationSessionById.mockReset();
    mockedFindLtiLaunchSessionById.mockReset();
    mockedListLtiDeploymentsForIssuer.mockReset();
    mockedListLtiIssuerRegistrations.mockReset();
    mockedRecordLtiLaunchNonceUse.mockReset();
    mockedUpsertLtiDeployment.mockReset();
    mockedUpsertLtiIssuerRegistration.mockReset();
    mockedListLtiDeploymentsForIssuer.mockResolvedValue([]);
    mockedFindLtiDynamicRegistrationSessionById.mockResolvedValue(null);
    mockedFindLtiLaunchSessionById.mockResolvedValue(null);
    mockedRecordLtiLaunchNonceUse.mockResolvedValue(true);
    mockedUpsertLtiIssuerRegistration.mockResolvedValue(sampleRegistration());
    mockedUpsertLtiDeployment.mockResolvedValue(sampleDeployment());
  });

  it("stores dynamic registration clients in the issuer registration table", async () => {
    mockedListLtiIssuerRegistrations.mockResolvedValue([]);
    const storage = new CredTrailLtiStorage(fakeDb, {
      defaultTenantId: "tenant-a",
    });

    const clientId = await storage.addClient({
      iss: "https://canvas.test/",
      name: "Canvas",
      clientId: "client-1",
      authUrl: "https://canvas.test/api/lti/authorize_redirect",
      tokenUrl: "https://canvas.test/login/oauth2/token",
      jwksUrl: "https://canvas.test/api/lti/security/jwks",
    });

    expect(clientId).toBe("https://canvas.test");
    expect(mockedUpsertLtiIssuerRegistration).toHaveBeenCalledWith(fakeDb, {
      issuer: "https://canvas.test/",
      tenantId: "tenant-a",
      authorizationEndpoint: "https://canvas.test/api/lti/authorize_redirect",
      clientId: "client-1",
      platformJwksEndpoint: "https://canvas.test/api/lti/security/jwks",
      tokenEndpoint: "https://canvas.test/login/oauth2/token",
    });
  });

  it("stores dynamic registration deployments in the deployment table", async () => {
    mockedListLtiIssuerRegistrations.mockResolvedValue([sampleRegistration()]);
    const storage = new CredTrailLtiStorage(fakeDb, {
      defaultTenantId: "tenant-a",
    });

    const deploymentId = await storage.addDeployment("https://canvas.test", {
      deploymentId: "deployment-1",
      name: "Course navigation",
      description: "Canvas course navigation placement",
    });

    expect(deploymentId).toBe("deployment-row-1");
    expect(mockedUpsertLtiDeployment).toHaveBeenCalledWith(fakeDb, {
      issuer: "https://canvas.test",
      clientId: "client-1",
      deploymentId: "deployment-1",
      name: "Course navigation",
      description: "Canvas course navigation placement",
    });
  });

  it("rejects issuer takeover across tenants", async () => {
    mockedUpsertLtiIssuerRegistration.mockRejectedValueOnce(
      new LtiIssuerTenantConflictError("https://canvas.test", "tenant-b", "tenant-a"),
    );
    const storage = new CredTrailLtiStorage(fakeDb, {
      defaultTenantId: "tenant-a",
    });

    await expect(
      storage.addClient({
        iss: "https://canvas.test/",
        name: "Canvas",
        clientId: "client-1",
        authUrl: "https://canvas.test/api/lti/authorize_redirect",
        tokenUrl: "https://canvas.test/login/oauth2/token",
        jwksUrl: "https://canvas.test/api/lti/security/jwks",
      }),
    ).rejects.toThrow(LtiStorageConflictError);
    expect(mockedUpsertLtiIssuerRegistration).toHaveBeenCalledTimes(1);
  });

  it("round-trips valid persisted launch sessions through the storage interface", async () => {
    const session = sampleLtiSession();
    mockedFindLtiLaunchSessionById.mockResolvedValue(
      sampleLtiLaunchSessionRecord({
        dataJson: JSON.stringify(session),
      }),
    );
    const storage = new CredTrailLtiStorage(fakeDb);

    await expect(storage.getSession("lti-session-1")).resolves.toEqual(session);
  });

  it("rejects malformed persisted launch session JSON", async () => {
    mockedFindLtiLaunchSessionById.mockResolvedValue(
      sampleLtiLaunchSessionRecord({
        dataJson: "{not-json",
      }),
    );
    const storage = new CredTrailLtiStorage(fakeDb);

    await expect(storage.getSession("lti-session-1")).resolves.toBeUndefined();
  });

  it("rejects launch session JSON that does not match the core session shape", async () => {
    mockedFindLtiLaunchSessionById.mockResolvedValue(
      sampleLtiLaunchSessionRecord({
        dataJson: JSON.stringify({ id: "lti-session-1" }),
      }),
    );
    const storage = new CredTrailLtiStorage(fakeDb);

    await expect(storage.getSession("lti-session-1")).resolves.toBeUndefined();
  });

  it("records launch nonce use atomically for replay protection", async () => {
    const storage = new CredTrailLtiStorage(fakeDb);

    await expect(storage.validateNonce("nonce-1")).resolves.toBe(true);

    expect(mockedRecordLtiLaunchNonceUse).toHaveBeenCalledWith(fakeDb, {
      nonce: "nonce-1",
      consumedAt: expect.any(String),
      expiresAt: expect.any(String),
    });
    const recorded = mockedRecordLtiLaunchNonceUse.mock.calls[0]?.[1] as
      | {
          consumedAt: string;
          expiresAt: string;
        }
      | undefined;

    expect(recorded).not.toBeUndefined();
    expect(Date.parse(recorded?.expiresAt ?? "")).toBeGreaterThan(
      Date.parse(recorded?.consumedAt ?? ""),
    );
  });

  it("round-trips valid dynamic registration sessions through the storage interface", async () => {
    const session = sampleDynamicRegistrationSession();
    mockedFindLtiDynamicRegistrationSessionById.mockResolvedValue(
      sampleDynamicRegistrationSessionRecord({
        dataJson: JSON.stringify(session),
      }),
    );
    const storage = new CredTrailLtiStorage(fakeDb);

    await expect(storage.getRegistrationSession("dynamic-registration-session-1")).resolves.toEqual(
      session,
    );
  });

  it("rejects malformed dynamic registration session JSON", async () => {
    mockedFindLtiDynamicRegistrationSessionById.mockResolvedValue(
      sampleDynamicRegistrationSessionRecord({
        dataJson: "{not-json",
      }),
    );
    const storage = new CredTrailLtiStorage(fakeDb);

    await expect(
      storage.getRegistrationSession("dynamic-registration-session-1"),
    ).resolves.toBeUndefined();
  });
});
