import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  mockedListLtiDeploymentsForIssuer,
  mockedListLtiIssuerRegistrations,
  mockedUpsertLtiDeployment,
  mockedUpsertLtiIssuerRegistration,
} = vi.hoisted(() => {
  return {
    mockedListLtiDeploymentsForIssuer: vi.fn(),
    mockedListLtiIssuerRegistrations: vi.fn(),
    mockedUpsertLtiDeployment: vi.fn(),
    mockedUpsertLtiIssuerRegistration: vi.fn(),
  };
});

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    listLtiDeploymentsForIssuer: mockedListLtiDeploymentsForIssuer,
    listLtiIssuerRegistrations: mockedListLtiIssuerRegistrations,
    upsertLtiDeployment: mockedUpsertLtiDeployment,
    upsertLtiIssuerRegistration: mockedUpsertLtiIssuerRegistration,
  };
});

import {
  LtiIssuerTenantConflictError,
  type LtiDeploymentRecord,
  type LtiIssuerRegistrationRecord,
  type SqlDatabase,
} from "@credtrail/db";
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

describe("CredTrailLtiStorage dynamic registration writes", () => {
  beforeEach(() => {
    mockedListLtiDeploymentsForIssuer.mockReset();
    mockedListLtiIssuerRegistrations.mockReset();
    mockedUpsertLtiDeployment.mockReset();
    mockedUpsertLtiIssuerRegistration.mockReset();
    mockedListLtiDeploymentsForIssuer.mockResolvedValue([]);
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
    ).rejects.toThrow("LTI issuer is already registered to a different tenant");
    expect(mockedUpsertLtiIssuerRegistration).toHaveBeenCalledTimes(1);
  });
});
