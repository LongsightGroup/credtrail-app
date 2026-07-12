import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    findAssertionById: vi.fn(),
    resolveAssertionLifecycleState: vi.fn(),
    findUserById: vi.fn(),
    listAllLtiIssuerRegistrations: vi.fn(),
    upsertLtiDeployment: vi.fn(),
  };
});

vi.mock("@credtrail/core-domain", async () => {
  const actual =
    await vi.importActual<typeof import("@credtrail/core-domain")>("@credtrail/core-domain");

  return {
    ...actual,
    getImmutableCredentialObject: vi.fn(),
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

vi.mock("./lti/credtrail-lti-tool", () => {
  const createTool = vi.fn(async () => ({
    handleLogin: vi.fn(async (input: Record<string, unknown>) => {
      const issuer = String(input.iss);
      const redirectUrl = new URL(`${issuer}/api/lti/authorize_redirect`);
      redirectUrl.searchParams.set("scope", "openid");
      redirectUrl.searchParams.set("response_type", "id_token");
      redirectUrl.searchParams.set("response_mode", "form_post");
      redirectUrl.searchParams.set("prompt", "none");
      redirectUrl.searchParams.set("client_id", String(input.client_id));
      redirectUrl.searchParams.set("redirect_uri", "http://localhost/v1/lti/launch");
      redirectUrl.searchParams.set("state", "mock-lti-state");
      redirectUrl.searchParams.set("nonce", "mock-lti-nonce");
      return redirectUrl.toString();
    }),
  }));

  return {
    createCredTrailLtiTool: createTool,
  };
});

import { type JsonObject, getImmutableCredentialObject } from "@credtrail/core-domain";
import {
  findAssertionById,
  resolveAssertionLifecycleState,
  listAllLtiIssuerRegistrations,
  type AssertionRecord,
  type LtiIssuerRegistrationRecord,
  type SqlDatabase,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { app } from "./index";

interface ErrorResponse {
  error: string;
}

const mockedFindAssertionById = vi.mocked(findAssertionById);
const mockedResolveAssertionLifecycleState = vi.mocked(resolveAssertionLifecycleState);
const mockedGetImmutableCredentialObject = vi.mocked(getImmutableCredentialObject);
const mockedListLtiIssuerRegistrations = vi.mocked(listAllLtiIssuerRegistrations);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  LTI_STATE_SIGNING_SECRET?: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
  };
};

const sampleAssertion = (overrides?: {
  revokedAt?: string | null;
  statusListIndex?: number | null;
}): AssertionRecord => {
  return {
    id: "tenant_123:assertion_456",
    tenantId: "tenant_123",
    publicId: "40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
    learnerProfileId: "lpr_123",
    badgeTemplateId: "badge_template_001",
    recipientIdentity: "learner@example.edu",
    recipientIdentityType: "email",
    vcR2Key: "tenants/tenant_123/assertions/tenant_123%3Aassertion_456.jsonld",
    statusListIndex: overrides?.statusListIndex === undefined ? 0 : overrides.statusListIndex,
    idempotencyKey: "idem_abc",
    issuedAt: "2026-02-10T22:00:00.000Z",
    issuedByUserId: "usr_123",
    revokedAt: overrides?.revokedAt ?? null,
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
  };
};

const sampleLtiIssuerRegistration = (
  overrides?: Partial<LtiIssuerRegistrationRecord>,
): LtiIssuerRegistrationRecord => {
  return {
    issuer: "https://canvas.example.edu",
    tenantId: "tenant_123",
    authorizationEndpoint: "https://canvas.example.edu/api/lti/authorize_redirect",
    clientId: "canvas-client-123",
    platformJwksEndpoint: null,
    tokenEndpoint: null,
    clientSecret: null,
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedFindAssertionById.mockReset();
  mockedResolveAssertionLifecycleState.mockReset();
  mockedResolveAssertionLifecycleState.mockResolvedValue({
    state: "active",
    source: "default_active",
    reasonCode: null,
    reason: null,
    transitionedAt: null,
    revokedAt: null,
  });
  mockedGetImmutableCredentialObject.mockReset();
  mockedListLtiIssuerRegistrations.mockReset();
  mockedListLtiIssuerRegistrations.mockResolvedValue([]);
});

describe("GET /credentials/v1/:credentialId/download", () => {
  beforeEach(() => {
    mockedFindAssertionById.mockReset();
    mockedGetImmutableCredentialObject.mockReset();
  });

  it("returns downloadable JSON-LD for a credential", async () => {
    const env = createEnv();
    const credential: JsonObject = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      type: ["VerifiableCredential", "OpenBadgeCredential"],
    };

    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      "/credentials/v1/tenant_123%3Aassertion_456/download",
      undefined,
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("content-type")).toContain("application/vc+ld+json");
    expect(response.headers.get("content-disposition")).toContain("attachment; filename=");
    expect(response.headers.get("x-credtrail-credential-state")).toBe("active");
    expect(body).toContain('"OpenBadgeCredential"');
  });

  it("returns suspended lifecycle headers for suspended credentials", async () => {
    const env = createEnv();
    const credential: JsonObject = {
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      type: ["VerifiableCredential"],
    };

    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);
    mockedResolveAssertionLifecycleState.mockResolvedValue({
      state: "suspended",
      source: "lifecycle_event",
      reasonCode: "administrative_hold",
      reason: "Suspended by institutional authority",
      transitionedAt: "2026-02-12T02:30:00.000Z",
      revokedAt: null,
    });

    const response = await app.request(
      "/credentials/v1/tenant_123%3Aassertion_456/download",
      undefined,
      env,
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("x-credtrail-credential-state")).toBe("suspended");
    expect(response.headers.get("x-credtrail-credential-reason")).toBe(
      "Suspended by institutional authority",
    );
  });

  it("keeps credential downloads available after LMS issuer migration", async () => {
    const env = createEnv();
    env.LTI_STATE_SIGNING_SECRET = "test-lti-state-secret";
    const targetLinkUri = "https://tool.example.edu/v1/lti/launch";
    const oldIssuer = "https://canvas-old.example.edu";
    const newIssuer = "https://canvas-new.example.edu";

    mockedListLtiIssuerRegistrations
      .mockResolvedValueOnce([
        sampleLtiIssuerRegistration({
          issuer: oldIssuer,
          clientId: "canvas-old-client",
          authorizationEndpoint: "https://canvas-old.example.edu/api/lti/authorize_redirect",
          platformJwksEndpoint: "https://canvas-old.example.edu/api/lti/security/jwks",
          tokenEndpoint: "https://canvas-old.example.edu/login/oauth2/token",
        }),
      ])
      .mockResolvedValueOnce([
        sampleLtiIssuerRegistration({
          issuer: newIssuer,
          clientId: "canvas-new-client",
          authorizationEndpoint: "https://canvas-new.example.edu/api/lti/authorize_redirect",
          platformJwksEndpoint: "https://canvas-new.example.edu/api/lti/security/jwks",
          tokenEndpoint: "https://canvas-new.example.edu/login/oauth2/token",
        }),
      ]);

    const oldLoginResponse = await app.request(
      "/v1/lti/oidc/login?iss=" +
        encodeURIComponent(oldIssuer) +
        "&login_hint=" +
        encodeURIComponent("old-login-hint") +
        "&target_link_uri=" +
        encodeURIComponent(targetLinkUri),
      undefined,
      env,
    );
    const oldLoginLocation = oldLoginResponse.headers.get("location");

    const newLoginResponse = await app.request(
      "/v1/lti/oidc/login?iss=" +
        encodeURIComponent(newIssuer) +
        "&login_hint=" +
        encodeURIComponent("new-login-hint") +
        "&target_link_uri=" +
        encodeURIComponent(targetLinkUri),
      undefined,
      env,
    );
    const newLoginLocation = newLoginResponse.headers.get("location");

    const credential: JsonObject = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      type: ["VerifiableCredential", "OpenBadgeCredential"],
    };

    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const downloadResponse = await app.request(
      "/credentials/v1/tenant_123%3Aassertion_456/download",
      undefined,
      env,
    );
    const downloadBody = await downloadResponse.text();

    expect(oldLoginResponse.status).toBe(302);
    expect(newLoginResponse.status).toBe(302);
    expect(oldLoginLocation).not.toBeNull();
    expect(newLoginLocation).not.toBeNull();

    const oldRedirectUrl = new URL(oldLoginLocation ?? "");
    const newRedirectUrl = new URL(newLoginLocation ?? "");

    expect(oldRedirectUrl.origin + oldRedirectUrl.pathname).toBe(
      "https://canvas-old.example.edu/api/lti/authorize_redirect",
    );
    expect(newRedirectUrl.origin + newRedirectUrl.pathname).toBe(
      "https://canvas-new.example.edu/api/lti/authorize_redirect",
    );
    expect(downloadResponse.status).toBe(200);
    expect(downloadBody).toContain("OpenBadgeCredential");
  });

  it("returns 400 for invalid credential identifier", async () => {
    const env = createEnv();
    const response = await app.request("/credentials/v1/assertion_456/download", undefined, env);
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(400);
    expect(body.error).toBe("Invalid credential identifier");
    expect(mockedFindAssertionById).not.toHaveBeenCalled();
  });

  it("returns 404 when credential does not exist", async () => {
    const env = createEnv();
    mockedFindAssertionById.mockResolvedValue(null);

    const response = await app.request(
      "/credentials/v1/tenant_123%3Aassertion_456/download",
      undefined,
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(404);
    expect(body.error).toBe("Credential not found");
  });
});

describe("GET /credentials/v1/:credentialId/download.pdf", () => {
  beforeEach(() => {
    mockedFindAssertionById.mockReset();
    mockedGetImmutableCredentialObject.mockReset();
  });

  it("returns downloadable PDF for a credential", async () => {
    const env = createEnv();
    const credential: JsonObject = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      type: ["VerifiableCredential", "OpenBadgeCredential"],
    };

    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      "/credentials/v1/tenant_123%3Aassertion_456/download.pdf",
      undefined,
      env,
    );
    const bodyBuffer = await response.arrayBuffer();
    const bodyText = new TextDecoder().decode(bodyBuffer.slice(0, 5));

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("content-type")).toContain("application/pdf");
    expect(response.headers.get("content-disposition")).toContain("attachment; filename=");
    expect(response.headers.get("content-disposition")).toContain(".pdf");
    expect(response.headers.get("x-credtrail-credential-state")).toBe("active");
    expect(bodyText).toBe("%PDF-");
  });

  it("returns 400 for invalid credential identifier", async () => {
    const env = createEnv();
    const response = await app.request(
      "/credentials/v1/assertion_456/download.pdf",
      undefined,
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(400);
    expect(body.error).toBe("Invalid credential identifier");
    expect(mockedFindAssertionById).not.toHaveBeenCalled();
  });

  it("returns 404 when credential does not exist", async () => {
    const env = createEnv();
    mockedFindAssertionById.mockResolvedValue(null);

    const response = await app.request(
      "/credentials/v1/tenant_123%3Aassertion_456/download.pdf",
      undefined,
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(404);
    expect(body.error).toBe("Credential not found");
  });
});

describe("GET /credentials/v1/:credentialId/jsonld", () => {
  beforeEach(() => {
    mockedFindAssertionById.mockReset();
    mockedGetImmutableCredentialObject.mockReset();
  });

  it("returns non-attachment OB3 JSON-LD for a credential", async () => {
    const env = createEnv();
    const credential: JsonObject = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      type: ["VerifiableCredential", "OpenBadgeCredential"],
    };

    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      "/credentials/v1/tenant_123%3Aassertion_456/jsonld",
      undefined,
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("content-type")).toContain("application/vc+ld+json");
    expect(response.headers.get("content-disposition")).toBeNull();
    expect(response.headers.get("x-credtrail-credential-state")).toBe("active");
    expect(body).toContain('"OpenBadgeCredential"');
  });

  it("returns 400 for invalid credential identifier", async () => {
    const env = createEnv();
    const response = await app.request("/credentials/v1/assertion_456/jsonld", undefined, env);
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(400);
    expect(body.error).toBe("Invalid credential identifier");
    expect(mockedFindAssertionById).not.toHaveBeenCalled();
  });
});
