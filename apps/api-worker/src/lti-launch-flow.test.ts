import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setCookie } from "hono/cookie";

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    addLearnerIdentityAlias: vi.fn(),
    createAuthIdentityLink: vi.fn(),
    ensureTenantMembership: vi.fn(),
    findAuthIdentityLinkByAuthUserId: vi.fn(),
    findAuthIdentityLinkByCredtrailUserId: vi.fn(),
    findBadgeTemplateById: vi.fn(),
    findLearnerProfileByIdentity: vi.fn(),
    findUserById: vi.fn(),
    listBadgeTemplates: vi.fn(),
    listLtiIssuerRegistrations: vi.fn(),
    upsertLtiDeployment: vi.fn(),
    resolveLearnerProfileForIdentity: vi.fn(),
    upsertLtiResourceLinkPlacement: vi.fn(),
    upsertTenantMembershipRole: vi.fn(),
    upsertUserByEmail: vi.fn(),
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import {
  addLearnerIdentityAlias,
  createAuthIdentityLink,
  ensureTenantMembership,
  findAuthIdentityLinkByAuthUserId,
  findAuthIdentityLinkByCredtrailUserId,
  findBadgeTemplateById,
  findLearnerProfileByIdentity,
  findUserById,
  listBadgeTemplates,
  listLtiIssuerRegistrations,
  resolveLearnerProfileForIdentity,
  upsertLtiResourceLinkPlacement,
  upsertTenantMembershipRole,
  upsertUserByEmail,
  type LearnerProfileRecord,
  type LtiIssuerRegistrationRecord,
  type SqlDatabase,
  type TenantMembershipRecord,
} from "@credtrail/db";
import type { LTISession } from "@lti-tool/core";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { app } from "./index";

interface ErrorResponse {
  error: string;
}

const mockedAddLearnerIdentityAlias = vi.mocked(addLearnerIdentityAlias);
const mockedCreateAuthIdentityLink = vi.mocked(createAuthIdentityLink);
const mockedEnsureTenantMembership = vi.mocked(ensureTenantMembership);
const mockedFindAuthIdentityLinkByAuthUserId = vi.mocked(findAuthIdentityLinkByAuthUserId);
const mockedFindAuthIdentityLinkByCredtrailUserId = vi.mocked(
  findAuthIdentityLinkByCredtrailUserId,
);
const mockedFindBadgeTemplateById = vi.mocked(findBadgeTemplateById);
const mockedFindLearnerProfileByIdentity = vi.mocked(findLearnerProfileByIdentity);
const mockedFindUserById = vi.mocked(findUserById);
const mockedListBadgeTemplates = vi.mocked(listBadgeTemplates);
const mockedListLtiIssuerRegistrations = vi.mocked(listLtiIssuerRegistrations);
const mockedResolveLearnerProfileForIdentity = vi.mocked(resolveLearnerProfileForIdentity);
const mockedUpsertLtiResourceLinkPlacement = vi.mocked(upsertLtiResourceLinkPlacement);
const mockedUpsertTenantMembershipRole = vi.mocked(upsertTenantMembershipRole);
const mockedUpsertUserByEmail = vi.mocked(upsertUserByEmail);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);

interface AuthUserRow {
  id: string;
  email: string | null;
  email_verified: boolean;
}

interface AuthSessionRow {
  id: string;
  token: string;
  user_id: string;
  expires_at: string;
  ip_address: string | null;
  user_agent: string | null;
}

interface AuthIdentityLinkRow {
  id: string;
  authSystem: string;
  authUserId: string;
  authAccountId: string | null;
  credtrailUserId: string;
  emailSnapshot: string | null;
  createdAt: string;
  updatedAt: string;
}

const authUsers: AuthUserRow[] = [];
const authSessions: AuthSessionRow[] = [];
const authIdentityLinks: AuthIdentityLinkRow[] = [];

const coerceBoundText = (value: unknown): string => {
  if (typeof value === "string") {
    return value;
  }

  if (typeof value === "number" || typeof value === "bigint" || typeof value === "boolean") {
    return String(value);
  }

  return "";
};

const fakeDbPrepare = vi.fn((sql: string) => {
  const normalizedSql = sql.replace(/\s+/g, " ").trim();
  let params: unknown[] = [];

  return {
    bind(...boundParams: unknown[]) {
      params = boundParams;
      return this;
    },
    first: async <T>() => {
      if (
        normalizedSql.includes("FROM auth.user") &&
        normalizedSql.includes("LOWER(email) = LOWER(?)")
      ) {
        const email = coerceBoundText(params[0]).toLowerCase();
        const row =
          authUsers.find((candidate) => (candidate.email ?? "").toLowerCase() === email) ?? null;

        return row === null
          ? null
          : ({
              id: row.id,
              email: row.email,
              emailVerified: row.email_verified,
            } as T);
      }

      if (
        normalizedSql.includes("FROM auth.session AS session") &&
        normalizedSql.includes("WHERE session.token = ?")
      ) {
        const token = coerceBoundText(params[0]);
        const session = authSessions.find((candidate) => candidate.token === token) ?? null;
        const user =
          session === null
            ? null
            : (authUsers.find((candidate) => candidate.id === session.user_id) ?? null);

        return session === null
          ? null
          : ({
              sessionId: session.id,
              sessionToken: session.token,
              userId: session.user_id,
              expiresAt: session.expires_at,
              userEmail: user?.email ?? null,
              userEmailVerified: user?.email_verified ?? false,
            } as T);
      }

      throw new Error(`Unhandled fakeDb first() SQL: ${normalizedSql}`);
    },
    all: async <T>() => {
      return {
        success: true,
        meta: {},
        results: [] as T[],
      };
    },
    run: async () => {
      if (normalizedSql.includes("INSERT INTO auth.user")) {
        authUsers.push({
          id: coerceBoundText(params[0]),
          email: (params[1] as string | null | undefined) ?? null,
          email_verified: Boolean(params[2]),
        });
        return {
          success: true,
          meta: {},
        };
      }

      if (normalizedSql.includes("INSERT INTO auth.session")) {
        authSessions.push({
          id: coerceBoundText(params[0]),
          token: coerceBoundText(params[1]),
          user_id: coerceBoundText(params[2]),
          expires_at: coerceBoundText(params[3]),
          ip_address: (params[4] as string | null | undefined) ?? null,
          user_agent: (params[5] as string | null | undefined) ?? null,
        });
        return {
          success: true,
          meta: {},
        };
      }

      throw new Error(`Unhandled fakeDb run() SQL: ${normalizedSql}`);
    },
  };
});

const fakeDb = {
  prepare: fakeDbPrepare,
} as unknown as SqlDatabase;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  LTI_ISSUER_REGISTRY_JSON?: string;
  LTI_STATE_SIGNING_SECRET?: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
  };
};

const sampleUserRecord = (overrides?: {
  id?: string;
  email?: string;
}): { id: string; email: string } => {
  return {
    id: overrides?.id ?? "usr_123",
    email: overrides?.email ?? "learner@example.edu",
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
    allowUnsignedIdToken: false,
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleLearnerProfile = (overrides?: Partial<LearnerProfileRecord>): LearnerProfileRecord => {
  return {
    id: "lpr_123",
    tenantId: "tenant_123",
    subjectId: "urn:credtrail:learner:tenant_123:lpr_123",
    displayName: null,
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleTenantMembership = (
  overrides?: Partial<TenantMembershipRecord>,
): TenantMembershipRecord => {
  return {
    tenantId: "tenant_123",
    userId: "usr_123",
    role: "issuer",
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

interface MockedInternalAuthProvider {
  requestMagicLink: ReturnType<typeof vi.fn>;
  createMagicLinkSession: ReturnType<typeof vi.fn>;
  createLtiSession: ReturnType<typeof vi.fn>;
  resolveAuthenticatedPrincipal: ReturnType<typeof vi.fn>;
  resolveRequestedTenantContext: ReturnType<typeof vi.fn>;
  revokeCurrentSession: ReturnType<typeof vi.fn>;
}

const loadAppWithMockedAuthProviders = async (
  beforeImport?: () => void,
): Promise<{
  app: typeof app;
  betterAuthProvider: MockedInternalAuthProvider;
}> => {
  vi.resetModules();
  const betterAuthProvider: MockedInternalAuthProvider = {
    requestMagicLink: vi.fn(),
    createMagicLinkSession: vi.fn(),
    createLtiSession: vi.fn(
      (context: Parameters<typeof setCookie>[0], input: { tenantId: string; userId: string }) => {
        setCookie(context, "better-auth.session_token", "better-lti-session", {
          httpOnly: true,
          sameSite: "None",
          secure: true,
          path: "/",
        });
        return Promise.resolve({
          userId: input.userId,
          authSessionId: "ba_ses_adapter",
          authMethod: "better_auth" as const,
          expiresAt: "2026-02-11T22:00:00.000Z",
          browserSessionToken: "better-lti-session",
        });
      },
    ),
    resolveAuthenticatedPrincipal: vi.fn(() => Promise.resolve(null)),
    resolveRequestedTenantContext: vi.fn(() => Promise.resolve(null)),
    revokeCurrentSession: vi.fn(() => Promise.resolve()),
  };

  vi.doMock("./auth/better-auth-adapter", async () => {
    const actual = await vi.importActual<typeof import("./auth/better-auth-adapter")>(
      "./auth/better-auth-adapter",
    );

    return {
      ...actual,
      createBetterAuthProvider: vi.fn(() => betterAuthProvider),
    };
  });

  beforeImport?.();

  const { app: isolatedApp } = await import("./index");

  return {
    app: isolatedApp,
    betterAuthProvider,
  };
};

const sampleBadgeTemplate = (overrides?: {
  id?: string;
  title?: string;
  description?: string | null;
}): {
  id: string;
  tenantId: string;
  slug: string;
  title: string;
  description: string | null;
  criteriaUri: string | null;
  imageUri: string | null;
  createdByUserId: string | null;
  ownerOrgUnitId: string;
  governanceMetadataJson: string | null;
  isArchived: boolean;
  createdAt: string;
  updatedAt: string;
} => {
  return {
    id: overrides?.id ?? "badge_template_001",
    tenantId: "tenant_123",
    slug: "typescript-foundations",
    title: overrides?.title ?? "TypeScript Foundations",
    description: overrides?.description ?? "Awarded for completing TypeScript fundamentals.",
    criteriaUri: "https://example.edu/criteria",
    imageUri: "https://example.edu/image.png",
    createdByUserId: "usr_123",
    ownerOrgUnitId: "tenant_123:org:institution",
    governanceMetadataJson: null,
    isArchived: false,
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
  };
};

const bytesToBase64UrlForTest = (bytes: Uint8Array): string => {
  let raw = "";

  for (const byte of bytes) {
    raw += String.fromCharCode(byte);
  }

  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const compactJwsForTest = (input: {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
}): string => {
  const headerSegment = bytesToBase64UrlForTest(
    new TextEncoder().encode(JSON.stringify(input.header)),
  );
  const payloadSegment = bytesToBase64UrlForTest(
    new TextEncoder().encode(JSON.stringify(input.payload)),
  );
  return `${headerSegment}.${payloadSegment}.signature`;
};

const ltiClaim = {
  context: "https://purl.imsglobal.org/spec/lti/claim/context",
  custom: "https://purl.imsglobal.org/spec/lti/claim/custom",
  deepLinkingSettings: "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings",
  deploymentId: "https://purl.imsglobal.org/spec/lti/claim/deployment_id",
  messageType: "https://purl.imsglobal.org/spec/lti/claim/message_type",
  namesRoleService: "https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice",
  resourceLink: "https://purl.imsglobal.org/spec/lti/claim/resource_link",
  roles: "https://purl.imsglobal.org/spec/lti/claim/roles",
  targetLinkUri: "https://purl.imsglobal.org/spec/lti/claim/target_link_uri",
} as const;

const parseBase64UrlJsonSegmentForTest = (segment: string): Record<string, unknown> => {
  const normalized = segment.replace(/-/g, "+").replace(/_/g, "/");
  const padded = `${normalized}${"=".repeat((4 - (normalized.length % 4)) % 4)}`;
  const decoded = atob(padded);

  return JSON.parse(decoded) as Record<string, unknown>;
};

const parseCompactJwtPayloadForTest = (compactJwt: string): Record<string, unknown> => {
  const [, payloadSegment] = compactJwt.split(".");

  if (payloadSegment === undefined) {
    throw new Error("Test JWT is missing payload segment");
  }

  return parseBase64UrlJsonSegmentForTest(payloadSegment);
};

const stringClaimForTest = (value: unknown, fallback: string): string => {
  return typeof value === "string" ? value : fallback;
};

afterEach(() => {
  vi.doUnmock("./auth/better-auth-adapter");
  vi.doUnmock("./badges/direct-issue");
  vi.doUnmock("./lti/credtrail-lti-tool");
});

describe("LTI 1.3 core launch flow", () => {
  const issuer = "https://canvas.example.edu";
  const authorizationEndpoint = "https://canvas.example.edu/api/lti/authorize_redirect";
  const platformJwksEndpoint = "https://canvas.example.edu/api/lti/security/jwks";
  const tokenEndpoint = "https://canvas.example.edu/login/oauth2/token";
  const clientId = "canvas-client-123";
  const tenantId = "tenant_123";
  const targetLinkUri = "https://tool.example.edu/v1/lti/launch";
  const deploymentId = "deployment-123";
  const linkedUserId = "usr_lti_123";

  beforeEach(() => {
    authUsers.length = 0;
    authSessions.length = 0;
    authIdentityLinks.length = 0;
    fakeDbPrepare.mockClear();
    mockedCreatePostgresDatabase.mockReset();
    mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
    mockedCreateAuthIdentityLink.mockReset();
    mockedCreateAuthIdentityLink.mockImplementation(
      async (_db, input): Promise<(typeof authIdentityLinks)[number]> => {
        const link = {
          id: "ail_123",
          authSystem: input.authSystem,
          authUserId: input.authUserId,
          authAccountId: input.authAccountId ?? null,
          credtrailUserId: input.credtrailUserId,
          emailSnapshot: input.emailSnapshot ?? null,
          createdAt: "2026-02-10T22:00:00.000Z",
          updatedAt: "2026-02-10T22:00:00.000Z",
        };
        authIdentityLinks.push(link);
        return link;
      },
    );
    mockedListLtiIssuerRegistrations.mockReset();
    mockedListLtiIssuerRegistrations.mockResolvedValue([]);
    mockedFindAuthIdentityLinkByAuthUserId.mockReset();
    mockedFindAuthIdentityLinkByAuthUserId.mockImplementation(
      async (_db, authSystem, authUserId) => {
        return (
          authIdentityLinks.find(
            (candidate) =>
              candidate.authSystem === authSystem && candidate.authUserId === authUserId,
          ) ?? null
        );
      },
    );
    mockedFindAuthIdentityLinkByCredtrailUserId.mockReset();
    mockedFindAuthIdentityLinkByCredtrailUserId.mockImplementation(
      async (_db, authSystem, credtrailUserId) => {
        return (
          authIdentityLinks.find(
            (candidate) =>
              candidate.authSystem === authSystem && candidate.credtrailUserId === credtrailUserId,
          ) ?? null
        );
      },
    );
    mockedListBadgeTemplates.mockReset();
    mockedListBadgeTemplates.mockResolvedValue([sampleBadgeTemplate()]);
    mockedFindBadgeTemplateById.mockReset();
    mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
    mockedUpsertLtiResourceLinkPlacement.mockReset();
    mockedUpsertLtiResourceLinkPlacement.mockResolvedValue({
      id: "lti_place_123",
      tenantId,
      issuer,
      clientId,
      deploymentId,
      contextId: "course-123",
      resourceLinkId: "resource-link-123",
      badgeTemplateId: "badge_template_001",
      createdByUserId: linkedUserId,
      createdAt: "2026-02-10T22:00:00.000Z",
      updatedAt: "2026-02-10T22:00:00.000Z",
    });
    mockedResolveLearnerProfileForIdentity.mockReset();
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedFindLearnerProfileByIdentity.mockReset();
    mockedFindLearnerProfileByIdentity.mockResolvedValue(null);
    mockedFindUserById.mockReset();
    mockedFindUserById.mockResolvedValue(
      sampleUserRecord({
        id: linkedUserId,
      }),
    );
    mockedAddLearnerIdentityAlias.mockReset();
    mockedUpsertUserByEmail.mockReset();
    mockedUpsertUserByEmail.mockResolvedValue(
      sampleUserRecord({
        id: linkedUserId,
      }),
    );
    mockedEnsureTenantMembership.mockReset();
    mockedEnsureTenantMembership.mockResolvedValue({
      membership: sampleTenantMembership({
        tenantId,
        userId: linkedUserId,
        role: "viewer",
      }),
      created: true,
    });
    mockedUpsertTenantMembershipRole.mockReset();
    mockedUpsertTenantMembershipRole.mockResolvedValue({
      membership: sampleTenantMembership({
        tenantId,
        userId: linkedUserId,
        role: "issuer",
      }),
      previousRole: "viewer",
      changed: true,
    });
  });

  const createLtiEnv = (): ReturnType<typeof createEnv> => {
    const env = createEnv();
    env.LTI_ISSUER_REGISTRY_JSON = JSON.stringify({
      [issuer]: {
        authorizationEndpoint,
        clientId,
        tenantId,
        platformJwksEndpoint,
        tokenEndpoint,
      },
    });
    env.LTI_STATE_SIGNING_SECRET = "test-lti-state-secret";
    return env;
  };

  const createUnsignedOnlyLtiEnv = (): ReturnType<typeof createEnv> => {
    const env = createEnv();
    env.LTI_ISSUER_REGISTRY_JSON = JSON.stringify({
      [issuer]: {
        authorizationEndpoint,
        clientId,
        tenantId,
      },
    });
    env.LTI_STATE_SIGNING_SECRET = "test-lti-state-secret";
    return env;
  };

  const ltiSessionFromClaims = (claims: Record<string, unknown>): LTISession => {
    const context = claims[ltiClaim.context] as Record<string, unknown> | undefined;
    const roles = Array.isArray(claims[ltiClaim.roles]) ? (claims[ltiClaim.roles] as string[]) : [];
    const normalizedRoles = roles.map((role) => role.toLowerCase());
    const isInstructor = normalizedRoles.some((role) => role.includes("#instructor"));
    const isStudent = normalizedRoles.some(
      (role) => role.includes("#learner") || role.includes("#student"),
    );
    const nrpsClaim = claims[ltiClaim.namesRoleService] as Record<string, unknown> | undefined;
    const deepLinkingSettings = claims[ltiClaim.deepLinkingSettings] as
      | Record<string, unknown>
      | undefined;
    const userName = typeof claims.name === "string" ? claims.name : undefined;
    const userEmail = typeof claims.email === "string" ? claims.email : undefined;
    const contextId = typeof context?.id === "string" ? context.id : undefined;
    const contextLabel = typeof context?.label === "string" ? context.label : undefined;
    const contextTitle = typeof context?.title === "string" ? context.title : undefined;
    const resourceLink = claims[ltiClaim.resourceLink] as Record<string, unknown> | undefined;
    const resourceLinkId = typeof resourceLink?.id === "string" ? resourceLink.id : undefined;
    const resourceLinkTitle =
      typeof resourceLink?.title === "string" ? resourceLink.title : undefined;
    const deepLinkingData =
      typeof deepLinkingSettings?.data === "string" ? deepLinkingSettings.data : undefined;

    return {
      jwtPayload: claims,
      id: "lti-session-test",
      user: {
        id: stringClaimForTest(claims.sub, "lti-user"),
        ...(userName === undefined ? {} : { name: userName }),
        ...(userEmail === undefined ? {} : { email: userEmail }),
        roles,
      },
      context: {
        id: contextId ?? "",
        label: contextLabel ?? "",
        title: contextTitle ?? "",
      },
      platform: {
        issuer,
        clientId,
        deploymentId: stringClaimForTest(claims[ltiClaim.deploymentId], deploymentId),
        name: "Canvas",
      },
      launch: {
        target: stringClaimForTest(claims[ltiClaim.targetLinkUri], targetLinkUri),
      },
      ...(resourceLinkId === undefined
        ? {}
        : {
            resourceLink: {
              id: resourceLinkId,
              ...(resourceLinkTitle === undefined ? {} : { title: resourceLinkTitle }),
            },
          }),
      services: {
        ...(nrpsClaim === undefined
          ? {}
          : {
              nrps: {
                membershipUrl: stringClaimForTest(nrpsClaim.context_memberships_url, ""),
                versions: Array.isArray(nrpsClaim.service_versions)
                  ? (nrpsClaim.service_versions as string[])
                  : [],
              },
            }),
        ...(deepLinkingSettings === undefined
          ? {}
          : {
              deepLinking: {
                returnUrl: stringClaimForTest(deepLinkingSettings.deep_link_return_url, ""),
                acceptTypes: Array.isArray(deepLinkingSettings.accept_types)
                  ? (deepLinkingSettings.accept_types as string[])
                  : [],
                acceptPresentationDocumentTargets: [],
                acceptMultiple: false,
                autoCreate: false,
                ...(deepLinkingData === undefined ? {} : { data: deepLinkingData }),
              },
            }),
      },
      customParameters: {},
      isAdmin: false,
      isInstructor,
      isStudent,
      isAssignmentAndGradesAvailable: false,
      isDeepLinkingAvailable: deepLinkingSettings !== undefined,
      isNameAndRolesAvailable: nrpsClaim !== undefined,
    } satisfies LTISession;
  };

  const loadAppWithMockedSignedLtiTool = async (options?: {
    authorizationEndpoint?: string;
    getMembers?: ReturnType<typeof vi.fn>;
    getSession?: ReturnType<typeof vi.fn>;
    issueBadgeForTenant?: ReturnType<typeof vi.fn>;
  }): Promise<
    Awaited<ReturnType<typeof loadAppWithMockedAuthProviders>> & {
      ltiTool: {
        handleLogin: ReturnType<typeof vi.fn>;
        verifyLaunch: ReturnType<typeof vi.fn>;
        createSession: ReturnType<typeof vi.fn>;
        getSession: ReturnType<typeof vi.fn>;
        getMembers: ReturnType<typeof vi.fn>;
      };
    }
  > => {
    let latestSession: LTISession | null = null;
    const ltiTool = {
      handleLogin: vi.fn(async (input: Record<string, unknown>) => {
        const redirectUrl = new URL(options?.authorizationEndpoint ?? authorizationEndpoint);
        redirectUrl.searchParams.set("scope", "openid");
        redirectUrl.searchParams.set("response_type", "id_token");
        redirectUrl.searchParams.set("response_mode", "form_post");
        redirectUrl.searchParams.set("prompt", "none");
        redirectUrl.searchParams.set("client_id", stringClaimForTest(input.client_id, clientId));
        redirectUrl.searchParams.set("redirect_uri", "http://localhost/v1/lti/launch");
        redirectUrl.searchParams.set("state", "mock-lti-state");
        redirectUrl.searchParams.set("nonce", "mock-lti-nonce");
        return redirectUrl.toString();
      }),
      verifyLaunch: vi.fn(async (idToken: string) => parseCompactJwtPayloadForTest(idToken)),
      createSession: vi.fn(async (claims: Record<string, unknown>) => {
        latestSession = ltiSessionFromClaims(claims);
        return latestSession;
      }),
      getSession:
        options?.getSession ??
        vi.fn(async (sessionId: string) =>
          latestSession !== null && latestSession.id === sessionId ? latestSession : undefined,
        ),
      getMembers: options?.getMembers ?? vi.fn().mockResolvedValue([]),
    };
    const result = await loadAppWithMockedAuthProviders(() => {
      if (options?.issueBadgeForTenant !== undefined) {
        vi.doMock("./badges/direct-issue", async () => {
          const actual =
            await vi.importActual<typeof import("./badges/direct-issue")>("./badges/direct-issue");

          return {
            ...actual,
            createIssueBadgeForTenant: vi.fn(() => options.issueBadgeForTenant),
          };
        });
      }

      vi.doMock("./lti/credtrail-lti-tool", () => {
        return {
          createCredTrailLtiTool: vi.fn(async () => ltiTool),
        };
      });
    });

    return {
      ...result,
      ltiTool,
    };
  };

  it("establishes a Better Auth browser session for LTI launches without legacy session writes", async () => {
    const { app: isolatedApp, betterAuthProvider } = await loadAppWithMockedSignedLtiTool();
    const env = createLtiEnv();
    const loginResponse = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}&lti_deployment_id=${encodeURIComponent(
        deploymentId,
      )}`,
      undefined,
      env,
    );
    const loginLocation = loginResponse.headers.get("location");
    const loginUrl = new URL(loginLocation ?? "");
    const state = loginUrl.searchParams.get("state") ?? "";
    const nonce = loginUrl.searchParams.get("nonce") ?? "";
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: "RS256",
        typ: "JWT",
      },
      payload: {
        iss: issuer,
        sub: "user-123",
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce,
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deploymentId,
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": targetLinkUri,
        "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
          id: "resource-link-123",
        },
        "https://purl.imsglobal.org/spec/lti/claim/roles": [
          "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor",
        ],
        "https://purl.imsglobal.org/spec/lti/claim/context": {
          id: "course-123",
          label: "TS101",
          title: "TypeScript 101",
        },
        name: "Instructor Example",
      },
    });

    const response = await isolatedApp.request(
      "/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: idToken,
          state,
        }).toString(),
      },
      env,
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("set-cookie") ?? "").toContain(
      "better-auth.session_token=better-lti-session",
    );
    expect(response.headers.get("set-cookie") ?? "").toContain("SameSite=None");
    expect(response.headers.get("set-cookie") ?? "").toContain("Secure");
    const body = await response.text();
    expect(body).toContain("lti_session_handoff=");
    expect(body).toContain('target="_blank"');
    expect(betterAuthProvider.createLtiSession).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        tenantId,
        userId: linkedUserId,
      }),
    );
  });

  it("redirects OIDC login initiation to issuer authorization endpoint with required parameters", async () => {
    const env = createLtiEnv();
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    const response = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}&lti_deployment_id=${encodeURIComponent(
        deploymentId,
      )}`,
      undefined,
      env,
    );

    expect(response.status).toBe(302);
    const location = response.headers.get("location");
    expect(location).not.toBeNull();

    const redirectUrl = new URL(location ?? "");
    expect(`${redirectUrl.origin}${redirectUrl.pathname}`).toBe(authorizationEndpoint);
    expect(redirectUrl.searchParams.get("scope")).toBe("openid");
    expect(redirectUrl.searchParams.get("response_type")).toBe("id_token");
    expect(redirectUrl.searchParams.get("response_mode")).toBe("form_post");
    expect(redirectUrl.searchParams.get("prompt")).toBe("none");
    expect(redirectUrl.searchParams.get("client_id")).toBe(clientId);
    expect(redirectUrl.searchParams.get("redirect_uri")).toBe("http://localhost/v1/lti/launch");
    expect(redirectUrl.searchParams.get("state")).toBeTruthy();
    expect(redirectUrl.searchParams.get("nonce")).toBeTruthy();
  });

  it("uses LTI postMessage storage before OIDC redirect when the platform advertises storage support", async () => {
    const env = createLtiEnv();
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    const response = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}&lti_deployment_id=${encodeURIComponent(
        deploymentId,
      )}&lti_storage_target=${encodeURIComponent("_parent")}`,
      undefined,
      env,
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("location")).toBeNull();

    const body = await response.text();
    const scriptMatch =
      /<script[^>]*src="([^"]*\/assets\/ui\/lti-post-message-storage\.[^"]+\.js)"[^>]*><\/script>/.exec(
        body,
      );
    const scriptPath = scriptMatch?.[1] ?? null;

    expect(scriptPath).not.toBeNull();
    expect(body).toContain('data-state="mock-lti-state"');
    expect(body).toContain('data-nonce="mock-lti-nonce"');
    expect(body).toContain(`data-platform-origin="${new URL(authorizationEndpoint).origin}"`);
    expect(body).toContain('data-storage-target="_parent"');

    const scriptResponse = await isolatedApp.request(scriptPath ?? "", undefined, env);
    const script = await scriptResponse.text();

    expect(scriptResponse.status).toBe(200);
    expect(scriptResponse.headers.get("cache-control")).toContain("immutable");
    expect(script).toContain("lti.put_data");
    expect(script).toContain("org.sakailms.lti.prelaunch");
    expect(script).toContain("JSON.stringify(message)");
    expect(script).toContain("JSON.parse(message)");
  });

  it("uses DB-backed issuer registrations when env registry is not configured", async () => {
    const env = createEnv();
    env.LTI_STATE_SIGNING_SECRET = "test-lti-state-secret";
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    mockedListLtiIssuerRegistrations.mockResolvedValue([
      sampleLtiIssuerRegistration({
        issuer,
        tenantId,
        clientId,
        authorizationEndpoint,
        platformJwksEndpoint,
        tokenEndpoint,
      }),
    ]);

    const response = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}`,
      undefined,
      env,
    );

    expect(response.status).toBe(302);
    const location = response.headers.get("location");
    expect(location).not.toBeNull();

    const redirectUrl = new URL(location ?? "");
    expect(`${redirectUrl.origin}${redirectUrl.pathname}`).toBe(authorizationEndpoint);
    expect(redirectUrl.searchParams.get("client_id")).toBe(clientId);
  });

  it("prefers DB issuer registrations over env defaults for the same issuer", async () => {
    const dbClientId = "db-client-777";
    const dbAuthorizationEndpoint = "https://canvas.example.edu/db/authorize_redirect";
    const env = createLtiEnv();
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool({
      authorizationEndpoint: dbAuthorizationEndpoint,
    });
    env.LTI_ISSUER_REGISTRY_JSON = JSON.stringify({
      [issuer]: {
        authorizationEndpoint: "https://canvas.example.edu/env/authorize_redirect",
        clientId: "env-client-123",
        tenantId,
        platformJwksEndpoint,
        tokenEndpoint,
      },
    });
    mockedListLtiIssuerRegistrations.mockResolvedValue([
      sampleLtiIssuerRegistration({
        issuer,
        tenantId,
        clientId: dbClientId,
        authorizationEndpoint: dbAuthorizationEndpoint,
        platformJwksEndpoint,
        tokenEndpoint,
      }),
    ]);

    const response = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}&client_id=${encodeURIComponent(dbClientId)}`,
      undefined,
      env,
    );

    expect(response.status).toBe(302);
    const location = response.headers.get("location");
    expect(location).not.toBeNull();

    const redirectUrl = new URL(location ?? "");
    expect(`${redirectUrl.origin}${redirectUrl.pathname}`).toBe(dbAuthorizationEndpoint);
    expect(redirectUrl.searchParams.get("client_id")).toBe(dbClientId);
  });

  it("accepts an instructor launch and renders launch completion page", async () => {
    const env = createLtiEnv();
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    const loginResponse = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}&lti_deployment_id=${encodeURIComponent(
        deploymentId,
      )}`,
      undefined,
      env,
    );
    const loginLocation = loginResponse.headers.get("location");
    const loginUrl = new URL(loginLocation ?? "");
    const state = loginUrl.searchParams.get("state") ?? "";
    const nonce = loginUrl.searchParams.get("nonce") ?? "";
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: "RS256",
        typ: "JWT",
      },
      payload: {
        iss: issuer,
        sub: "user-123",
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce,
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deploymentId,
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": targetLinkUri,
        "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
          id: "resource-link-123",
        },
        "https://purl.imsglobal.org/spec/lti/claim/context": {
          id: "course-123",
          label: "TS101",
          title: "TypeScript 101",
        },
        "https://purl.imsglobal.org/spec/lti/claim/custom": {
          badgeTemplateId: "badge_template_001",
        },
        "https://purl.imsglobal.org/spec/lti/claim/roles": [
          "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor",
        ],
      },
    });

    const response = await isolatedApp.request(
      "/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: idToken,
          state,
        }).toString(),
      },
      env,
    );
    const body = await response.text();
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("set-cookie")).toContain("better-auth.session_token=");
    expect(body).toContain("LTI 1.3 launch complete");
    expect(body).toContain("Instructor");
    expect(body).toContain("issuer");
    expect(body).toContain("LtiResourceLinkRequest");
    expect(body).toContain("/tenants/tenant_123/learner/dashboard");
    expect(body).toContain("lti_session_handoff=");
    expect(body).toContain('target="_blank"');
    expect(body).toContain("/assets/ui/foundation.");
    expect(body).toContain("/assets/ui/lti-pages.");
    expect(body).not.toContain(".lti-launch__hero {");
    expect(mockedResolveLearnerProfileForIdentity).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      identityType: "saml_subject",
      identityValue: "https://canvas.example.edu::user-123",
    });
    expect(mockedUpsertUserByEmail).toHaveBeenCalledWith(
      fakeDb,
      expect.stringContaining("@credtrail-lti.local"),
    );
    expect(mockedEnsureTenantMembership).toHaveBeenCalledWith(fakeDb, tenantId, linkedUserId);
    expect(mockedUpsertTenantMembershipRole).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      userId: linkedUserId,
      role: "issuer",
    });
    expect(mockedUpsertLtiResourceLinkPlacement).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      issuer,
      clientId,
      deploymentId,
      contextId: "course-123",
      resourceLinkId: "resource-link-123",
      badgeTemplateId: "badge_template_001",
      createdByUserId: linkedUserId,
    });
  });

  it("rejects resource-link placement when badge template is not tenant-owned and active", async () => {
    mockedFindBadgeTemplateById.mockResolvedValue(null);
    const env = createLtiEnv();
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    const loginResponse = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}&lti_deployment_id=${encodeURIComponent(
        deploymentId,
      )}`,
      undefined,
      env,
    );
    const loginUrl = new URL(loginResponse.headers.get("location") ?? "");
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: "RS256",
        typ: "JWT",
      },
      payload: {
        iss: issuer,
        sub: "user-tenant-cross",
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce: loginUrl.searchParams.get("nonce") ?? "",
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deploymentId,
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": targetLinkUri,
        "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
          id: "resource-link-cross-tenant",
        },
        "https://purl.imsglobal.org/spec/lti/claim/custom": {
          badgeTemplateId: "badge_template_other_tenant",
        },
        "https://purl.imsglobal.org/spec/lti/claim/roles": [
          "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor",
        ],
      },
    });

    const response = await isolatedApp.request(
      "/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: idToken,
          state: loginUrl.searchParams.get("state") ?? "",
        }).toString(),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(400);
    expect(body.error).toContain("badge template is not available");
    expect(mockedFindBadgeTemplateById).toHaveBeenCalledWith(
      fakeDb,
      tenantId,
      "badge_template_other_tenant",
    );
    expect(mockedUpsertLtiResourceLinkPlacement).not.toHaveBeenCalled();
    expect(mockedResolveLearnerProfileForIdentity).not.toHaveBeenCalled();
  });

  it("pulls NRPS roster for instructor launch and renders bulk issuance view", async () => {
    const env = createLtiEnv();
    const rosterTargetLinkUri = `${targetLinkUri}?badgeTemplateId=badge_template_001`;
    const getMembers = vi.fn().mockResolvedValue([
      {
        userId: "learner-001",
        name: "Learner One",
        email: "learner-one@example.edu",
        lisPersonSourcedId: "sourced-learner-001",
        roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
        status: "Active",
      },
      {
        userId: "teacher-001",
        name: "Instructor One",
        roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"],
        status: "Active",
      },
    ]);
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool({ getMembers });
    const loginResponse = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(rosterTargetLinkUri)}&lti_deployment_id=${encodeURIComponent(
        deploymentId,
      )}`,
      undefined,
      env,
    );
    const loginLocation = loginResponse.headers.get("location");
    const loginUrl = new URL(loginLocation ?? "");
    const state = loginUrl.searchParams.get("state") ?? "";
    const nonce = loginUrl.searchParams.get("nonce") ?? "";
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: "RS256",
        typ: "JWT",
      },
      payload: {
        iss: issuer,
        sub: "instructor-001",
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce,
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deploymentId,
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": rosterTargetLinkUri,
        "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
          id: "resource-link-nrps-1",
        },
        "https://purl.imsglobal.org/spec/lti/claim/context": {
          id: "course-42",
          title: "Course 42",
        },
        "https://purl.imsglobal.org/spec/lti/claim/roles": [
          "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor",
        ],
        "https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice": {
          context_memberships_url: "https://canvas.example.edu/api/lti/courses/42/names_and_roles",
          service_versions: ["2.0"],
        },
      },
    });

    const response = await isolatedApp.request(
      "/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: idToken,
          state,
        }).toString(),
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Issue badges from Sakai roster");
    expect(body).toContain("Loaded 1 learner members from LMS NRPS roster.");
    expect(body).toContain("badge_template_001");
    expect(body).toContain("learner-one@example.edu");
    expect(body).toContain('action="/v1/lti/resource-link/issue"');
    expect(body).toContain('name="issuance_action_token"');
    expect(body).toContain('name="learner_user_id"');
    expect(body).toContain("Issue selected badges");
    expect(getMembers).toHaveBeenCalledTimes(1);
  });

  it("issues selected Sakai roster learners through the LTI resource-link action", async () => {
    const env = createLtiEnv();
    const rosterTargetLinkUri = `${targetLinkUri}?badgeTemplateId=badge_template_001`;
    const getMembers = vi.fn().mockResolvedValue([
      {
        userId: "learner-001",
        name: "Learner One",
        email: "learner-one@example.edu",
        lisPersonSourcedId: "sourced-learner-001",
        roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
        status: "Active",
      },
      {
        userId: "learner-no-email",
        name: "Learner No Email",
        roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
        status: "Active",
      },
    ]);
    const issueBadgeForTenant = vi.fn(async () => ({
      status: "issued" as const,
      tenantId,
      assertionId: "assertion_lti_001",
      idempotencyKey: "lti:digest",
      vcR2Key: "tenant_123/assertion_lti_001.json",
      credential: {},
    }));
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool({
      getMembers,
      issueBadgeForTenant,
    });
    const loginResponse = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(rosterTargetLinkUri)}&lti_deployment_id=${encodeURIComponent(
        deploymentId,
      )}`,
      undefined,
      env,
    );
    const loginUrl = new URL(loginResponse.headers.get("location") ?? "");
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: "RS256",
        typ: "JWT",
      },
      payload: {
        iss: issuer,
        sub: "instructor-001",
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce: loginUrl.searchParams.get("nonce") ?? "",
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deploymentId,
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": rosterTargetLinkUri,
        "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
          id: "resource-link-nrps-1",
        },
        "https://purl.imsglobal.org/spec/lti/claim/context": {
          id: "course-42",
          title: "Course 42",
        },
        "https://purl.imsglobal.org/spec/lti/claim/roles": [
          "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor",
        ],
        "https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice": {
          context_memberships_url: "https://canvas.example.edu/api/lti/courses/42/names_and_roles",
          service_versions: ["2.0"],
        },
        email: "instructor@example.edu",
      },
    });
    const launchResponse = await isolatedApp.request(
      "/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: idToken,
          state: loginUrl.searchParams.get("state") ?? "",
        }).toString(),
      },
      env,
    );
    const launchBody = await launchResponse.text();
    const actionToken = /name="issuance_action_token" value="([^"]+)"/.exec(launchBody)?.[1];

    expect(actionToken).toBeTruthy();

    const issueResponse = await isolatedApp.request(
      "/v1/lti/resource-link/issue",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams([
          ["issuance_action_token", actionToken ?? ""],
          ["learner_user_id", "learner-001"],
          ["learner_user_id", "learner-no-email"],
          ["learner_user_id", "forged-learner"],
        ]).toString(),
      },
      env,
    );
    const issueBody = await issueResponse.text();

    expect(issueResponse.status).toBe(200);
    expect(issueBody).toContain("Badge issuance complete");
    expect(issueBody).toContain("Badge issued.");
    expect(issueBody).toContain("Sakai did not provide an email address.");
    expect(issueBody).toContain("Learner is not present in the current Sakai learner roster.");
    expect(issueBadgeForTenant).toHaveBeenCalledTimes(1);
    expect(issueBadgeForTenant).toHaveBeenCalledWith(
      expect.anything(),
      tenantId,
      expect.objectContaining({
        badgeTemplateId: "badge_template_001",
        recipientIdentity: "learner-one@example.edu",
        recipientIdentityType: "email",
        recipientIdentifiers: [
          {
            identifierType: "sourcedId",
            identifier: "sourced-learner-001",
          },
        ],
        idempotencyKey: expect.stringMatching(/^lti:[a-f0-9]{64}$/),
      }),
      linkedUserId,
      {
        recipientDisplayName: "Learner One",
      },
    );
    expect(getMembers).toHaveBeenCalledTimes(2);
  });

  it("rejects LTI roster issuance without a valid action token", async () => {
    const env = createLtiEnv();
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    const response = await isolatedApp.request(
      "/v1/lti/resource-link/issue",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          issuance_action_token: "invalid-token",
          learner_user_id: "learner-001",
        }).toString(),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(403);
    expect(body.error).toContain("invalid or expired");
  });

  it("accepts signed launch payloads with multiple audiences and normalizes service session client id", async () => {
    const env = createLtiEnv();
    env.LTI_ISSUER_REGISTRY_JSON = JSON.stringify({
      [issuer]: {
        authorizationEndpoint,
        clientId,
        tenantId,
        platformJwksEndpoint: "https://canvas.example.edu/api/lti/security/jwks",
        tokenEndpoint: "https://canvas.example.edu/login/oauth2/token",
      },
    });
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const launchPayload = {
      iss: issuer,
      sub: "instructor-multi-aud",
      aud: ["other-client", clientId],
      exp: nowEpochSeconds + 300,
      iat: nowEpochSeconds - 10,
      nonce: "signed-nonce",
      "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deploymentId,
      "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
      "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
      "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": targetLinkUri,
      "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
        id: "resource-link-signed-multi-aud",
      },
      "https://purl.imsglobal.org/spec/lti/claim/roles": [
        "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor",
      ],
      "https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice": {
        context_memberships_url: "https://canvas.example.edu/api/lti/courses/42/names_and_roles",
        service_versions: ["2.0"],
      },
    };
    const idToken = compactJwsForTest({
      header: {
        alg: "RS256",
        typ: "JWT",
      },
      payload: launchPayload,
    });
    const createSession = vi.fn().mockResolvedValue({
      jwtPayload: launchPayload,
      id: "lti-session-multi-aud",
      user: {
        id: "instructor-multi-aud",
        roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"],
      },
      context: {
        id: "course-42",
        label: "TS101",
        title: "TypeScript 101",
      },
      platform: {
        issuer,
        clientId: "other-client",
        deploymentId,
        name: "Canvas",
      },
      launch: {
        target: targetLinkUri,
      },
      services: {
        nrps: {
          membershipUrl: "https://canvas.example.edu/api/lti/courses/42/names_and_roles",
          versions: ["2.0"],
        },
      },
      customParameters: {},
      isAdmin: false,
      isInstructor: true,
      isStudent: false,
      isAssignmentAndGradesAvailable: false,
      isDeepLinkingAvailable: false,
      isNameAndRolesAvailable: true,
    } satisfies LTISession);
    const getMembers = vi.fn().mockResolvedValue([
      {
        userId: "learner-001",
        name: "Learner One",
        email: "learner-one@example.edu",
        lisPersonSourcedId: "sourced-learner-001",
        roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
        status: "Active",
      },
    ]);
    const { app: isolatedApp } = await loadAppWithMockedAuthProviders(() => {
      vi.doMock("./lti/credtrail-lti-tool", () => {
        return {
          createCredTrailLtiTool: vi.fn(async () => ({
            verifyLaunch: vi.fn().mockResolvedValue(launchPayload),
            createSession,
            getMembers,
          })),
        };
      });
    });

    const response = await isolatedApp.request(
      "/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: idToken,
          state: "opaque-core-state",
        }).toString(),
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Loaded 1 learner members from LMS NRPS roster.");
    expect(createSession).toHaveBeenCalledWith(launchPayload);
    expect(getMembers).toHaveBeenCalledWith(
      expect.objectContaining({
        platform: expect.objectContaining({
          clientId,
        }),
      }),
    );
  });

  it("renders unavailable NRPS state when launch omits the service claim", async () => {
    const env = createLtiEnv();
    const rosterTargetLinkUri = `${targetLinkUri}?badgeTemplateId=badge_template_001`;
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    const loginResponse = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(rosterTargetLinkUri)}&lti_deployment_id=${encodeURIComponent(
        deploymentId,
      )}`,
      undefined,
      env,
    );
    const loginLocation = loginResponse.headers.get("location");
    const loginUrl = new URL(loginLocation ?? "");
    const state = loginUrl.searchParams.get("state") ?? "";
    const nonce = loginUrl.searchParams.get("nonce") ?? "";
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: "RS256",
        typ: "JWT",
      },
      payload: {
        iss: issuer,
        sub: "instructor-002",
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce,
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deploymentId,
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": rosterTargetLinkUri,
        "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
          id: "resource-link-nrps-2",
        },
        "https://purl.imsglobal.org/spec/lti/claim/roles": [
          "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor",
        ],
      },
    });

    const response = await isolatedApp.request(
      "/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: idToken,
          state,
        }).toString(),
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Issue badges from Sakai roster");
    expect(body).toContain("LMS launch did not include NRPS names/roles service claim details.");
  });

  it("accepts a learner launch and links local account session with email claim", async () => {
    const env = createLtiEnv();
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    const loginResponse = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}`,
      undefined,
      env,
    );
    const loginLocation = loginResponse.headers.get("location");
    const loginUrl = new URL(loginLocation ?? "");
    const state = loginUrl.searchParams.get("state") ?? "";
    const nonce = loginUrl.searchParams.get("nonce") ?? "";
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: "RS256",
        typ: "JWT",
      },
      payload: {
        iss: issuer,
        sub: "user-456",
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce,
        email: "Learner@Example.edu",
        "https://purl.imsglobal.org/spec/lti/claim/lis": {
          person_sourcedid: "sourced-learner-456",
        },
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deploymentId,
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": targetLinkUri,
        "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
          id: "resource-link-456",
        },
        "https://purl.imsglobal.org/spec/lti/claim/roles": [
          "http://purl.imsglobal.org/vocab/lis/v2/membership#Learner",
        ],
      },
    });

    const response = await isolatedApp.request(
      "/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: idToken,
          state,
        }).toString(),
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Learner");
    expect(body).toContain("viewer");
    expect(mockedUpsertUserByEmail).toHaveBeenCalledWith(fakeDb, "Learner@Example.edu");
    expect(mockedAddLearnerIdentityAlias).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId,
        learnerProfileId: "lpr_123",
        identityType: "sourced_id",
        identityValue: "sourced-learner-456",
      }),
    );
    expect(mockedUpsertTenantMembershipRole).not.toHaveBeenCalled();
  });

  it("accepts instructor deep linking launch and renders badge template placement forms", async () => {
    const env = createLtiEnv();
    const deepLinkReturnUrl = "https://canvas.example.edu/api/lti/deep_link_return";
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    const loginResponse = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}&lti_deployment_id=${encodeURIComponent(
        deploymentId,
      )}`,
      undefined,
      env,
    );
    const loginLocation = loginResponse.headers.get("location");
    const loginUrl = new URL(loginLocation ?? "");
    const state = loginUrl.searchParams.get("state") ?? "";
    const nonce = loginUrl.searchParams.get("nonce") ?? "";
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: "RS256",
        typ: "JWT",
      },
      payload: {
        iss: issuer,
        sub: "user-999",
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce,
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deploymentId,
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiDeepLinkingRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": targetLinkUri,
        "https://purl.imsglobal.org/spec/lti/claim/roles": [
          "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor",
        ],
        "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings": {
          deep_link_return_url: deepLinkReturnUrl,
          accept_types: ["ltiResourceLink"],
          data: "opaque-deep-link-state",
        },
      },
    });

    const response = await isolatedApp.request(
      "/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: idToken,
          state,
        }).toString(),
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("set-cookie")).toContain("better-auth.session_token=");
    expect(body).toContain("Select badge template placement");
    expect(body).toContain(deepLinkReturnUrl);
    expect(body).toContain('name="lti_session_id"');
    expect(body).toContain('name="badge_template_id"');
    expect(body).toContain("TypeScript Foundations");
    expect(body).toContain("badgeTemplateId=badge_template_001");
    expect(body).toContain("/assets/ui/foundation.");
    expect(body).toContain("/assets/ui/lti-pages.");
    expect(mockedListBadgeTemplates).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      includeArchived: false,
    });
  });

  it("returns a signed Deep Linking response for selected templates through lti-tool core", async () => {
    const env = createLtiEnv();
    const deepLinkReturnUrl = "https://canvas.example.edu/api/lti/deep_link_return";
    const ltiSession: LTISession = {
      jwtPayload: {},
      id: "lti-session-123",
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
        issuer,
        clientId,
        deploymentId,
        name: "Canvas",
      },
      launch: {
        target: targetLinkUri,
      },
      services: {
        deepLinking: {
          returnUrl: deepLinkReturnUrl,
          acceptTypes: ["ltiResourceLink"],
          acceptPresentationDocumentTargets: [],
          acceptMultiple: false,
          autoCreate: false,
          data: "opaque-deep-link-state",
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
    const getSession = vi.fn().mockResolvedValue(ltiSession);
    const createDeepLinkingResponse = vi
      .fn()
      .mockResolvedValue("<!DOCTYPE html><html><body>signed deep link</body></html>");
    const { app: isolatedApp } = await loadAppWithMockedAuthProviders(() => {
      vi.doMock("./lti/credtrail-lti-tool", () => {
        return {
          createCredTrailLtiTool: vi.fn(async () => ({
            getSession,
            createDeepLinkingResponse,
          })),
        };
      });
    });

    const response = await isolatedApp.request(
      "/v1/lti/deep-linking/select",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          lti_session_id: ltiSession.id,
          badge_template_id: "badge_template_001",
        }).toString(),
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body).toContain("signed deep link");
    expect(getSession).toHaveBeenCalledWith(ltiSession.id);
    expect(createDeepLinkingResponse).toHaveBeenCalledWith(ltiSession, [
      expect.objectContaining({
        type: "ltiResourceLink",
        title: "TypeScript Foundations",
        url: "https://tool.example.edu/v1/lti/launch?badgeTemplateId=badge_template_001",
        custom: {
          badgeTemplateId: "badge_template_001",
        },
      }),
    ]);
  });

  it("rejects deep linking launch for learner role", async () => {
    const env = createLtiEnv();
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    const loginResponse = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}`,
      undefined,
      env,
    );
    const loginLocation = loginResponse.headers.get("location");
    const loginUrl = new URL(loginLocation ?? "");
    const state = loginUrl.searchParams.get("state") ?? "";
    const nonce = loginUrl.searchParams.get("nonce") ?? "";
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: "RS256",
      },
      payload: {
        iss: issuer,
        sub: "user-learner-deep-link",
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce,
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deploymentId,
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiDeepLinkingRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": targetLinkUri,
        "https://purl.imsglobal.org/spec/lti/claim/roles": [
          "http://purl.imsglobal.org/vocab/lis/v2/membership#Learner",
        ],
        "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings": {
          deep_link_return_url: "https://canvas.example.edu/api/lti/deep_link_return",
          accept_types: ["ltiResourceLink"],
        },
      },
    });

    const response = await isolatedApp.request(
      "/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: idToken,
          state,
        }).toString(),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(403);
    expect(body.error).toContain("requires instructor role");
    expect(mockedListBadgeTemplates).not.toHaveBeenCalled();
  });

  it("rejects OIDC login when issuer is missing signed launch configuration", async () => {
    const env = createUnsignedOnlyLtiEnv();
    const response = await app.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}`,
      undefined,
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(501);
    expect(body.error).toContain("requires platform JWKS and token endpoint");
  });

  it("rejects launch when issuer is missing signed launch configuration", async () => {
    const env = createUnsignedOnlyLtiEnv();
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: "RS256",
      },
      payload: {
        iss: issuer,
        sub: "user-789",
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce: "mock-lti-nonce",
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deploymentId,
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": targetLinkUri,
        "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
          id: "resource-link-789",
        },
      },
    });

    const response = await app.request(
      "/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: idToken,
          state: "mock-lti-state",
        }).toString(),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(501);
    expect(body.error).toContain("requires platform JWKS and token endpoint");
  });
});
