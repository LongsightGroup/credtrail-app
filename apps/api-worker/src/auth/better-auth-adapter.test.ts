import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    createAuthIdentityLink: vi.fn(),
    findAuthIdentityLinkByAuthUserId: vi.fn(),
    findAuthIdentityLinkByCredtrailUserId: vi.fn(),
    upsertUserByEmail: vi.fn(),
  };
});

import {
  createAuthIdentityLink,
  findAuthIdentityLinkByAuthUserId,
  findAuthIdentityLinkByCredtrailUserId,
  upsertUserByEmail,
  type SqlDatabase,
} from "@credtrail/db";
import { createBetterAuthRuntimeConfig } from "./better-auth-config";
import {
  type BetterAuthAdapterInput,
  createBetterAuthProvider,
  resolveAuthenticatedPrincipal,
} from "./better-auth-adapter";

interface FakeBindings {
  APP_ENV?: string;
}

interface FakeContext {
  env: FakeBindings;
}

const mockedCreateAuthIdentityLink = vi.mocked(createAuthIdentityLink);
const mockedFindAuthIdentityLinkByAuthUserId = vi.mocked(findAuthIdentityLinkByAuthUserId);
const mockedFindAuthIdentityLinkByCredtrailUserId = vi.mocked(
  findAuthIdentityLinkByCredtrailUserId,
);
const mockedUpsertUserByEmail = vi.mocked(upsertUserByEmail);

const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const sampleLink = (overrides?: {
  authUserId?: string;
  credtrailUserId?: string;
  emailSnapshot?: string | null;
}): {
  id: string;
  authSystem: string;
  authUserId: string;
  authAccountId: string | null;
  credtrailUserId: string;
  emailSnapshot: string | null;
  createdAt: string;
  updatedAt: string;
} => {
  return {
    id: "ail_123",
    authSystem: "better_auth",
    authUserId: overrides?.authUserId ?? "ba_usr_123",
    authAccountId: "ba_account_123",
    credtrailUserId: overrides?.credtrailUserId ?? "usr_123",
    emailSnapshot: overrides?.emailSnapshot ?? "student@example.edu",
    createdAt: "2026-03-16T20:00:00.000Z",
    updatedAt: "2026-03-16T20:00:00.000Z",
  };
};

const sampleUser = (overrides?: { id?: string; email?: string }): { id: string; email: string } => {
  return {
    id: overrides?.id ?? "usr_123",
    email: overrides?.email ?? "student@example.edu",
  };
};

const createInput = (sessionOverride?: {
  sessionId?: string;
  authUserId?: string;
  email?: string | null;
  emailVerified?: boolean;
}): BetterAuthAdapterInput<FakeContext, FakeBindings> => {
  return {
    resolveDatabase: () => fakeDb,
    requestMagicLink: vi.fn<BetterAuthAdapterInput<FakeContext, FakeBindings>["requestMagicLink"]>(
      async () => ({
        tenantId: "tenant_123",
        email: "student@example.edu",
        deliveryStatus: "sent" as const,
        expiresAt: "2026-03-17T20:10:00.000Z",
      }),
    ),
    resolveSession: () =>
      Promise.resolve({
        sessionId: sessionOverride?.sessionId ?? "ba_ses_123",
        accountId: "ba_account_123",
        expiresAt: "2026-03-17T20:00:00.000Z",
        user: {
          id: sessionOverride?.authUserId ?? "ba_usr_123",
          email: sessionOverride?.email ?? "Student@Example.edu",
          emailVerified: sessionOverride?.emailVerified ?? true,
        },
      }),
    revokeSession: vi.fn<BetterAuthAdapterInput<FakeContext, FakeBindings>["revokeSession"]>(
      async () => {},
    ),
  };
};

beforeEach(() => {
  mockedCreateAuthIdentityLink.mockReset();
  mockedFindAuthIdentityLinkByAuthUserId.mockReset();
  mockedFindAuthIdentityLinkByCredtrailUserId.mockReset();
  mockedUpsertUserByEmail.mockReset();
});

describe("better auth adapter", () => {
  it("builds explicit Better Auth runtime config and keeps hosted request flow behind the provider seam", async () => {
    const config = createBetterAuthRuntimeConfig({
      APP_ENV: "test",
      PLATFORM_DOMAIN: "credtrail.test",
      PUBLIC_APP_ORIGIN: "https://credtrail.test",
      BETTER_AUTH_SECRET: "test-secret",
      BETTER_AUTH_TRUSTED_ORIGINS:
        "https://credtrail.test, https://admin.credtrail.test , https://credtrail.test",
    });
    const input = createInput();
    const provider = createBetterAuthProvider(input);

    const result = await provider.requestMagicLink({ env: {} } satisfies FakeContext, {
      tenantId: "tenant_123",
      email: "student@example.edu",
    });

    expect(config.baseURL).toBe("https://credtrail.test");
    expect(config.trustedOrigins).toEqual([
      "https://credtrail.test",
      "https://admin.credtrail.test",
    ]);
    expect(config.secret).toBe("test-secret");
    expect(config.session.expiresInSeconds).toBe(7 * 24 * 60 * 60);
    expect(config.database.schema).toBe("auth");
    expect(input.requestMagicLink).toHaveBeenCalledWith(
      { env: {} },
      {
        tenantId: "tenant_123",
        email: "student@example.edu",
      },
    );
    expect(result.deliveryStatus).toBe("sent");
  });

  it("links unlinked Better Auth users to existing CredTrail users by normalized verified email", async () => {
    mockedFindAuthIdentityLinkByAuthUserId.mockResolvedValue(null);
    mockedUpsertUserByEmail.mockResolvedValue(sampleUser());
    mockedFindAuthIdentityLinkByCredtrailUserId.mockResolvedValue(null);
    mockedCreateAuthIdentityLink.mockResolvedValue(sampleLink());

    const principal = await resolveAuthenticatedPrincipal(
      { env: {} } satisfies FakeContext,
      createInput(),
    );

    expect(principal).toEqual({
      userId: "usr_123",
      authSessionId: "ba_ses_123",
      authMethod: "better_auth",
      expiresAt: "2026-03-17T20:00:00.000Z",
    });
    expect(mockedUpsertUserByEmail).toHaveBeenCalledWith(fakeDb, "Student@Example.edu");
    expect(mockedCreateAuthIdentityLink).toHaveBeenCalledWith(fakeDb, {
      authSystem: "better_auth",
      authUserId: "ba_usr_123",
      authAccountId: "ba_account_123",
      credtrailUserId: "usr_123",
      emailSnapshot: "Student@Example.edu",
    });
  });

  it("reuses an existing auth identity link without trying to relink by email", async () => {
    mockedFindAuthIdentityLinkByAuthUserId.mockResolvedValue(sampleLink());

    const principal = await resolveAuthenticatedPrincipal(
      { env: {} } satisfies FakeContext,
      createInput(),
    );

    expect(principal).toEqual({
      userId: "usr_123",
      authSessionId: "ba_ses_123",
      authMethod: "better_auth",
      expiresAt: "2026-03-17T20:00:00.000Z",
    });
    expect(mockedUpsertUserByEmail).not.toHaveBeenCalled();
    expect(mockedCreateAuthIdentityLink).not.toHaveBeenCalled();
  });

  it("fails closed when Better Auth identity data is missing or the email match is unsafe", async () => {
    mockedFindAuthIdentityLinkByAuthUserId.mockResolvedValue(null);

    const missingIdentityPrincipal = await resolveAuthenticatedPrincipal(
      { env: {} } satisfies FakeContext,
      createInput({
        email: null,
        emailVerified: false,
      }),
    );

    mockedUpsertUserByEmail.mockResolvedValue(sampleUser());
    mockedFindAuthIdentityLinkByCredtrailUserId.mockResolvedValue(
      sampleLink({
        authUserId: "ba_usr_conflict",
      }),
    );

    const conflictingLinkPrincipal = await resolveAuthenticatedPrincipal(
      { env: {} } satisfies FakeContext,
      createInput(),
    );

    expect(missingIdentityPrincipal).toBeNull();
    expect(conflictingLinkPrincipal).toBeNull();
    expect(mockedCreateAuthIdentityLink).not.toHaveBeenCalled();
  });
});
