import { readFileSync } from "node:fs";

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
import type { BetterAuthResolvedSession } from "./better-auth-adapter";
import { createBetterAuthProvider } from "./better-auth-adapter";

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
    authAccountId: null,
    credtrailUserId: overrides?.credtrailUserId ?? "usr_123",
    emailSnapshot: null,
    createdAt: "2026-03-18T18:00:00.000Z",
    updatedAt: "2026-03-18T18:00:00.000Z",
  };
};

const sampleBetterAuthSession = (
  overrides?: Partial<BetterAuthResolvedSession>,
): BetterAuthResolvedSession => {
  return {
    sessionId: "ba_ses_lti_123",
    sessionToken: "lti-browser-session-token",
    accountId: null,
    expiresAt: "2026-03-25T18:00:00.000Z",
    user: {
      id: "ba_usr_123",
      email: null,
      emailVerified: false,
    },
    ...overrides,
  };
};

beforeEach(() => {
  mockedCreateAuthIdentityLink.mockReset();
  mockedFindAuthIdentityLinkByAuthUserId.mockReset();
  mockedFindAuthIdentityLinkByCredtrailUserId.mockReset();
  mockedUpsertUserByEmail.mockReset();
});

describe("legacy auth removal cleanup contract", () => {
  it("does not expose a composite auth provider helper once runtime fallback is removed", async () => {
    const adapterModule = await import("./better-auth-adapter");

    expect(adapterModule).not.toHaveProperty("createCompositeAuthProvider");
  });

  it("describes hosted auth as Better Auth-backed in the app README", () => {
    const readme = readFileSync(new URL("../../../../README.md", import.meta.url), "utf8");

    expect(readme).toContain("Better Auth-backed passwordless email login");
    expect(readme).toContain("Better Auth-backed institutional sign-in");
    expect(readme).toContain("Better Auth sessions with tenant-scoped authorization");
    expect(readme).not.toContain("Magic link authentication");
    expect(readme).not.toContain(
      "Session management - Server-side sessions with secure cookie handling",
    );
  });

  it("keeps active auth runtime sources free of legacy auth helper symbols", () => {
    const source = [
      readFileSync(new URL("./better-auth-adapter.ts", import.meta.url), "utf8"),
      readFileSync(new URL("../index.ts", import.meta.url), "utf8"),
      readFileSync(new URL("../../../../packages/db/src/index.ts", import.meta.url), "utf8"),
    ].join("\n");

    expect(source).not.toMatch(
      /createLegacyAuthProvider|resolveLegacySessionRecord|createCompositeAuthProvider|credtrail_session|legacy_magic_link|legacy_lti|createMagicLinkToken|findMagicLinkTokenByHash|markMagicLinkTokenUsed|createSession|findActiveSessionByHash|touchSession|revokeSessionByHash/,
    );
  });

  it("creates Better Auth-backed LTI sessions without runtime fallback plumbing", async () => {
    mockedFindAuthIdentityLinkByAuthUserId.mockResolvedValue(
      sampleLink({
        authUserId: "ba_usr_123",
        credtrailUserId: "usr_123",
      }),
    );

    const createLtiSession = vi.fn(async () => sampleBetterAuthSession());
    const cacheAuthenticatedPrincipal = vi.fn();
    const provider = createBetterAuthProvider<FakeContext, FakeBindings>({
      resolveDatabase: () => fakeDb,
      requestMagicLink: vi.fn(),
      resolveSession: vi.fn(async () => null),
      revokeSession: vi.fn(async () => {}),
      cacheAuthenticatedPrincipal,
      createLtiSession,
    } as Parameters<typeof createBetterAuthProvider<FakeContext, FakeBindings>>[0] & {
      createLtiSession: (
        context: FakeContext,
        input: {
          tenantId: string;
          userId: string;
        },
      ) => Promise<BetterAuthResolvedSession>;
    });

    const context = { env: {} } satisfies FakeContext;
    const principal = await provider.createLtiSession(context, {
      tenantId: "tenant_123",
      userId: "usr_123",
    });

    expect(createLtiSession).toHaveBeenCalledWith(context, {
      tenantId: "tenant_123",
      userId: "usr_123",
    });
    expect(principal).toEqual({
      userId: "usr_123",
      authSessionId: "ba_ses_lti_123",
      authMethod: "better_auth",
      expiresAt: "2026-03-25T18:00:00.000Z",
      browserSessionToken: "lti-browser-session-token",
    });
    expect(cacheAuthenticatedPrincipal).toHaveBeenCalledWith(context, {
      userId: "usr_123",
      authSessionId: "ba_ses_lti_123",
      authMethod: "better_auth",
      expiresAt: "2026-03-25T18:00:00.000Z",
      browserSessionToken: "lti-browser-session-token",
    });
  });
});
