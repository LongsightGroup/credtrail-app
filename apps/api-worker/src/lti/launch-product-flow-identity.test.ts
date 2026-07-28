import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  mockedAttachLtiLaunchSessionPrincipal,
  mockedFindTenantLmsConnectionByLtiRegistration,
  mockedLinkLtiLaunchAccount,
  mockedUpsertTenantLmsUserIdentity,
} = vi.hoisted(() => ({
  mockedAttachLtiLaunchSessionPrincipal: vi.fn(),
  mockedFindTenantLmsConnectionByLtiRegistration: vi.fn(),
  mockedLinkLtiLaunchAccount: vi.fn(),
  mockedUpsertTenantLmsUserIdentity: vi.fn(),
}));

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    attachLtiLaunchSessionPrincipal: mockedAttachLtiLaunchSessionPrincipal,
    findTenantLmsConnectionByLtiRegistration: mockedFindTenantLmsConnectionByLtiRegistration,
    upsertTenantLmsUserIdentity: mockedUpsertTenantLmsUserIdentity,
  };
});

vi.mock("./launch-account-linking", () => ({
  linkLtiLaunchAccount: mockedLinkLtiLaunchAccount,
}));

import type { TenantLmsConnectionRecord } from "@credtrail/db";
import { createCredTrailAuthSessionFromLtiLaunch } from "./launch-product-flow";

type LaunchSessionInput = Parameters<typeof createCredTrailAuthSessionFromLtiLaunch>[0];

describe("createCredTrailAuthSessionFromLtiLaunch LMS identity linking", () => {
  beforeEach(() => {
    mockedAttachLtiLaunchSessionPrincipal.mockReset();
    mockedFindTenantLmsConnectionByLtiRegistration.mockReset();
    mockedLinkLtiLaunchAccount.mockReset();
    mockedUpsertTenantLmsUserIdentity.mockReset();
    mockedLinkLtiLaunchAccount.mockResolvedValue({
      userId: "usr_123",
      learnerProfileId: null,
      matchedBy: "saml_subject",
    });
    mockedFindTenantLmsConnectionByLtiRegistration.mockResolvedValue({
      id: "lms_123",
    } as TenantLmsConnectionRecord);
    mockedUpsertTenantLmsUserIdentity.mockResolvedValue({
      tenantId: "tenant_123",
      connectionId: "lms_123",
      userId: "usr_123",
      providerUserId: "sakai-user-123",
      createdAt: "2026-07-26T00:00:00.000Z",
      updatedAt: "2026-07-26T00:00:00.000Z",
    });
    mockedAttachLtiLaunchSessionPrincipal.mockResolvedValue(undefined);
  });

  it("records the verified LTI subject for the matching connection registration", async () => {
    const createLtiSession = vi.fn().mockResolvedValue({
      id: "auth-session-123",
      token: "session-token",
    });
    const input = {
      c: {
        env: { APP_ENV: "test" },
      },
      db: {},
      tenantId: "tenant_123",
      launchClaims: {
        iss: "https://sakai.example.edu",
        sub: "sakai-user-123",
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": "deployment-123",
      },
      launchMessage: {
        roleKind: "instructor",
      },
      ltiLaunchSession: {
        id: "lti-session-123",
      },
      ltiClientId: "credtrail-client",
      sha256Hex: vi.fn(),
      createLtiSession,
    } as unknown as LaunchSessionInput;

    const result = await createCredTrailAuthSessionFromLtiLaunch(input);

    expect(result.ok).toBe(true);
    expect(mockedFindTenantLmsConnectionByLtiRegistration).toHaveBeenCalledWith(input.db, {
      tenantId: "tenant_123",
      issuer: "https://sakai.example.edu",
      clientId: "credtrail-client",
      deploymentId: "deployment-123",
    });
    expect(mockedUpsertTenantLmsUserIdentity).toHaveBeenCalledWith(input.db, {
      tenantId: "tenant_123",
      connectionId: "lms_123",
      userId: "usr_123",
      providerUserId: "sakai-user-123",
    });
  });
});
