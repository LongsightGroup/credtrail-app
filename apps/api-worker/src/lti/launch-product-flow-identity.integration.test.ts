import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import {
  findLtiLaunchSessionById,
  findTenantLmsUserIdentity,
  findUserByEmail,
  upsertLtiLaunchSession,
  upsertTenantLmsConnection,
  upsertTenantLmsUserIdentity,
  upsertUserByEmail,
  type SqlDatabase,
  type TenantLmsConnectionRecord,
} from "@credtrail/db";
import {
  LTI_CLAIM_CONTEXT,
  LTI_CLAIM_DEPLOYMENT_ID,
  LTI_CLAIM_MESSAGE_TYPE,
  LTI_CLAIM_RESOURCE_LINK,
  LTI_CLAIM_ROLES,
  LTI_CLAIM_TARGET_LINK_URI,
  LTI_CLAIM_VERSION,
  LTI13JwtPayloadSchema,
  LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
  LTI_VERSION_1P3P0,
  type LtiToolPort,
} from "@longsightgroup/lti-tool";
import { testSession } from "@longsightgroup/lti-tool/testing";
import { Hono } from "hono";
import { expect, it } from "vitest";
import {
  cleanupTestResources,
  createTestTenantFixture,
  describeDbIntegration,
  uniqueTestId,
} from "../../../../packages/db/src/postgres-test-support";
import type { AppBindings, AppEnv } from "../app";
import { linkInstructorLmsIdentity } from "./instructor-lms-identity";
import type { ResolvedLtiLaunchMessage } from "./launch-message";
import { handleVerifiedLtiLaunch } from "./launch-product-flow";
import type { LtiIssuerRegistryEntry } from "./lti-issuer-registry";
import type { LtiLaunchClaimsWithSubject } from "./launch-verification";

const ISSUER = "https://sakai.example.test";
const CLIENT_ID = "credtrail-client";
const DEPLOYMENT_ID = "deployment-123";

const issuerEntry: LtiIssuerRegistryEntry = {
  tenantId: "resolved-per-test",
  clientId: CLIENT_ID,
  authorizationEndpoint: `${ISSUER}/authorize`,
};

const createUnusedLtiTool = (): LtiToolPort => {
  const unused = (): Promise<never> => Promise.reject(new Error("LTI tool is unused in this test"));

  return {
    getJWKS: unused,
    handleLogin: unused,
    verifyLaunch: unused,
    createSessionFromVerifiedLaunch: unused,
    getSession: unused,
    createAdvantage: () => {
      throw new Error("LTI Advantage is unused in this test");
    },
  };
};

const createNoopStore = (): ImmutableCredentialStore => {
  return {
    head: () => Promise.resolve(null),
    get: () => Promise.resolve(null),
    put: () =>
      Promise.resolve({
        key: "noop",
        etag: "noop",
        version: "noop",
        size: 0,
        uploaded: new Date("2026-08-05T00:00:00.000Z"),
      }),
    delete: () => Promise.resolve(),
  };
};

const createEnv = (): AppBindings => {
  return {
    APP_ENV: "test",
    PLATFORM_DOMAIN: "credtrail.test",
    BADGE_OBJECTS: createNoopStore(),
  };
};

const createLmsConnection = (
  db: SqlDatabase,
  tenantId: string,
): Promise<TenantLmsConnectionRecord> => {
  return upsertTenantLmsConnection(db, {
    id: uniqueTestId("lms_lti_identity"),
    tenantId,
    displayName: "Sakai",
    providerKind: "sakai",
    apiBaseUrl: ISSUER,
    ltiIssuer: ISSUER,
    ltiClientId: CLIENT_ID,
    ltiDeploymentId: DEPLOYMENT_ID,
  });
};

const launchClaims = (
  email: string,
  providerUserId: string,
  roleKind: "instructor" | "learner",
): LtiLaunchClaimsWithSubject => {
  const role =
    roleKind === "instructor"
      ? "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"
      : "http://purl.imsglobal.org/vocab/lis/v2/membership#Learner";
  const claims = LTI13JwtPayloadSchema.parse({
    iss: ISSUER,
    aud: CLIENT_ID,
    sub: providerUserId,
    iat: 1_786_000_000,
    exp: 1_786_000_300,
    nonce: uniqueTestId("nonce"),
    name: "First-time LTI user",
    email,
    [LTI_CLAIM_MESSAGE_TYPE]: LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
    [LTI_CLAIM_VERSION]: LTI_VERSION_1P3P0,
    [LTI_CLAIM_DEPLOYMENT_ID]: DEPLOYMENT_ID,
    [LTI_CLAIM_TARGET_LINK_URI]: "https://credtrail.test/v1/lti/launch",
    [LTI_CLAIM_ROLES]: [role],
    [LTI_CLAIM_CONTEXT]: {
      id: "course-123",
      title: "Course 123",
    },
    [LTI_CLAIM_RESOURCE_LINK]: {
      id: "resource-link-123",
    },
  });

  if (claims.sub === undefined) {
    throw new Error("LTI launch fixture requires a subject");
  }

  return {
    ...claims,
    sub: claims.sub,
  };
};

const resourceLinkLaunchMessage = (
  roleKind: "instructor" | "learner",
): ResolvedLtiLaunchMessage => {
  return {
    kind: "resource-link",
    messageType: LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
    roleKind,
    resolvedTargetLinkUri: "https://credtrail.test/v1/lti/launch",
    resourceLinkId: "resource-link-123",
    resourceContextId: "course-123",
    badgeTemplateId: null,
    ruleId: null,
    setupToken: null,
  };
};

const runVerifiedLaunch = async (input: {
  db: SqlDatabase;
  tenantId: string;
  launchClaims: LtiLaunchClaimsWithSubject;
  launchSessionId: string;
  launchMessage: ResolvedLtiLaunchMessage;
  createLtiSession: Parameters<typeof handleVerifiedLtiLaunch>[0]["createLtiSession"];
}): Promise<Response> => {
  const app = new Hono<AppEnv>();

  app.get("/launch", (c) =>
    handleVerifiedLtiLaunch({
      c,
      db: input.db,
      tenantId: input.tenantId,
      resolvedLaunch: {
        issuer: ISSUER,
        issuerEntry: {
          ...issuerEntry,
          tenantId: input.tenantId,
        },
        launchClaims: input.launchClaims,
        ltiLaunchSession: testSession({
          id: input.launchSessionId,
          context: { id: "course-123", label: "COURSE-123", title: "Course 123" },
        }),
        ltiTool: createUnusedLtiTool(),
      },
      launchMessage: input.launchMessage,
      sha256Hex: () => Promise.resolve("0".repeat(64)),
      createLtiSession: input.createLtiSession,
    }),
  );

  return app.request("https://credtrail.test/launch", {}, createEnv());
};

describeDbIntegration("LTI launch identity boundaries", () => {
  it("establishes a learner session without writing instructor course-scope identity", async () => {
    const fixture = await createTestTenantFixture();
    const learnerEmail = `${uniqueTestId("learner")}@example.edu`;
    const providerUserId = uniqueTestId("sakai_learner");
    const conflictingUser = await upsertUserByEmail(
      fixture.db,
      `${uniqueTestId("existing")}@example.edu`,
    );
    let learnerUserId: string | null = null;

    try {
      const connection = await createLmsConnection(fixture.db, fixture.tenantId);
      await upsertTenantLmsUserIdentity(fixture.db, {
        tenantId: fixture.tenantId,
        connectionId: connection.id,
        userId: conflictingUser.id,
        providerUserId,
      });
      const launchSessionId = uniqueTestId("lti_session");
      await upsertLtiLaunchSession(fixture.db, {
        id: launchSessionId,
        issuer: ISSUER,
        clientId: CLIENT_ID,
        deploymentId: DEPLOYMENT_ID,
        tenantId: fixture.tenantId,
        dataJson: "{}",
        expiresAt: new Date(Date.now() + 60 * 60 * 1_000).toISOString(),
      });
      const response = await runVerifiedLaunch({
        db: fixture.db,
        tenantId: fixture.tenantId,
        launchClaims: launchClaims(learnerEmail, providerUserId, "learner"),
        launchSessionId,
        launchMessage: resourceLinkLaunchMessage("learner"),
        createLtiSession: (_context, input) => {
          return Promise.resolve({
            userId: input.userId,
            authSessionId: uniqueTestId("auth_session"),
            authMethod: "better_auth",
            expiresAt: new Date(Date.now() + 60 * 60 * 1_000).toISOString(),
          });
        },
      });
      expect(response.status).toBe(200);

      const learnerUser = await findUserByEmail(fixture.db, learnerEmail);
      expect(learnerUser).not.toBeNull();
      learnerUserId = learnerUser?.id ?? null;

      if (learnerUser === null) {
        throw new Error("Learner launch did not create a CredTrail user");
      }

      expect(
        await findTenantLmsUserIdentity(fixture.db, {
          tenantId: fixture.tenantId,
          connectionId: connection.id,
          userId: learnerUser.id,
        }),
      ).toBeNull();
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [conflictingUser.id, ...(learnerUserId === null ? [] : [learnerUserId])],
      });
    }
  });

  it("does not establish a browser session when instructor identity linking fails", async () => {
    const fixture = await createTestTenantFixture();
    const instructorEmail = `${uniqueTestId("instructor")}@example.edu`;
    const providerUserId = uniqueTestId("sakai_instructor");
    const conflictingUser = await upsertUserByEmail(
      fixture.db,
      `${uniqueTestId("existing")}@example.edu`,
    );
    let instructorUserId: string | null = null;

    try {
      const connection = await createLmsConnection(fixture.db, fixture.tenantId);
      await upsertTenantLmsUserIdentity(fixture.db, {
        tenantId: fixture.tenantId,
        connectionId: connection.id,
        userId: conflictingUser.id,
        providerUserId,
      });
      const launchSessionId = uniqueTestId("lti_session");
      await upsertLtiLaunchSession(fixture.db, {
        id: launchSessionId,
        issuer: ISSUER,
        clientId: CLIENT_ID,
        deploymentId: DEPLOYMENT_ID,
        tenantId: fixture.tenantId,
        dataJson: "{}",
        expiresAt: new Date(Date.now() + 60 * 60 * 1_000).toISOString(),
      });
      let createSessionCalls = 0;

      const response = await runVerifiedLaunch({
        db: fixture.db,
        tenantId: fixture.tenantId,
        launchClaims: launchClaims(instructorEmail, providerUserId, "instructor"),
        launchSessionId,
        launchMessage: resourceLinkLaunchMessage("instructor"),
        createLtiSession: (_context, input) => {
          createSessionCalls += 1;
          return Promise.resolve({
            userId: input.userId,
            authSessionId: uniqueTestId("auth_session"),
            authMethod: "better_auth",
            expiresAt: new Date(Date.now() + 60 * 60 * 1_000).toISOString(),
          });
        },
      });

      expect(response.status).toBe(500);
      await expect(response.json()).resolves.toMatchObject({
        error: "CredTrail could not verify your LMS course access",
      });
      expect(createSessionCalls).toBe(0);
      expect(
        await findLtiLaunchSessionById(fixture.db, {
          tenantId: fixture.tenantId,
          sessionId: launchSessionId,
        }),
      ).toMatchObject({ userId: null });

      instructorUserId = (await findUserByEmail(fixture.db, instructorEmail))?.id ?? null;
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [conflictingUser.id, ...(instructorUserId === null ? [] : [instructorUserId])],
      });
    }
  });

  it("records a verified instructor identity for the matching LMS connection", async () => {
    const fixture = await createTestTenantFixture();
    const instructor = await upsertUserByEmail(
      fixture.db,
      `${uniqueTestId("instructor")}@example.edu`,
    );

    try {
      const connection = await createLmsConnection(fixture.db, fixture.tenantId);
      const providerUserId = uniqueTestId("sakai_instructor");
      const result = await linkInstructorLmsIdentity(fixture.db, {
        tenantId: fixture.tenantId,
        issuer: ISSUER,
        clientId: CLIENT_ID,
        deploymentId: DEPLOYMENT_ID,
        userId: instructor.id,
        providerUserId,
      });

      expect(result).toEqual({ ok: true });
      expect(
        await findTenantLmsUserIdentity(fixture.db, {
          tenantId: fixture.tenantId,
          connectionId: connection.id,
          userId: instructor.id,
        }),
      ).toMatchObject({ providerUserId });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [instructor.id],
      });
    }
  });
});
