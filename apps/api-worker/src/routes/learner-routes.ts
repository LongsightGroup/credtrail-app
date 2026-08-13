import {
  addLearnerIdentityAlias,
  createLearnerIdentityLinkProof,
  findClaimableLearnerBadgeSummary,
  findLearnerIdentityLinkProofByHash,
  findLearnerProfileByIdentity,
  findUserById,
  isLearnerIdentityLinkProofValid,
  listAccessibleTenantContextsForUser,
  listAssertionEngagementEvents,
  listLearnerBadgeSummaries,
  listLearnerIdentitiesByProfile,
  listLearnerPathwayProgress,
  markLearnerIdentityLinkProofUsed,
  recordAssertionEngagementEvent,
  removeLearnerIdentityAliasesByType,
  resolveLearnerProfileForIdentity,
  type TenantMembershipRole,
  type LearnerPathwayProgressRecord,
} from "@credtrail/db";
import {
  parseAssertionPathParams,
  parseLearnerDidSettingsRequest,
  parseLearnerIdentityLinkRequest,
  parseLearnerIdentityLinkVerifyRequest,
  parseTenantPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import { setCookie } from "hono/cookie";
import type { AppContext, AppEnv } from "../app";
import type { RequireTenantRole, ResolveDatabase } from "../app/route-deps";
import { resolveAuthenticatedPrincipalFromSession } from "../auth/better-auth-adapter";
import { createBetterAuthRuntimeConfig } from "../auth/better-auth-config";
import { findBetterAuthSessionByToken } from "../auth/better-auth-runtime";
import { buildOrganizationsPath } from "../auth/tenant-context-selection";
import { loadLearnerRecordExportBundle } from "../learner-record/learner-record-export";
import { createLearnerRecordPresentation } from "../learner-record/learner-record-presentation";
import type { LearnerDashboardBadge } from "../learner/pages";
import { verifyLtiSessionHandoffToken } from "../lti/session-handoff";
import { renderAppPage, type AppPage } from "../ui/render-page";

interface RegisterLearnerRoutesInput<DidNotice> {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  requireTenantRole: RequireTenantRole;
  TENANT_MEMBER_ROLES: readonly TenantMembershipRole[];
  addSecondsToIso: (isoTimestamp: string, seconds: number) => string;
  generateOpaqueToken: () => string;
  sha256Hex: (value: string) => Promise<string>;
  LEARNER_IDENTITY_LINK_TTL_SECONDS: number;
  learnerDidSettingsNoticeFromQuery: (value: string | undefined) => DidNotice;
  learnerDashboardPage: (
    requestUrl: string,
    tenantId: string,
    badges: readonly LearnerDashboardBadge[],
    learnerDid: string | null,
    didNotice: DidNotice,
    claimNotice: string | null,
    switchOrganizationPath?: string | null,
    learnerRecordPath?: string | null,
  ) => AppPage;
  learnerRecordPage: (
    tenantId: string,
    presentation: ReturnType<typeof createLearnerRecordPresentation>,
    options?: {
      switchOrganizationPath?: string | null;
      pathways?: readonly LearnerPathwayProgressRecord[];
    },
  ) => AppPage;
}

const LTI_SESSION_HANDOFF_QUERY_PARAM = "lti_session_handoff";

const consumeLtiSessionHandoff = async (input: {
  context: AppContext;
  tenantId: string;
  resolveDatabase: ResolveDatabase;
}): Promise<{
  sanitizedRequestUrl: string;
  consumed: boolean;
}> => {
  const requestUrl = new URL(input.context.req.url);
  const handoffToken = requestUrl.searchParams.get(LTI_SESSION_HANDOFF_QUERY_PARAM)?.trim();

  requestUrl.searchParams.delete(LTI_SESSION_HANDOFF_QUERY_PARAM);

  if (handoffToken === undefined || handoffToken.length === 0) {
    return {
      sanitizedRequestUrl: requestUrl.toString(),
      consumed: false,
    };
  }

  const handoff = await verifyLtiSessionHandoffToken(input.context.env, handoffToken);

  if (handoff === null || handoff.tenantId !== input.tenantId) {
    return {
      sanitizedRequestUrl: requestUrl.toString(),
      consumed: false,
    };
  }

  const runtimeConfig = createBetterAuthRuntimeConfig(input.context.env);
  const session = await findBetterAuthSessionByToken(
    input.resolveDatabase(input.context.env),
    handoff.sessionToken,
  );

  if (session === null) {
    return {
      sanitizedRequestUrl: requestUrl.toString(),
      consumed: false,
    };
  }

  const principal = await resolveAuthenticatedPrincipalFromSession({
    db: input.resolveDatabase(input.context.env),
    session: {
      sessionId: session.sessionId,
      sessionToken: session.sessionToken,
      accountId: null,
      expiresAt: session.expiresAt,
      user: {
        id: session.userId,
        email: session.userEmail,
        emailVerified: session.userEmailVerified,
      },
    },
  });

  if (principal === null) {
    return {
      sanitizedRequestUrl: requestUrl.toString(),
      consumed: false,
    };
  }

  setCookie(input.context, runtimeConfig.session.cookieName, session.sessionToken, {
    httpOnly: true,
    sameSite: "None",
    secure: true,
    path: "/",
    maxAge: runtimeConfig.session.expiresInSeconds,
  });
  input.context.set("authenticatedPrincipal", principal);
  input.context.set("requestedTenantContext", {
    tenantId: input.tenantId,
  });

  return {
    sanitizedRequestUrl: requestUrl.toString(),
    consumed: true,
  };
};

const learnerClaimStatusNoticeFromQuery = (
  value: string | undefined,
): "recorded" | "already_recorded" | "invalid" | null => {
  switch (value) {
    case "recorded":
    case "already_recorded":
    case "invalid":
      return value;
    default:
      return null;
  }
};

const learnerClaimInvalidDashboardRedirectUrl = (input: {
  requestUrl: string;
  tenantId: string;
}): string => {
  const dashboardUrl = new URL(
    `/tenants/${encodeURIComponent(input.tenantId)}/learner/dashboard`,
    input.requestUrl,
  );
  dashboardUrl.searchParams.set("claimStatus", "invalid");
  return dashboardUrl.toString();
};

const learnerBadgeSharePath = (badge: {
  assertionId: string;
  assertionPublicId: string | null;
}): string => {
  return `/badges/${encodeURIComponent(
    badge.assertionPublicId ?? badge.assertionId,
  )}#share-this-credential`;
};

const learnerBadgeClaimStateFromEvents = (
  events: Awaited<ReturnType<typeof listAssertionEngagementEvents>>,
): LearnerDashboardBadge["claimState"] => {
  if (events.some((event) => event.eventType === "wallet_accept")) {
    return "accepted";
  }

  if (events.some((event) => event.eventType === "learner_claim")) {
    return "claimed";
  }

  return "claimable";
};

export const registerLearnerRoutes = <DidNotice>(
  input: RegisterLearnerRoutesInput<DidNotice>,
): void => {
  const {
    app,
    resolveDatabase,
    requireTenantRole,
    TENANT_MEMBER_ROLES,
    addSecondsToIso,
    generateOpaqueToken,
    sha256Hex,
    LEARNER_IDENTITY_LINK_TTL_SECONDS,
    learnerDidSettingsNoticeFromQuery,
    learnerDashboardPage,
    learnerRecordPage,
  } = input;

  const learnerBadgeClaimHandler = async (c: AppContext): Promise<Response> => {
    const pathParams = parseAssertionPathParams(c.req.param());
    await consumeLtiSessionHandoff({
      context: c,
      tenantId: pathParams.tenantId,
      resolveDatabase,
    });
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, TENANT_MEMBER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const badge = await findClaimableLearnerBadgeSummary(db, {
      tenantId: pathParams.tenantId,
      userId: roleCheck.principal.userId,
      assertionId: pathParams.assertionId,
    });

    if (badge === null) {
      return c.redirect(
        learnerClaimInvalidDashboardRedirectUrl({
          requestUrl: c.req.url,
          tenantId: pathParams.tenantId,
        }),
        303,
      );
    }

    if (c.req.method === "POST") {
      await recordAssertionEngagementEvent(db, {
        tenantId: pathParams.tenantId,
        assertionId: pathParams.assertionId,
        eventType: "learner_claim",
        actorType: "learner",
        channel: "learner_dashboard",
        occurredAt: new Date().toISOString(),
      });
    }

    return c.redirect(learnerBadgeSharePath(badge), 303);
  };

  app.get("/tenants/:tenantId/learner/dashboard", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const handoff = await consumeLtiSessionHandoff({
      context: c,
      tenantId: pathParams.tenantId,
      resolveDatabase,
    });
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, TENANT_MEMBER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    if (handoff.consumed) {
      c.header("Cache-Control", "no-store");
    }

    const db = resolveDatabase(c.env);
    const user = await findUserById(db, roleCheck.principal.userId);

    if (user === null) {
      return c.json(
        {
          error: "Authenticated user not found",
        },
        404,
      );
    }

    const learnerProfile = await resolveLearnerProfileForIdentity(db, {
      tenantId: pathParams.tenantId,
      identityType: "email",
      identityValue: user.email,
    });
    const learnerIdentities = await listLearnerIdentitiesByProfile(
      db,
      pathParams.tenantId,
      learnerProfile.id,
    );
    const learnerDid =
      learnerIdentities.find((identity) => identity.identityType === "did")?.identityValue ?? null;
    const badges = await listLearnerBadgeSummaries(db, {
      tenantId: pathParams.tenantId,
      userId: roleCheck.principal.userId,
    });
    const dashboardBadges = await Promise.all(
      badges.map(async (badge) => {
        const events = await listAssertionEngagementEvents(db, {
          tenantId: pathParams.tenantId,
          assertionId: badge.assertionId,
        });

        return {
          ...badge,
          claimState: learnerBadgeClaimStateFromEvents(events),
        };
      }),
    );
    const didNotice = learnerDidSettingsNoticeFromQuery(c.req.query("didStatus"));
    const claimNotice = learnerClaimStatusNoticeFromQuery(c.req.query("claimStatus"));
    const accessibleTenantContexts = await listAccessibleTenantContextsForUser(
      db,
      roleCheck.principal.userId,
    );
    const requestUrl = new URL(c.req.url);
    const switchOrganizationPath =
      accessibleTenantContexts.length > 1
        ? buildOrganizationsPath(`${requestUrl.pathname}${requestUrl.search}`)
        : null;
    const learnerRecordPath = `/tenants/${encodeURIComponent(pathParams.tenantId)}/learner/record`;

    c.header("Cache-Control", "no-store");
    return renderAppPage(
      c,
      learnerDashboardPage(
        handoff.sanitizedRequestUrl,
        pathParams.tenantId,
        dashboardBadges,
        learnerDid,
        didNotice,
        claimNotice,
        switchOrganizationPath,
        learnerRecordPath,
      ),
    );
  });

  app.get("/tenants/:tenantId/learner/record", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, TENANT_MEMBER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const user = await findUserById(db, roleCheck.principal.userId);

    if (user === null) {
      return c.json(
        {
          error: "Authenticated user not found",
        },
        404,
      );
    }

    const learnerProfile = await resolveLearnerProfileForIdentity(db, {
      tenantId: pathParams.tenantId,
      identityType: "email",
      identityValue: user.email,
    });
    const bundle = await loadLearnerRecordExportBundle(db, {
      tenantId: pathParams.tenantId,
      learnerProfileId: learnerProfile.id,
    });

    if (bundle === null) {
      return c.json(
        {
          error: "Learner profile not found",
        },
        404,
      );
    }

    const pathways = await listLearnerPathwayProgress(db, {
      tenantId: pathParams.tenantId,
      learnerProfileId: learnerProfile.id,
    });

    const accessibleTenantContexts = await listAccessibleTenantContextsForUser(
      db,
      roleCheck.principal.userId,
    );
    const requestUrl = new URL(c.req.url);
    const switchOrganizationPath =
      accessibleTenantContexts.length > 1
        ? buildOrganizationsPath(`${requestUrl.pathname}${requestUrl.search}`)
        : null;

    c.header("Cache-Control", "no-store");
    return renderAppPage(
      c,
      learnerRecordPage(pathParams.tenantId, createLearnerRecordPresentation(bundle), {
        switchOrganizationPath,
        pathways,
      }),
    );
  });

  app.get("/tenants/:tenantId/learner/badges/:assertionId/claim", learnerBadgeClaimHandler);
  app.post("/tenants/:tenantId/learner/badges/:assertionId/claim", learnerBadgeClaimHandler);

  app.post("/tenants/:tenantId/learner/settings/did", async (c): Promise<Response> => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, TENANT_MEMBER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const dashboardUrl = new URL(
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/learner/dashboard`,
      c.req.url,
    );
    const contentType = c.req.header("content-type") ?? "";

    if (!contentType.toLowerCase().includes("application/x-www-form-urlencoded")) {
      dashboardUrl.searchParams.set("didStatus", "invalid");
      return c.redirect(dashboardUrl.toString(), 303);
    }

    const rawBody = await c.req.text();
    const formData = new URLSearchParams(rawBody);

    let request: ReturnType<typeof parseLearnerDidSettingsRequest>;

    try {
      request = parseLearnerDidSettingsRequest({
        did: formData.get("did") ?? undefined,
      });
    } catch {
      dashboardUrl.searchParams.set("didStatus", "invalid");
      return c.redirect(dashboardUrl.toString(), 303);
    }

    const db = resolveDatabase(c.env);
    const user = await findUserById(db, roleCheck.principal.userId);

    if (user === null) {
      return c.json(
        {
          error: "Authenticated user not found",
        },
        404,
      );
    }

    const learnerProfile = await resolveLearnerProfileForIdentity(db, {
      tenantId: pathParams.tenantId,
      identityType: "email",
      identityValue: user.email,
    });
    const submittedDid = request.did ?? "";

    if (submittedDid.length === 0) {
      await removeLearnerIdentityAliasesByType(db, {
        tenantId: pathParams.tenantId,
        learnerProfileId: learnerProfile.id,
        identityType: "did",
      });
      dashboardUrl.searchParams.set("didStatus", "cleared");
      return c.redirect(dashboardUrl.toString(), 303);
    }

    const existingDidProfile = await findLearnerProfileByIdentity(db, {
      tenantId: pathParams.tenantId,
      identityType: "did",
      identityValue: submittedDid,
    });

    if (existingDidProfile !== null && existingDidProfile.id !== learnerProfile.id) {
      dashboardUrl.searchParams.set("didStatus", "conflict");
      return c.redirect(dashboardUrl.toString(), 303);
    }

    await removeLearnerIdentityAliasesByType(db, {
      tenantId: pathParams.tenantId,
      learnerProfileId: learnerProfile.id,
      identityType: "did",
    });
    await addLearnerIdentityAlias(db, {
      tenantId: pathParams.tenantId,
      learnerProfileId: learnerProfile.id,
      identityType: "did",
      identityValue: submittedDid,
      isPrimary: false,
      isVerified: true,
    });

    dashboardUrl.searchParams.set("didStatus", "updated");
    return c.redirect(dashboardUrl.toString(), 303);
  });

  app.post("/v1/tenants/:tenantId/learner/identity-links/email/request", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const payload = await c.req.json<unknown>();
    const request = parseLearnerIdentityLinkRequest(payload);
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, TENANT_MEMBER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const user = await findUserById(db, roleCheck.principal.userId);

    if (user === null) {
      return c.json(
        {
          error: "Authenticated user not found",
        },
        404,
      );
    }

    const learnerProfile = await resolveLearnerProfileForIdentity(db, {
      tenantId: pathParams.tenantId,
      identityType: "email",
      identityValue: user.email,
    });
    const normalizedEmail = request.email.trim().toLowerCase();
    const existingProfile = await findLearnerProfileByIdentity(db, {
      tenantId: pathParams.tenantId,
      identityType: "email",
      identityValue: normalizedEmail,
    });

    // Learner-initiated email linking returns conflict instead of auto-reparenting.
    // LTI launch repair uses moveLearnerIdentityAliasToProfile for stale identity cleanup.
    if (existingProfile !== null && existingProfile.id !== learnerProfile.id) {
      return c.json(
        {
          error: "Email is already linked to a different learner profile",
        },
        409,
      );
    }

    if (existingProfile !== null) {
      return c.json({
        status: "already_linked",
        tenantId: pathParams.tenantId,
        learnerProfileId: learnerProfile.id,
        identityType: "email",
        identityValue: normalizedEmail,
      });
    }

    const nowIso = new Date().toISOString();
    const expiresAt = addSecondsToIso(nowIso, LEARNER_IDENTITY_LINK_TTL_SECONDS);
    const proofToken = generateOpaqueToken();
    const tokenHash = await sha256Hex(proofToken);

    await createLearnerIdentityLinkProof(db, {
      tenantId: pathParams.tenantId,
      learnerProfileId: learnerProfile.id,
      requestedByUserId: roleCheck.principal.userId,
      identityType: "email",
      identityValue: normalizedEmail,
      tokenHash,
      expiresAt,
    });

    if (c.env.APP_ENV === "development") {
      return c.json(
        {
          status: "sent",
          tenantId: pathParams.tenantId,
          identityType: "email",
          identityValue: normalizedEmail,
          expiresAt,
          token: proofToken,
        },
        202,
      );
    }

    return c.json(
      {
        status: "sent",
        tenantId: pathParams.tenantId,
        identityType: "email",
        identityValue: normalizedEmail,
        expiresAt,
      },
      202,
    );
  });

  app.post("/v1/tenants/:tenantId/learner/identity-links/email/verify", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const payload = await c.req.json<unknown>();
    const request = parseLearnerIdentityLinkVerifyRequest(payload);
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, TENANT_MEMBER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const nowIso = new Date().toISOString();
    const proof = await findLearnerIdentityLinkProofByHash(db, await sha256Hex(request.token));

    if (proof === null || !isLearnerIdentityLinkProofValid(proof, nowIso)) {
      return c.json(
        {
          error: "Invalid or expired identity link token",
        },
        400,
      );
    }

    if (
      proof.tenantId !== pathParams.tenantId ||
      proof.requestedByUserId !== roleCheck.principal.userId
    ) {
      return c.json(
        {
          error: "Forbidden identity link token",
        },
        403,
      );
    }

    const existingProfile = await findLearnerProfileByIdentity(db, {
      tenantId: pathParams.tenantId,
      identityType: proof.identityType,
      identityValue: proof.identityValue,
    });

    // Identity-link proof completion also rejects cross-profile conflicts instead of reparenting.
    if (existingProfile !== null && existingProfile.id !== proof.learnerProfileId) {
      return c.json(
        {
          error: "Email is already linked to a different learner profile",
        },
        409,
      );
    }

    if (existingProfile === null) {
      await addLearnerIdentityAlias(db, {
        tenantId: pathParams.tenantId,
        learnerProfileId: proof.learnerProfileId,
        identityType: proof.identityType,
        identityValue: proof.identityValue,
        isPrimary: true,
        isVerified: true,
      });
    }

    await markLearnerIdentityLinkProofUsed(db, proof.id, nowIso);

    return c.json({
      status: existingProfile === null ? "linked" : "already_linked",
      tenantId: pathParams.tenantId,
      learnerProfileId: proof.learnerProfileId,
      identityType: proof.identityType,
      identityValue: proof.identityValue,
    });
  });
};
