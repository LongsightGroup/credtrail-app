import { createDidWeb } from "@credtrail/core-domain";
import {
  createDedicatedDbProvisioningRequest,
  createAuditLog,
  deleteLtiIssuerRegistrationByIssuer,
  findTenantCanvasGradebookIntegration,
  listAuditLogs,
  listDedicatedDbProvisioningRequests,
  listLtiIssuerRegistrations,
  resolveDedicatedDbProvisioningRequest,
  updateTenantCanvasGradebookIntegrationTokens,
  upsertBadgeTemplateById,
  upsertTenantCanvasGradebookIntegration,
  upsertLtiIssuerRegistration,
  upsertTenant,
  upsertTenantMembershipRole,
  upsertTenantSigningRegistration,
  type AuditLogRecord,
  type SqlDatabase,
} from "@credtrail/db";
import type { Hono } from "hono";
import {
  type AdminAuditLogListQuery,
  parseAdminCanvasOAuthAuthorizeUrlRequest,
  parseAdminCanvasOAuthExchangeRequest,
  parseCreateDedicatedDbProvisioningRequest,
  parseAdminAuditLogListQuery,
  parseAdminDeleteLtiIssuerRegistrationRequest,
  parseAdminUpsertBadgeTemplateByIdRequest,
  parseUpsertTenantCanvasGradebookIntegrationRequest,
  parseAdminUpsertLtiIssuerRegistrationRequest,
  parseAdminUpsertTenantMembershipRoleRequest,
  parseAdminUpsertTenantRequest,
  parseAdminUpsertTenantSigningRegistrationRequest,
  parseResolveDedicatedDbProvisioningRequest,
  parseBadgeTemplatePathParams,
  parseTenantDedicatedDbProvisioningRequestPathParams,
  parseTenantCanvasGradebookSnapshotQuery,
  parseTenantPathParams,
  parseTenantUserPathParams,
} from "@credtrail/validation";
import type { AppBindings, AppContext, AppEnv } from "../app";
import { renderAppPage } from "../ui/render-page";
import { auditLogAdminPage, type AuditLogAdminPageFilterState } from "../admin/pages";
import { createGradebookProvider } from "../lms/gradebook-provider";
import {
  canvasOAuthStateSigningSecret,
  exchangeCanvasAuthorizationCode,
  refreshCanvasAccessToken,
  signCanvasOAuthStatePayload,
  validateCanvasOAuthStateToken,
} from "../lms/canvas-oauth";
import { normalizeLtiIssuer } from "../lti/lti-helpers";
import { ltiIssuerRegistrationAdminPage, type LtiIssuerRegistrationFormState } from "../lti/pages";

interface RegisterAdminRoutesInput {
  app: Hono<AppEnv>;
  requireBootstrapAdmin: (c: AppContext) => Response | null;
  requireBootstrapAdminUiToken: (c: AppContext, token: string | null) => Response | null;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  isUniqueConstraintError: (error: unknown) => boolean;
}

export const registerAdminRoutes = (input: RegisterAdminRoutesInput): void => {
  const {
    app,
    requireBootstrapAdmin,
    requireBootstrapAdminUiToken,
    resolveDatabase,
    isUniqueConstraintError,
  } = input;

  const ltiIssuerRegistrationAdminPageResponse = async (
    c: AppContext,
    input: {
      token: string;
      submissionError?: string;
      formState?: LtiIssuerRegistrationFormState;
      status?: 200 | 400;
    },
  ): Promise<Response> => {
    const registrations = await listLtiIssuerRegistrations(resolveDatabase(c.env));
    const page = ltiIssuerRegistrationAdminPage({
      token: input.token,
      registrations,
      ...(input.submissionError === undefined ? {} : { submissionError: input.submissionError }),
      ...(input.formState === undefined ? {} : { formState: input.formState }),
    });
    return renderAppPage(c, page, input.status ?? 200);
  };

  const auditLogAdminPageResponse = (
    c: AppContext,
    input: {
      token: string;
      filterState: AuditLogAdminPageFilterState;
      logs: readonly AuditLogRecord[];
      status?: 200 | 400;
      submissionError?: string;
    },
  ): Response | Promise<Response> => {
    const page = auditLogAdminPage({
      token: input.token,
      filterState: input.filterState,
      logs: input.logs,
      ...(input.submissionError === undefined ? {} : { submissionError: input.submissionError }),
    });
    return renderAppPage(c, page, input.status ?? 200);
  };

  const addSecondsToIso = (fromIso: string, seconds: number): string => {
    const fromMs = Date.parse(fromIso);

    if (!Number.isFinite(fromMs)) {
      throw new Error("Invalid timestamp");
    }

    return new Date(fromMs + seconds * 1000).toISOString();
  };

  const generateNonce = (): string => {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    let raw = "";

    for (const byte of bytes) {
      raw += String.fromCharCode(byte);
    }

    return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  };

  const canvasIntegrationApiResponse = (
    integration: Awaited<ReturnType<typeof findTenantCanvasGradebookIntegration>>,
  ): Record<string, unknown> | null => {
    if (integration === null) {
      return null;
    }

    return {
      tenantId: integration.tenantId,
      apiBaseUrl: integration.apiBaseUrl,
      authorizationEndpoint: integration.authorizationEndpoint,
      tokenEndpoint: integration.tokenEndpoint,
      clientId: integration.clientId,
      scope: integration.scope,
      hasClientSecret: integration.clientSecret.length > 0,
      hasAccessToken: integration.accessToken !== null,
      hasRefreshToken: integration.refreshToken !== null,
      accessTokenExpiresAt: integration.accessTokenExpiresAt,
      refreshTokenExpiresAt: integration.refreshTokenExpiresAt,
      connectedAt: integration.connectedAt,
      createdAt: integration.createdAt,
      updatedAt: integration.updatedAt,
    };
  };

  const ltiIssuerRegistrationApiResponse = (
    registration: Awaited<ReturnType<typeof upsertLtiIssuerRegistration>>,
  ): Record<string, unknown> => {
    return {
      issuer: registration.issuer,
      tenantId: registration.tenantId,
      authorizationEndpoint: registration.authorizationEndpoint,
      clientId: registration.clientId,
      platformJwksEndpoint: registration.platformJwksEndpoint,
      tokenEndpoint: registration.tokenEndpoint,
      createdAt: registration.createdAt,
      updatedAt: registration.updatedAt,
    };
  };

  app.put("/v1/admin/tenants/:tenantId", async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    const pathParams = parseTenantPathParams(c.req.param());
    const payload = await c.req.json<unknown>();
    const request = parseAdminUpsertTenantRequest(payload);
    const issuerDomain = request.issuerDomain ?? `${request.slug}.${c.env.PLATFORM_DOMAIN}`;
    const didWeb = createDidWeb({
      host: c.env.PLATFORM_DOMAIN,
      pathSegments: [pathParams.tenantId],
    });

    try {
      const tenant = await upsertTenant(resolveDatabase(c.env), {
        id: pathParams.tenantId,
        slug: request.slug,
        displayName: request.displayName,
        planTier: request.planTier ?? "team",
        issuerDomain,
        didWeb,
        isActive: request.isActive,
      });

      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        action: "tenant.upserted",
        targetType: "tenant",
        targetId: pathParams.tenantId,
        metadata: {
          slug: tenant.slug,
          displayName: tenant.displayName,
          planTier: tenant.planTier,
          issuerDomain: tenant.issuerDomain,
          didWeb: tenant.didWeb,
          isActive: tenant.isActive,
        },
      });

      return c.json(
        {
          tenant,
        },
        201,
      );
    } catch (error: unknown) {
      if (isUniqueConstraintError(error)) {
        return c.json(
          {
            error: "Tenant slug or issuer domain is already in use",
          },
          409,
        );
      }

      throw error;
    }
  });

  app.put("/v1/admin/tenants/:tenantId/signing-registration", async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    const pathParams = parseTenantPathParams(c.req.param());
    const payload = await c.req.json<unknown>();
    const request = parseAdminUpsertTenantSigningRegistrationRequest(payload);
    const did = createDidWeb({
      host: c.env.PLATFORM_DOMAIN,
      pathSegments: [pathParams.tenantId],
    });

    try {
      const registration = await upsertTenantSigningRegistration(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        did,
        keyId: request.keyId,
        publicJwkJson: JSON.stringify(request.publicJwk),
        ...(request.privateJwk === undefined
          ? {}
          : {
              privateJwkJson: JSON.stringify(request.privateJwk),
            }),
      });

      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        action: "tenant.signing_registration_upserted",
        targetType: "tenant_signing_registration",
        targetId: pathParams.tenantId,
        metadata: {
          did: registration.did,
          keyId: registration.keyId,
          hasPrivateKey: registration.privateJwkJson !== null,
        },
      });

      return c.json(
        {
          tenantId: registration.tenantId,
          did: registration.did,
          keyId: registration.keyId,
          hasPrivateKey: registration.privateJwkJson !== null,
        },
        201,
      );
    } catch (error: unknown) {
      if (isUniqueConstraintError(error)) {
        return c.json(
          {
            error: "Signing registration conflicts with another tenant DID",
          },
          409,
        );
      }

      throw error;
    }
  });

  app.put("/v1/admin/tenants/:tenantId/badge-templates/:badgeTemplateId", async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    const payload = await c.req.json<unknown>();
    const request = parseAdminUpsertBadgeTemplateByIdRequest(payload);

    try {
      const template = await upsertBadgeTemplateById(resolveDatabase(c.env), {
        id: pathParams.badgeTemplateId,
        tenantId: pathParams.tenantId,
        slug: request.slug,
        title: request.title,
        description: request.description,
        criteriaUri: request.criteriaUri,
        imageUri: request.imageUri,
        ownerOrgUnitId: request.ownerOrgUnitId,
      });

      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        action: "badge_template.upserted",
        targetType: "badge_template",
        targetId: pathParams.badgeTemplateId,
        metadata: {
          slug: template.slug,
          title: template.title,
          description: template.description,
          criteriaUri: template.criteriaUri,
          imageUri: template.imageUri,
          ownerOrgUnitId: template.ownerOrgUnitId,
        },
      });

      return c.json(
        {
          tenantId: pathParams.tenantId,
          template,
        },
        201,
      );
    } catch (error: unknown) {
      if (isUniqueConstraintError(error)) {
        return c.json(
          {
            error: "Badge template slug already exists for tenant",
          },
          409,
        );
      }

      if (
        error instanceof Error &&
        ((error.message.includes("Org unit") && error.message.includes("not found for tenant")) ||
          error.message.includes("ownership changes must use transferBadgeTemplateOwnership"))
      ) {
        return c.json(
          {
            error: error.message,
          },
          422,
        );
      }

      throw error;
    }
  });

  app.put("/v1/admin/tenants/:tenantId/users/:userId/role", async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    const pathParams = parseTenantUserPathParams(c.req.param());
    const payload = await c.req.json<unknown>();
    const request = parseAdminUpsertTenantMembershipRoleRequest(payload);
    const roleResult = await upsertTenantMembershipRole(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      role: request.role,
    });

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      action:
        roleResult.previousRole === null
          ? "membership.role_assigned"
          : roleResult.previousRole === roleResult.membership.role
            ? "membership.role_reasserted"
            : "membership.role_changed",
      targetType: "membership",
      targetId: `${pathParams.tenantId}:${pathParams.userId}`,
      metadata: {
        userId: pathParams.userId,
        previousRole: roleResult.previousRole,
        role: roleResult.membership.role,
        changed: roleResult.changed,
      },
    });

    return c.json(
      {
        tenantId: pathParams.tenantId,
        userId: pathParams.userId,
        role: roleResult.membership.role,
        previousRole: roleResult.previousRole,
        changed: roleResult.changed,
      },
      201,
    );
  });

  app.get("/v1/admin/tenants/:tenantId/lms/canvas/config", async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    const pathParams = parseTenantPathParams(c.req.param());
    const integration = await findTenantCanvasGradebookIntegration(
      resolveDatabase(c.env),
      pathParams.tenantId,
    );

    if (integration === null) {
      return c.json(
        {
          error: "Canvas gradebook integration not found",
        },
        404,
      );
    }

    return c.json({
      tenantId: pathParams.tenantId,
      integration: canvasIntegrationApiResponse(integration),
    });
  });

  app.put("/v1/admin/tenants/:tenantId/lms/canvas/config", async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    const pathParams = parseTenantPathParams(c.req.param());
    let request;

    try {
      request = parseUpsertTenantCanvasGradebookIntegrationRequest(await c.req.json<unknown>());
    } catch (error) {
      return c.json(
        {
          error: error instanceof Error ? error.message : "Invalid Canvas integration payload",
        },
        400,
      );
    }

    const integration = await upsertTenantCanvasGradebookIntegration(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      apiBaseUrl: request.apiBaseUrl,
      authorizationEndpoint: request.authorizationEndpoint,
      tokenEndpoint: request.tokenEndpoint,
      clientId: request.clientId,
      clientSecret: request.clientSecret,
      scope:
        request.scope ??
        "url:GET|/api/v1/courses url:GET|/api/v1/courses/:course_id/enrollments url:GET|/api/v1/courses/:course_id/assignments",
    });

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      action: "tenant.canvas_gradebook_integration_upserted",
      targetType: "tenant_canvas_gradebook_integration",
      targetId: pathParams.tenantId,
      metadata: {
        apiBaseUrl: integration.apiBaseUrl,
        authorizationEndpoint: integration.authorizationEndpoint,
        tokenEndpoint: integration.tokenEndpoint,
        clientId: integration.clientId,
        scope: integration.scope,
        hasAccessToken: integration.accessToken !== null,
        hasRefreshToken: integration.refreshToken !== null,
      },
    });

    return c.json(
      {
        tenantId: pathParams.tenantId,
        integration: canvasIntegrationApiResponse(integration),
      },
      201,
    );
  });

  app.post("/v1/admin/tenants/:tenantId/lms/canvas/oauth/authorize-url", async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    const pathParams = parseTenantPathParams(c.req.param());
    const integration = await findTenantCanvasGradebookIntegration(
      resolveDatabase(c.env),
      pathParams.tenantId,
    );

    if (integration === null) {
      return c.json(
        {
          error: "Canvas gradebook integration not found",
        },
        404,
      );
    }

    const requestPayload = await c.req.json<unknown>().catch(() => ({}));
    let request;

    try {
      request = parseAdminCanvasOAuthAuthorizeUrlRequest(requestPayload);
    } catch (error) {
      return c.json(
        {
          error: error instanceof Error ? error.message : "Invalid OAuth authorize payload",
        },
        400,
      );
    }

    const defaultRedirectUri = new URL(
      `/v1/admin/tenants/${encodeURIComponent(pathParams.tenantId)}/lms/canvas/oauth/exchange`,
      c.req.url,
    ).toString();
    const redirectUri = request.redirectUri ?? defaultRedirectUri;
    const nowIso = new Date().toISOString();
    const expiresAt = addSecondsToIso(nowIso, 10 * 60);
    const stateToken = await signCanvasOAuthStatePayload(
      {
        tenantId: pathParams.tenantId,
        nonce: generateNonce(),
        issuedAt: nowIso,
        expiresAt,
      },
      canvasOAuthStateSigningSecret(c.env),
    );

    const authorizationUrl = new URL(integration.authorizationEndpoint);
    authorizationUrl.searchParams.set("response_type", "code");
    authorizationUrl.searchParams.set("client_id", integration.clientId);
    authorizationUrl.searchParams.set("redirect_uri", redirectUri);
    authorizationUrl.searchParams.set("scope", integration.scope);
    authorizationUrl.searchParams.set("state", stateToken);

    return c.json({
      tenantId: pathParams.tenantId,
      authorizationUrl: authorizationUrl.toString(),
      state: stateToken,
      redirectUri,
      expiresAt,
    });
  });

  app.post("/v1/admin/tenants/:tenantId/lms/canvas/oauth/exchange", async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    const pathParams = parseTenantPathParams(c.req.param());
    let request;

    try {
      request = parseAdminCanvasOAuthExchangeRequest(await c.req.json<unknown>());
    } catch (error) {
      return c.json(
        {
          error: error instanceof Error ? error.message : "Invalid OAuth exchange payload",
        },
        400,
      );
    }

    const integration = await findTenantCanvasGradebookIntegration(
      resolveDatabase(c.env),
      pathParams.tenantId,
    );

    if (integration === null) {
      return c.json(
        {
          error: "Canvas gradebook integration not found",
        },
        404,
      );
    }

    const nowIso = new Date().toISOString();
    const stateValidation = await validateCanvasOAuthStateToken(
      request.state,
      canvasOAuthStateSigningSecret(c.env),
      nowIso,
    );

    if (
      stateValidation.status !== "ok" ||
      stateValidation.payload.tenantId !== pathParams.tenantId
    ) {
      return c.json(
        {
          error:
            stateValidation.status === "ok"
              ? "OAuth state token does not match tenant"
              : stateValidation.reason,
        },
        400,
      );
    }

    const defaultRedirectUri = new URL(
      `/v1/admin/tenants/${encodeURIComponent(pathParams.tenantId)}/lms/canvas/oauth/exchange`,
      c.req.url,
    ).toString();
    const redirectUri = request.redirectUri ?? defaultRedirectUri;

    let tokenResponse;

    try {
      tokenResponse = await exchangeCanvasAuthorizationCode({
        tokenEndpoint: integration.tokenEndpoint,
        clientId: integration.clientId,
        clientSecret: integration.clientSecret,
        code: request.code,
        redirectUri,
      });
    } catch (error) {
      return c.json(
        {
          error: error instanceof Error ? error.message : "Canvas OAuth token exchange failed",
        },
        502,
      );
    }

    const accessTokenExpiresAt =
      tokenResponse.expiresInSeconds === undefined
        ? undefined
        : addSecondsToIso(nowIso, tokenResponse.expiresInSeconds);
    const refreshTokenExpiresAt =
      tokenResponse.refreshTokenExpiresInSeconds === undefined
        ? undefined
        : addSecondsToIso(nowIso, tokenResponse.refreshTokenExpiresInSeconds);
    const updatedIntegration = await updateTenantCanvasGradebookIntegrationTokens(
      resolveDatabase(c.env),
      {
        tenantId: pathParams.tenantId,
        accessToken: tokenResponse.accessToken,
        refreshToken: tokenResponse.refreshToken,
        accessTokenExpiresAt,
        refreshTokenExpiresAt,
      },
    );

    if (updatedIntegration === null) {
      return c.json(
        {
          error: "Canvas gradebook integration not found",
        },
        404,
      );
    }

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      action: "tenant.canvas_gradebook_oauth_connected",
      targetType: "tenant_canvas_gradebook_integration",
      targetId: pathParams.tenantId,
      metadata: {
        scope: tokenResponse.scope ?? updatedIntegration.scope,
        accessTokenExpiresAt: updatedIntegration.accessTokenExpiresAt,
        refreshTokenExpiresAt: updatedIntegration.refreshTokenExpiresAt,
        connectedAt: updatedIntegration.connectedAt,
      },
    });

    return c.json({
      tenantId: pathParams.tenantId,
      status: "connected",
      integration: canvasIntegrationApiResponse(updatedIntegration),
    });
  });

  app.get("/v1/admin/tenants/:tenantId/lms/canvas/gradebook/snapshot", async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    const pathParams = parseTenantPathParams(c.req.param());
    let query;

    try {
      query = parseTenantCanvasGradebookSnapshotQuery({
        courseId: c.req.query("courseId"),
        learnerId: c.req.query("learnerId"),
        assignmentId: c.req.query("assignmentId"),
      });
    } catch (error) {
      return c.json(
        {
          error: error instanceof Error ? error.message : "Invalid gradebook snapshot query",
        },
        400,
      );
    }

    if (query.assignmentId !== undefined && query.courseId === undefined) {
      return c.json(
        {
          error: "assignmentId requires courseId",
        },
        400,
      );
    }

    const db = resolveDatabase(c.env);
    const integration = await findTenantCanvasGradebookIntegration(db, pathParams.tenantId);

    if (integration === null) {
      return c.json(
        {
          error: "Canvas gradebook integration not found",
        },
        404,
      );
    }

    let accessToken = integration.accessToken;
    const nowIso = new Date().toISOString();
    const accessTokenExpired =
      integration.accessTokenExpiresAt !== null &&
      Number.isFinite(Date.parse(integration.accessTokenExpiresAt)) &&
      Date.parse(integration.accessTokenExpiresAt) <= Date.parse(nowIso);

    if ((accessToken === null || accessTokenExpired) && integration.refreshToken !== null) {
      try {
        const refreshed = await refreshCanvasAccessToken({
          tokenEndpoint: integration.tokenEndpoint,
          clientId: integration.clientId,
          clientSecret: integration.clientSecret,
          refreshToken: integration.refreshToken,
        });
        const updatedIntegration = await updateTenantCanvasGradebookIntegrationTokens(db, {
          tenantId: integration.tenantId,
          accessToken: refreshed.accessToken,
          refreshToken: refreshed.refreshToken,
          accessTokenExpiresAt:
            refreshed.expiresInSeconds === undefined
              ? undefined
              : addSecondsToIso(nowIso, refreshed.expiresInSeconds),
          refreshTokenExpiresAt:
            refreshed.refreshTokenExpiresInSeconds === undefined
              ? undefined
              : addSecondsToIso(nowIso, refreshed.refreshTokenExpiresInSeconds),
        });

        if (updatedIntegration === null) {
          return c.json(
            {
              error: "Canvas gradebook integration not found",
            },
            404,
          );
        }

        accessToken = updatedIntegration.accessToken;
      } catch (error) {
        return c.json(
          {
            error: error instanceof Error ? error.message : "Canvas access token refresh failed",
          },
          502,
        );
      }
    }

    if (accessToken === null) {
      return c.json(
        {
          error: "Canvas integration is not connected. Complete OAuth exchange first.",
        },
        409,
      );
    }

    const gradebookProvider = createGradebookProvider({
      config: {
        kind: "canvas",
        apiBaseUrl: integration.apiBaseUrl,
        accessToken,
      },
    });
    const courses = await gradebookProvider.listCourses();

    if (query.courseId === undefined) {
      return c.json({
        tenantId: pathParams.tenantId,
        provider: "canvas",
        generatedAt: nowIso,
        courses,
      });
    }

    const assignments = await gradebookProvider.listAssignments({
      courseId: query.courseId,
    });
    const learnerFilter = query.learnerId === undefined ? {} : { learnerId: query.learnerId };
    const assignmentFilter =
      query.assignmentId === undefined ? {} : { assignmentId: query.assignmentId };

    const enrollments = await gradebookProvider.listEnrollments({
      courseId: query.courseId,
      ...learnerFilter,
    });
    const grades = await gradebookProvider.listGrades({
      courseId: query.courseId,
      ...learnerFilter,
    });
    const completions = await gradebookProvider.listCompletions({
      courseId: query.courseId,
      ...learnerFilter,
    });
    const submissions = await gradebookProvider.listSubmissions({
      courseId: query.courseId,
      ...assignmentFilter,
      ...learnerFilter,
    });

    return c.json({
      tenantId: pathParams.tenantId,
      provider: "canvas",
      generatedAt: nowIso,
      courses,
      assignments,
      enrollments,
      grades,
      completions,
      submissions,
      badgeCriteriaFacts: {
        courseCompletionFacts: completions.map((completion) => ({
          courseId: completion.courseId,
          learnerId: completion.learnerId,
          completed: completion.completed,
          completionPercent: completion.completionPercent,
          sourceState: completion.sourceState,
        })),
        courseGradeFacts: grades.map((grade) => ({
          courseId: grade.courseId,
          learnerId: grade.learnerId,
          finalScore: grade.finalScore,
          currentScore: grade.currentScore,
          finalGrade: grade.finalGrade,
          currentGrade: grade.currentGrade,
        })),
        assignmentSubmissionFacts: submissions.map((submission) => ({
          courseId: submission.courseId,
          assignmentId: submission.assignmentId,
          learnerId: submission.learnerId,
          score: submission.score,
          workflowState: submission.workflowState,
          submittedAt: submission.submittedAt,
          gradedAt: submission.gradedAt,
        })),
      },
    });
  });

  app.get("/v1/admin/lti/issuer-registrations", async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    const registrations = await listLtiIssuerRegistrations(resolveDatabase(c.env));

    return c.json({
      registrations: registrations.map((registration) =>
        ltiIssuerRegistrationApiResponse(registration),
      ),
    });
  });

  app.get("/v1/admin/audit-logs", async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    let query: AdminAuditLogListQuery;

    try {
      query = parseAdminAuditLogListQuery({
        tenantId: c.req.query("tenantId"),
        action: c.req.query("action"),
        limit: c.req.query("limit"),
      });
    } catch (error) {
      return c.json(
        {
          error: error instanceof Error ? error.message : "Invalid audit log query parameters",
        },
        400,
      );
    }

    const logs = await listAuditLogs(resolveDatabase(c.env), query);

    return c.json({
      tenantId: query.tenantId,
      action: query.action ?? null,
      limit: query.limit,
      logs,
    });
  });

  app.get("/v1/admin/tenants/:tenantId/dedicated-db/provisioning-requests", async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    const pathParams = parseTenantPathParams(c.req.param());
    const statusCandidate = c.req.query("status");
    const status =
      statusCandidate === "pending" ||
      statusCandidate === "provisioned" ||
      statusCandidate === "failed" ||
      statusCandidate === "canceled"
        ? statusCandidate
        : undefined;

    if (statusCandidate !== undefined && status === undefined) {
      return c.json(
        {
          error: "status must be one of pending, provisioned, failed, canceled",
        },
        400,
      );
    }

    const requests = await listDedicatedDbProvisioningRequests(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      ...(status === undefined ? {} : { status }),
    });

    return c.json({
      tenantId: pathParams.tenantId,
      requests,
    });
  });

  app.post("/v1/admin/tenants/:tenantId/dedicated-db/provisioning-requests", async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    const pathParams = parseTenantPathParams(c.req.param());
    let request;

    try {
      request = parseCreateDedicatedDbProvisioningRequest(await c.req.json<unknown>());
    } catch (error) {
      return c.json(
        {
          error: error instanceof Error ? error.message : "Invalid provisioning request payload",
        },
        400,
      );
    }

    const provisioningRequest = await createDedicatedDbProvisioningRequest(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      targetRegion: request.targetRegion,
      notes: request.notes,
    });

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      action: "tenant.dedicated_db_provisioning_requested",
      targetType: "tenant_dedicated_db_provisioning_request",
      targetId: provisioningRequest.id,
      metadata: {
        targetRegion: provisioningRequest.targetRegion,
        notes: provisioningRequest.notes,
      },
    });

    return c.json(
      {
        tenantId: pathParams.tenantId,
        request: provisioningRequest,
      },
      201,
    );
  });

  app.post(
    "/v1/admin/tenants/:tenantId/dedicated-db/provisioning-requests/:requestId/resolve",
    async (c) => {
      const unauthorizedResponse = requireBootstrapAdmin(c);

      if (unauthorizedResponse !== null) {
        return unauthorizedResponse;
      }

      const pathParams = parseTenantDedicatedDbProvisioningRequestPathParams(c.req.param());
      let request;

      try {
        request = parseResolveDedicatedDbProvisioningRequest(await c.req.json<unknown>());
      } catch (error) {
        return c.json(
          {
            error: error instanceof Error ? error.message : "Invalid provisioning resolve payload",
          },
          400,
        );
      }

      const resolved = await resolveDedicatedDbProvisioningRequest(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        requestId: pathParams.requestId,
        status: request.status,
        dedicatedDatabaseUrl: request.dedicatedDatabaseUrl,
        notes: request.notes,
        resolvedAt: request.resolvedAt,
      });

      if (resolved === null) {
        return c.json(
          {
            error: "Provisioning request not found",
          },
          404,
        );
      }

      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        action: "tenant.dedicated_db_provisioning_resolved",
        targetType: "tenant_dedicated_db_provisioning_request",
        targetId: resolved.id,
        metadata: {
          status: resolved.status,
          targetRegion: resolved.targetRegion,
          dedicatedDatabaseUrl: resolved.dedicatedDatabaseUrl,
          resolvedAt: resolved.resolvedAt,
          notes: resolved.notes,
        },
      });

      return c.json({
        tenantId: pathParams.tenantId,
        request: resolved,
      });
    },
  );

  app.get("/admin/audit-logs", async (c) => {
    const token = c.req.query("token") ?? null;
    const unauthorizedResponse = requireBootstrapAdminUiToken(c, token);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    if (token === null) {
      return c.json(
        {
          error: "Unauthorized",
        },
        401,
      );
    }

    const tenantId = c.req.query("tenantId");
    const action = c.req.query("action");
    const limitRaw = c.req.query("limit");
    const limitParsed = limitRaw === undefined ? undefined : Number(limitRaw);
    const filterState: AuditLogAdminPageFilterState = {
      ...(tenantId === undefined ? {} : { tenantId }),
      ...(action === undefined ? {} : { action }),
      ...(typeof limitParsed === "number" && Number.isFinite(limitParsed)
        ? {
            limit: Math.trunc(limitParsed),
          }
        : {}),
    };
    const hasAnyFilter = tenantId !== undefined || action !== undefined || limitRaw !== undefined;

    if (!hasAnyFilter) {
      return auditLogAdminPageResponse(c, {
        token,
        filterState: {},
        logs: [],
      });
    }

    let query: AdminAuditLogListQuery;

    try {
      query = parseAdminAuditLogListQuery({
        tenantId,
        action,
        limit: limitRaw,
      });
    } catch (error) {
      return auditLogAdminPageResponse(c, {
        token,
        filterState,
        logs: [],
        status: 400,
        submissionError: error instanceof Error ? error.message : "Invalid audit log filters",
      });
    }

    const logs = await listAuditLogs(resolveDatabase(c.env), query);

    return auditLogAdminPageResponse(c, {
      token,
      filterState,
      logs,
    });
  });

  app.put("/v1/admin/lti/issuer-registrations", async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    const payload = await c.req.json<unknown>();
    const request = parseAdminUpsertLtiIssuerRegistrationRequest(payload);
    const registration = await upsertLtiIssuerRegistration(resolveDatabase(c.env), {
      issuer: request.issuer,
      tenantId: request.tenantId,
      authorizationEndpoint: request.authorizationEndpoint,
      clientId: request.clientId,
      platformJwksEndpoint: request.platformJwksEndpoint,
      tokenEndpoint: request.tokenEndpoint,
    });

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: registration.tenantId,
      action: "lti.issuer_registration_upserted",
      targetType: "lti_issuer_registration",
      targetId: registration.issuer,
      metadata: {
        issuer: registration.issuer,
        tenantId: registration.tenantId,
        clientId: registration.clientId,
        authorizationEndpoint: registration.authorizationEndpoint,
        platformJwksEndpoint: registration.platformJwksEndpoint,
        tokenEndpoint: registration.tokenEndpoint,
      },
    });

    return c.json(
      {
        registration: ltiIssuerRegistrationApiResponse(registration),
      },
      201,
    );
  });

  app.delete("/v1/admin/lti/issuer-registrations", async (c) => {
    const unauthorizedResponse = requireBootstrapAdmin(c);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    const payload = await c.req.json<unknown>();
    const request = parseAdminDeleteLtiIssuerRegistrationRequest(payload);
    const normalizedIssuer = normalizeLtiIssuer(request.issuer);
    const registrations = await listLtiIssuerRegistrations(resolveDatabase(c.env));
    const existingRegistration =
      registrations.find(
        (registration) => normalizeLtiIssuer(registration.issuer) === normalizedIssuer,
      ) ?? null;
    const deleted = await deleteLtiIssuerRegistrationByIssuer(
      resolveDatabase(c.env),
      request.issuer,
    );

    if (deleted && existingRegistration !== null) {
      await createAuditLog(resolveDatabase(c.env), {
        tenantId: existingRegistration.tenantId,
        action: "lti.issuer_registration_deleted",
        targetType: "lti_issuer_registration",
        targetId: normalizedIssuer,
        metadata: {
          issuer: normalizedIssuer,
          tenantId: existingRegistration.tenantId,
        },
      });
    }

    return c.json({
      status: deleted ? "deleted" : "not_found",
      issuer: normalizedIssuer,
    });
  });

  app.get("/admin/lti/issuer-registrations", async (c) => {
    const token = c.req.query("token") ?? null;
    const unauthorizedResponse = requireBootstrapAdminUiToken(c, token);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    if (token === null) {
      return c.json(
        {
          error: "Unauthorized",
        },
        401,
      );
    }

    return ltiIssuerRegistrationAdminPageResponse(c, {
      token,
    });
  });

  app.post("/admin/lti/issuer-registrations", async (c) => {
    const contentType = c.req.header("content-type") ?? "";

    if (!contentType.toLowerCase().includes("application/x-www-form-urlencoded")) {
      return c.json(
        {
          error: "Content-Type must be application/x-www-form-urlencoded",
        },
        400,
      );
    }

    const rawBody = await c.req.text();
    const formData = new URLSearchParams(rawBody);
    const token = formData.get("token");
    const unauthorizedResponse = requireBootstrapAdminUiToken(c, token);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    if (token === null) {
      return c.json(
        {
          error: "Unauthorized",
        },
        401,
      );
    }

    const formState: LtiIssuerRegistrationFormState = {
      issuer: formData.get("issuer") ?? "",
      tenantId: formData.get("tenantId") ?? "",
      authorizationEndpoint: formData.get("authorizationEndpoint") ?? "",
      clientId: formData.get("clientId") ?? "",
      platformJwksEndpoint: formData.get("platformJwksEndpoint") ?? "",
      tokenEndpoint: formData.get("tokenEndpoint") ?? "",
    };
    const parsedPlatformJwksEndpoint = formState.platformJwksEndpoint?.trim() ?? "";
    const parsedTokenEndpoint = formState.tokenEndpoint?.trim() ?? "";

    let request;

    try {
      request = parseAdminUpsertLtiIssuerRegistrationRequest({
        issuer: formState.issuer,
        tenantId: formState.tenantId,
        authorizationEndpoint: formState.authorizationEndpoint,
        clientId: formState.clientId,
        ...(parsedPlatformJwksEndpoint.length === 0
          ? {}
          : { platformJwksEndpoint: parsedPlatformJwksEndpoint }),
        ...(parsedTokenEndpoint.length === 0 ? {} : { tokenEndpoint: parsedTokenEndpoint }),
      });
    } catch (error) {
      return ltiIssuerRegistrationAdminPageResponse(c, {
        token,
        status: 400,
        submissionError:
          error instanceof Error ? error.message : "Invalid LTI registration payload",
        formState,
      });
    }

    const registration = await upsertLtiIssuerRegistration(resolveDatabase(c.env), {
      issuer: request.issuer,
      tenantId: request.tenantId,
      authorizationEndpoint: request.authorizationEndpoint,
      clientId: request.clientId,
      platformJwksEndpoint: request.platformJwksEndpoint,
      tokenEndpoint: request.tokenEndpoint,
    });

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: registration.tenantId,
      action: "lti.issuer_registration_upserted",
      targetType: "lti_issuer_registration",
      targetId: registration.issuer,
      metadata: {
        issuer: registration.issuer,
        tenantId: registration.tenantId,
        clientId: registration.clientId,
        authorizationEndpoint: registration.authorizationEndpoint,
        platformJwksEndpoint: registration.platformJwksEndpoint,
        tokenEndpoint: registration.tokenEndpoint,
      },
    });

    return c.redirect(`/admin/lti/issuer-registrations?token=${encodeURIComponent(token)}`, 303);
  });

  app.post("/admin/lti/issuer-registrations/delete", async (c) => {
    const contentType = c.req.header("content-type") ?? "";

    if (!contentType.toLowerCase().includes("application/x-www-form-urlencoded")) {
      return c.json(
        {
          error: "Content-Type must be application/x-www-form-urlencoded",
        },
        400,
      );
    }

    const rawBody = await c.req.text();
    const formData = new URLSearchParams(rawBody);
    const token = formData.get("token");
    const unauthorizedResponse = requireBootstrapAdminUiToken(c, token);

    if (unauthorizedResponse !== null) {
      return unauthorizedResponse;
    }

    if (token === null) {
      return c.json(
        {
          error: "Unauthorized",
        },
        401,
      );
    }

    const issuerCandidate = formData.get("issuer");

    if (issuerCandidate === null) {
      return ltiIssuerRegistrationAdminPageResponse(c, {
        token,
        status: 400,
        submissionError: "issuer is required",
      });
    }

    let request;

    try {
      request = parseAdminDeleteLtiIssuerRegistrationRequest({
        issuer: issuerCandidate,
      });
    } catch (error) {
      return ltiIssuerRegistrationAdminPageResponse(c, {
        token,
        status: 400,
        submissionError: error instanceof Error ? error.message : "Invalid issuer value",
      });
    }

    const normalizedIssuer = normalizeLtiIssuer(request.issuer);
    const registrations = await listLtiIssuerRegistrations(resolveDatabase(c.env));
    const existingRegistration =
      registrations.find(
        (registration) => normalizeLtiIssuer(registration.issuer) === normalizedIssuer,
      ) ?? null;
    const deleted = await deleteLtiIssuerRegistrationByIssuer(
      resolveDatabase(c.env),
      request.issuer,
    );

    if (deleted && existingRegistration !== null) {
      await createAuditLog(resolveDatabase(c.env), {
        tenantId: existingRegistration.tenantId,
        action: "lti.issuer_registration_deleted",
        targetType: "lti_issuer_registration",
        targetId: normalizedIssuer,
        metadata: {
          issuer: normalizedIssuer,
          tenantId: existingRegistration.tenantId,
        },
      });
    }

    return c.redirect(`/admin/lti/issuer-registrations?token=${encodeURIComponent(token)}`, 303);
  });
};
