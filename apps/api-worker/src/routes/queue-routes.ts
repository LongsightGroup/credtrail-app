import {
  enqueueJobQueueMessage,
  findActiveTenantApiKeyByHash,
  touchTenantApiKeyLastUsedAt,
  type SqlDatabase,
} from "@credtrail/db";
import type { Hono } from "hono";
import {
  parseIssueBadgeRequest,
  parseProgrammaticIssueBadgeRequest,
  parseProgrammaticRevokeBadgeRequest,
  parseProcessQueueRequest,
  parseRevokeBadgeRequest,
  type IssueBadgeQueueJob,
  type ProcessQueueRequest,
  type RevokeBadgeQueueJob,
} from "@credtrail/validation";
import type { AppBindings, AppContext, AppEnv } from "../app";

interface IssueBadgeQueueEnvelope {
  assertionId: string;
  job: IssueBadgeQueueJob;
}

interface RevokeBadgeQueueEnvelope {
  revocationId: string;
  job: RevokeBadgeQueueJob;
}

interface ProcessQueueConfig {
  limit: number;
  leaseSeconds: number;
  retryDelaySeconds: number;
}

interface ProcessQueueRunResult {
  leased: number;
  processed: number;
  succeeded: number;
  retried: number;
  deadLettered: number;
  failedToFinalize: number;
}

interface ValidationIssue {
  path: unknown[];
  message: string;
}

interface RegisterQueueRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  sha256Hex: (value: string) => Promise<string>;
  readJsonBodyOrEmptyObject: (c: AppContext) => Promise<unknown>;
  processQueuedJobs: (c: AppContext, input: ProcessQueueConfig) => Promise<ProcessQueueRunResult>;
  processQueueInputWithDefaults: (input: ProcessQueueRequest) => ProcessQueueConfig;
  issueBadgeQueueJobFromRequest: (
    request: ReturnType<typeof parseIssueBadgeRequest>,
  ) => IssueBadgeQueueEnvelope;
  revokeBadgeQueueJobFromRequest: (
    request: ReturnType<typeof parseRevokeBadgeRequest>,
  ) => RevokeBadgeQueueEnvelope;
}

export const registerQueueRoutes = (input: RegisterQueueRoutesInput): void => {
  const {
    app,
    resolveDatabase,
    sha256Hex,
    readJsonBodyOrEmptyObject,
    processQueuedJobs,
    processQueueInputWithDefaults,
    issueBadgeQueueJobFromRequest,
    revokeBadgeQueueJobFromRequest,
  } = input;

  const parseApiKeyScopes = (scopesJson: string): string[] => {
    try {
      const parsed = JSON.parse(scopesJson) as unknown;

      if (!Array.isArray(parsed)) {
        return [];
      }

      return parsed.filter(
        (value): value is string => typeof value === "string" && value.length > 0,
      );
    } catch {
      return [];
    }
  };

  const isValidationError = (error: unknown): error is { issues: ValidationIssue[] } => {
    const isValidationIssue = (issue: unknown): issue is ValidationIssue => {
      if (typeof issue !== "object" || issue === null) {
        return false;
      }

      const candidate = issue as Record<string, unknown>;
      return Array.isArray(candidate.path) && typeof candidate.message === "string";
    };

    if (!(error instanceof Error) || !("issues" in error)) {
      return false;
    }

    const issues = error.issues;

    if (!Array.isArray(issues)) {
      return false;
    }

    return issues.every((issue) => isValidationIssue(issue));
  };

  const parseRequest = <T>(
    c: AppContext,
    parser: (input: unknown) => T,
    payload: unknown,
  ): { value: T } | { response: Response } => {
    try {
      return {
        value: parser(payload),
      };
    } catch (error) {
      if (isValidationError(error)) {
        return {
          response: c.json(
            {
              error: "Invalid request payload",
              details: error.issues.map((issue) => ({
                path: issue.path.map((segment) => String(segment)),
                message: issue.message,
              })),
            },
            400,
          ),
        };
      }

      throw error;
    }
  };

  const authorizeTrustedInternalRequest = (c: AppContext): Response | null => {
    const configuredToken = c.env.JOB_PROCESSOR_TOKEN?.trim();

    if (configuredToken === undefined || configuredToken.length === 0) {
      return c.json(
        {
          error: "Route unavailable",
        },
        404,
      );
    }

    const authorizationHeader = c.req.header("authorization");
    const expectedAuthorization = `Bearer ${configuredToken}`;

    if (authorizationHeader !== expectedAuthorization) {
      return c.json(
        {
          error: "Unauthorized",
        },
        401,
      );
    }

    return null;
  };

  const authorizeProgrammaticRequest = async (
    c: AppContext,
    input: {
      tenantId: string;
      requiredScope: "queue.issue" | "queue.revoke";
    },
  ): Promise<{ actorUserId: string } | { response: Response }> => {
    const rawApiKey = c.req.header("x-api-key")?.trim();

    if (rawApiKey === undefined || rawApiKey.length === 0) {
      return {
        response: c.json(
          {
            error: "x-api-key header is required",
          },
          401,
        ),
      };
    }

    const nowIso = new Date().toISOString();
    const keyHash = await sha256Hex(rawApiKey);
    const keyRecord = await findActiveTenantApiKeyByHash(resolveDatabase(c.env), {
      keyHash,
      nowIso,
    });

    if (keyRecord === null) {
      return {
        response: c.json(
          {
            error: "Invalid or expired API key",
          },
          401,
        ),
      };
    }

    if (keyRecord.tenantId !== input.tenantId) {
      return {
        response: c.json(
          {
            error: "API key tenant does not match request tenant",
          },
          403,
        ),
      };
    }

    const scopes = parseApiKeyScopes(keyRecord.scopesJson);
    const hasRequiredScope = scopes.includes("*") || scopes.includes(input.requiredScope);

    if (!hasRequiredScope) {
      return {
        response: c.json(
          {
            error: `API key is missing required scope: ${input.requiredScope}`,
          },
          403,
        ),
      };
    }

    const actorUserId = keyRecord.createdByUserId?.trim();

    if (actorUserId === undefined || actorUserId.length === 0) {
      return {
        response: c.json(
          {
            error: "API key is missing an owning user and cannot perform write operations",
          },
          403,
        ),
      };
    }

    await touchTenantApiKeyLastUsedAt(resolveDatabase(c.env), keyRecord.id, nowIso);
    return {
      actorUserId,
    };
  };

  async function enqueueQueuedJob(
    c: AppContext,
    job: IssueBadgeQueueJob | RevokeBadgeQueueJob,
  ): Promise<void> {
    await enqueueJobQueueMessage(resolveDatabase(c.env), {
      tenantId: job.tenantId,
      jobType: job.jobType,
      payload: job.payload,
      idempotencyKey: job.idempotencyKey,
    });
  }

  function createQueuedIssueResponse(
    c: AppContext,
    queued: IssueBadgeQueueEnvelope,
    channel?: "programmatic_api_key",
  ): Response {
    if (channel === undefined) {
      return c.json(
        {
          status: "queued",
          jobType: queued.job.jobType,
          assertionId: queued.assertionId,
          idempotencyKey: queued.job.idempotencyKey,
        },
        202,
      );
    }

    return c.json(
      {
        status: "queued",
        channel,
        jobType: queued.job.jobType,
        assertionId: queued.assertionId,
        idempotencyKey: queued.job.idempotencyKey,
      },
      202,
    );
  }

  function createQueuedRevokeResponse(
    c: AppContext,
    input: {
      assertionId: string;
      queued: RevokeBadgeQueueEnvelope;
      channel?: "programmatic_api_key";
    },
  ): Response {
    if (input.channel === undefined) {
      return c.json(
        {
          status: "queued",
          jobType: input.queued.job.jobType,
          assertionId: input.assertionId,
          revocationId: input.queued.revocationId,
          idempotencyKey: input.queued.job.idempotencyKey,
        },
        202,
      );
    }

    return c.json(
      {
        status: "queued",
        channel: input.channel,
        jobType: input.queued.job.jobType,
        assertionId: input.assertionId,
        revocationId: input.queued.revocationId,
        idempotencyKey: input.queued.job.idempotencyKey,
      },
      202,
    );
  }

  app.post("/v1/jobs/process", async (c) => {
    const authError = authorizeTrustedInternalRequest(c);

    if (authError !== null) {
      return authError;
    }

    const request = parseProcessQueueRequest(await readJsonBodyOrEmptyObject(c));
    const result = await processQueuedJobs(c, processQueueInputWithDefaults(request));

    return c.json(
      {
        status: "ok",
        ...result,
      },
      200,
    );
  });

  app.post("/v1/issue", async (c) => {
    const authError = authorizeTrustedInternalRequest(c);

    if (authError !== null) {
      return authError;
    }

    const payload = await c.req.json<unknown>();
    const parsedRequest = parseRequest(c, parseIssueBadgeRequest, payload);

    if ("response" in parsedRequest) {
      return parsedRequest.response;
    }

    const request = parsedRequest.value;
    const queued = issueBadgeQueueJobFromRequest(request);
    await enqueueQueuedJob(c, queued.job);

    return createQueuedIssueResponse(c, queued);
  });

  app.post("/v1/revoke", async (c) => {
    const authError = authorizeTrustedInternalRequest(c);

    if (authError !== null) {
      return authError;
    }

    const payload = await c.req.json<unknown>();
    const parsedRequest = parseRequest(c, parseRevokeBadgeRequest, payload);

    if ("response" in parsedRequest) {
      return parsedRequest.response;
    }

    const request = parsedRequest.value;
    const queued = revokeBadgeQueueJobFromRequest(request);
    await enqueueQueuedJob(c, queued.job);

    return createQueuedRevokeResponse(c, {
      assertionId: request.assertionId,
      queued,
    });
  });

  app.post("/v1/programmatic/issue", async (c) => {
    const payload = await c.req.json<unknown>();
    const parsedRequest = parseRequest(c, parseProgrammaticIssueBadgeRequest, payload);

    if ("response" in parsedRequest) {
      return parsedRequest.response;
    }

    const request = parsedRequest.value;
    const authResult = await authorizeProgrammaticRequest(c, {
      tenantId: request.tenantId,
      requiredScope: "queue.issue",
    });

    if ("response" in authResult) {
      return authResult.response;
    }

    const queued = issueBadgeQueueJobFromRequest({
      ...request,
      requestedByUserId: authResult.actorUserId,
    });
    await enqueueQueuedJob(c, queued.job);

    return createQueuedIssueResponse(c, queued, "programmatic_api_key");
  });

  app.post("/v1/programmatic/revoke", async (c) => {
    const payload = await c.req.json<unknown>();
    const parsedRequest = parseRequest(c, parseProgrammaticRevokeBadgeRequest, payload);

    if ("response" in parsedRequest) {
      return parsedRequest.response;
    }

    const request = parsedRequest.value;
    const authResult = await authorizeProgrammaticRequest(c, {
      tenantId: request.tenantId,
      requiredScope: "queue.revoke",
    });

    if ("response" in authResult) {
      return authResult.response;
    }

    const queued = revokeBadgeQueueJobFromRequest({
      ...request,
      requestedByUserId: authResult.actorUserId,
    });
    await enqueueQueuedJob(c, queued.job);

    return createQueuedRevokeResponse(c, {
      assertionId: request.assertionId,
      queued,
      channel: "programmatic_api_key",
    });
  });
};
