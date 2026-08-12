import {
  parseIssueBadgeRequest,
  parseProcessQueueRequest,
  parseProgrammaticIssueBadgeRequest,
  parseProgrammaticRevokeBadgeRequest,
  parseRevokeBadgeRequest,
  type IssueBadgeRequest,
  type ProcessQueueRequest,
  type RevokeBadgeRequest,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app";
import { badgeArtworkIssuanceHttpFailure } from "../badges/badge-artwork-issuance-http";
import {
  issueQueueIngressCommand,
  revokeQueueIngressCommand,
  type IssueBadgeQueueEnvelope,
  type IssueQueueIngressResult,
  type RevokeBadgeQueueEnvelope,
  type RevokeQueueIngressResult,
} from "../queue/ingress-service";
import type { QueueIngressStore } from "../queue/ingress-store";

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
  resolveQueueIngressStore: (bindings: AppBindings) => QueueIngressStore;
  sha256Hex: (value: string) => Promise<string>;
  readJsonBodyOrEmptyObject: (c: AppContext) => Promise<unknown>;
  processQueuedJobs: (c: AppContext, input: ProcessQueueConfig) => Promise<ProcessQueueRunResult>;
  processQueueInputWithDefaults: (input: ProcessQueueRequest) => ProcessQueueConfig;
}

const parseApiKeyScopes = (scopesJson: string): string[] => {
  try {
    const parsed = JSON.parse(scopesJson) as unknown;

    if (!Array.isArray(parsed)) {
      return [];
    }

    return parsed.filter((value): value is string => typeof value === "string" && value.length > 0);
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

  if (!(error instanceof Error) || !("issues" in error) || !Array.isArray(error.issues)) {
    return false;
  }

  return error.issues.every((issue) => isValidationIssue(issue));
};

const parseRequest = <Value>(
  c: AppContext,
  parser: (input: unknown) => Value,
  payload: unknown,
): { value: Value } | { response: Response } => {
  try {
    return { value: parser(payload) };
  } catch (error: unknown) {
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
    return c.json({ error: "Route unavailable" }, 404);
  }

  if (c.req.header("authorization") !== `Bearer ${configuredToken}`) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  return null;
};

const authorizeProgrammaticRequest = async (
  c: AppContext,
  store: QueueIngressStore,
  input: {
    readonly tenantId: string;
    readonly requiredScope: "queue.issue" | "queue.revoke";
  },
  sha256Hex: (value: string) => Promise<string>,
): Promise<{ actorUserId: string } | { response: Response }> => {
  const rawApiKey = c.req.header("x-api-key")?.trim();

  if (rawApiKey === undefined || rawApiKey.length === 0) {
    return { response: c.json({ error: "x-api-key header is required" }, 401) };
  }

  const nowIso = new Date().toISOString();
  const keyRecord = await store.findActiveApiKeyByHash({
    keyHash: await sha256Hex(rawApiKey),
    nowIso,
  });

  if (keyRecord === null) {
    return { response: c.json({ error: "Invalid or expired API key" }, 401) };
  }

  if (keyRecord.tenantId !== input.tenantId) {
    return { response: c.json({ error: "API key tenant does not match request tenant" }, 403) };
  }

  const scopes = parseApiKeyScopes(keyRecord.scopesJson);

  if (!scopes.includes("*") && !scopes.includes(input.requiredScope)) {
    return {
      response: c.json({ error: `API key is missing required scope: ${input.requiredScope}` }, 403),
    };
  }

  const actorUserId = keyRecord.createdByUserId?.trim();

  if (actorUserId === undefined || actorUserId.length === 0) {
    return {
      response: c.json(
        { error: "API key is missing an owning user and cannot perform write operations" },
        403,
      ),
    };
  }

  await store.touchApiKeyLastUsedAt(keyRecord.id, nowIso);
  return { actorUserId };
};

const issueQueueResponse = (
  c: AppContext,
  result: IssueQueueIngressResult,
  channel?: "programmatic_api_key",
): Response => {
  switch (result.status) {
    case "queued":
      return createQueuedIssueResponse(c, result.envelope, channel);
    case "idempotency_conflict":
      return c.json(
        { error: "This idempotency key is already assigned to a different request" },
        409,
      );
    case "template_not_found":
      return c.json({ error: "Badge template not found" }, 404);
    case "template_archived":
      return c.json({ error: "Badge template is archived" }, 409);
    case "artwork_failure": {
      const failure = badgeArtworkIssuanceHttpFailure(result.failure);
      return c.json({ error: failure.error }, failure.statusCode);
    }
  }
};

const revokeQueueResponse = (
  c: AppContext,
  request: RevokeBadgeRequest,
  result: RevokeQueueIngressResult,
  channel?: "programmatic_api_key",
): Response => {
  if (result.status === "idempotency_conflict") {
    return c.json(
      { error: "This idempotency key is already assigned to a different request" },
      409,
    );
  }

  return createQueuedRevokeResponse(c, request.assertionId, result.envelope, channel);
};

const createQueuedIssueResponse = (
  c: AppContext,
  queued: IssueBadgeQueueEnvelope,
  channel?: "programmatic_api_key",
): Response => {
  return c.json(
    {
      status: "queued",
      ...(channel === undefined ? {} : { channel }),
      jobType: queued.job.jobType,
      assertionId: queued.assertionId,
      idempotencyKey: queued.job.idempotencyKey,
    },
    202,
  );
};

const createQueuedRevokeResponse = (
  c: AppContext,
  assertionId: string,
  queued: RevokeBadgeQueueEnvelope,
  channel?: "programmatic_api_key",
): Response => {
  return c.json(
    {
      status: "queued",
      ...(channel === undefined ? {} : { channel }),
      jobType: queued.job.jobType,
      assertionId,
      revocationId: queued.revocationId,
      idempotencyKey: queued.job.idempotencyKey,
    },
    202,
  );
};

const handleIssueCommand = async (
  c: AppContext,
  store: QueueIngressStore,
  request: IssueBadgeRequest,
  requestedByUserId?: string,
  channel?: "programmatic_api_key",
): Promise<Response> => {
  const result = await issueQueueIngressCommand({
    store,
    artworkStore: c.env.BADGE_OBJECTS,
    publicAppOrigin: c.env.PUBLIC_APP_ORIGIN,
    request,
    ...(requestedByUserId === undefined ? {} : { requestedByUserId }),
  });
  return issueQueueResponse(c, result, channel);
};

const handleRevokeCommand = async (
  c: AppContext,
  store: QueueIngressStore,
  request: RevokeBadgeRequest,
  requestedByUserId?: string,
  channel?: "programmatic_api_key",
): Promise<Response> => {
  const result = await revokeQueueIngressCommand({
    store,
    request,
    ...(requestedByUserId === undefined ? {} : { requestedByUserId }),
  });
  return revokeQueueResponse(c, request, result, channel);
};

/** Registers authenticated queue-processing and queue-ingress HTTP routes. */
export const registerQueueRoutes = (input: RegisterQueueRoutesInput): void => {
  const { app } = input;

  app.post("/v1/jobs/process", async (c) => {
    const authError = authorizeTrustedInternalRequest(c);

    if (authError !== null) {
      return authError;
    }

    const request = parseProcessQueueRequest(await input.readJsonBodyOrEmptyObject(c));
    const result = await input.processQueuedJobs(c, input.processQueueInputWithDefaults(request));
    return c.json({ status: "ok", ...result }, 200);
  });

  app.post("/v1/issue", async (c) => {
    const authError = authorizeTrustedInternalRequest(c);

    if (authError !== null) {
      return authError;
    }

    const parsed = parseRequest(c, parseIssueBadgeRequest, await c.req.json<unknown>());
    return "response" in parsed
      ? parsed.response
      : handleIssueCommand(c, input.resolveQueueIngressStore(c.env), parsed.value);
  });

  app.post("/v1/revoke", async (c) => {
    const authError = authorizeTrustedInternalRequest(c);

    if (authError !== null) {
      return authError;
    }

    const parsed = parseRequest(c, parseRevokeBadgeRequest, await c.req.json<unknown>());
    return "response" in parsed
      ? parsed.response
      : handleRevokeCommand(c, input.resolveQueueIngressStore(c.env), parsed.value);
  });

  app.post("/v1/programmatic/issue", async (c) => {
    const parsed = parseRequest(c, parseProgrammaticIssueBadgeRequest, await c.req.json<unknown>());

    if ("response" in parsed) {
      return parsed.response;
    }

    const store = input.resolveQueueIngressStore(c.env);
    const auth = await authorizeProgrammaticRequest(
      c,
      store,
      { tenantId: parsed.value.tenantId, requiredScope: "queue.issue" },
      input.sha256Hex,
    );

    return "response" in auth
      ? auth.response
      : handleIssueCommand(c, store, parsed.value, auth.actorUserId, "programmatic_api_key");
  });

  app.post("/v1/programmatic/revoke", async (c) => {
    const parsed = parseRequest(c, parseProgrammaticRevokeBadgeRequest, await c.req.json<unknown>());

    if ("response" in parsed) {
      return parsed.response;
    }

    const store = input.resolveQueueIngressStore(c.env);
    const auth = await authorizeProgrammaticRequest(
      c,
      store,
      { tenantId: parsed.value.tenantId, requiredScope: "queue.revoke" },
      input.sha256Hex,
    );

    return "response" in auth
      ? auth.response
      : handleRevokeCommand(c, store, parsed.value, auth.actorUserId, "programmatic_api_key");
  });
};
