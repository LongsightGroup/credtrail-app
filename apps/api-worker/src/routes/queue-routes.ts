import {
  parseProcessQueueRequest,
  programmaticAcceptedSchema,
  programmaticIssueBadgeRequestSchema,
  programmaticRevokeBadgeRequestSchema,
  type ProcessQueueRequest,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app/types";
import { badgeArtworkIssuanceHttpFailure } from "../badges/badge-artwork-issuance-http";
import {
  issueQueueIngressCommand,
  revokeQueueIngressCommand,
  type IssueBadgeQueueEnvelope,
  type IssueQueueIngressResult,
  type RevokeQueueIngressResult,
  type RevokeBadgeQueueEnvelope,
} from "../queue/ingress-service";
import { authorizeProgrammaticWriteRequest } from "../auth/programmatic-api-key";
import { parseProgrammaticInput, programmaticApiError } from "../http/programmatic-api-response";
import { programmaticOperationStatusUrl } from "./programmatic-api-links";
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

interface RegisterQueueRoutesInput {
  app: Hono<AppEnv>;
  resolveQueueIngressStore: (bindings: AppBindings) => QueueIngressStore;
  sha256Hex: (value: string) => Promise<string>;
  readJsonBodyOrEmptyObject: (c: AppContext) => Promise<unknown>;
  processQueuedJobs: (c: AppContext, input: ProcessQueueConfig) => Promise<ProcessQueueRunResult>;
  processQueueInputWithDefaults: (input: ProcessQueueRequest) => ProcessQueueConfig;
}

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

const queueIngressResponse = (
  c: AppContext,
  result: IssueQueueIngressResult | RevokeQueueIngressResult,
): Response => {
  switch (result.status) {
    case "queued":
      return createQueuedResponse(c, result.envelope);
    case "idempotency_conflict":
      return programmaticApiError(
        c,
        409,
        "idempotency_conflict",
        "This idempotency key is already assigned to a different request",
      );
    case "template_not_found":
      return programmaticApiError(c, 404, "template_not_found", "Badge template not found");
    case "template_archived":
      return programmaticApiError(c, 409, "template_archived", "Badge template is archived");
    case "invalid_expiry":
      return programmaticApiError(c, 422, result.failure.code, result.failure.error);
    case "artwork_failure": {
      const failure = badgeArtworkIssuanceHttpFailure(result.failure);
      return programmaticApiError(
        c,
        failure.statusCode,
        result.failure.status === "storage_unavailable"
          ? "storage_unavailable"
          : "artwork_required",
        failure.error,
      );
    }
  }
};

const createQueuedResponse = (
  c: AppContext,
  queued: IssueBadgeQueueEnvelope | RevokeBadgeQueueEnvelope,
): Response => {
  const statusUrl = programmaticOperationStatusUrl(
    c.env.PUBLIC_APP_ORIGIN,
    queued.job.tenantId,
    queued.operationId,
  );
  c.header("Location", statusUrl);
  return c.json(
    programmaticAcceptedSchema.parse({
      status: "queued",
      channel: "programmatic_api_key",
      operationId: queued.operationId,
      statusUrl,
      jobType: queued.job.jobType,
      assertionId: queued.job.payload.assertionId,
      idempotencyKey: queued.job.idempotencyKey,
      ...("revocationId" in queued ? { revocationId: queued.revocationId } : {}),
    }),
    202,
  );
};

const readProgrammaticJson = async (c: AppContext): Promise<unknown> => {
  try {
    return await c.req.json<unknown>();
  } catch {
    return undefined;
  }
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

  app.post("/v1/programmatic/issue", async (c) => {
    const parsed = parseProgrammaticInput(
      c,
      programmaticIssueBadgeRequestSchema,
      await readProgrammaticJson(c),
    );

    if ("response" in parsed) {
      return parsed.response;
    }

    const store = input.resolveQueueIngressStore(c.env);
    const auth = await authorizeProgrammaticWriteRequest(
      c,
      store,
      { tenantId: parsed.value.tenantId, requiredScope: "queue.issue" },
      input.sha256Hex,
    );

    if ("response" in auth) return auth.response;
    const result = await issueQueueIngressCommand({
      store,
      artworkStore: c.env.BADGE_OBJECTS,
      publicAppOrigin: c.env.PUBLIC_APP_ORIGIN,
      request: parsed.value,
      nowIso: new Date().toISOString(),
      requestedByUserId: auth.actorUserId,
    });
    return queueIngressResponse(c, result);
  });

  app.post("/v1/programmatic/revoke", async (c) => {
    const parsed = parseProgrammaticInput(
      c,
      programmaticRevokeBadgeRequestSchema,
      await readProgrammaticJson(c),
    );

    if ("response" in parsed) {
      return parsed.response;
    }

    const store = input.resolveQueueIngressStore(c.env);
    const auth = await authorizeProgrammaticWriteRequest(
      c,
      store,
      { tenantId: parsed.value.tenantId, requiredScope: "queue.revoke" },
      input.sha256Hex,
    );

    if ("response" in auth) return auth.response;
    const result = await revokeQueueIngressCommand({
      store,
      request: parsed.value,
      requestedByUserId: auth.actorUserId,
    });
    return queueIngressResponse(c, result);
  });
};
