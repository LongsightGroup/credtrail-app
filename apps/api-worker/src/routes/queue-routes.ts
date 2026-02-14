import {
  enqueueJobQueueMessage,
  findActiveTenantApiKeyByHash,
  touchTenantApiKeyLastUsedAt,
  type SqlDatabase,
} from '@credtrail/db';
import type { Hono } from 'hono';
import {
  parseIssueBadgeRequest,
  parseProcessQueueRequest,
  parseRevokeBadgeRequest,
  type IssueBadgeQueueJob,
  type ProcessQueueRequest,
  type RevokeBadgeQueueJob,
} from '@credtrail/validation';
import type { AppBindings, AppContext, AppEnv } from '../app';

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

interface RegisterQueueRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  sha256Hex: (value: string) => Promise<string>;
  readJsonBodyOrEmptyObject: (c: AppContext) => Promise<unknown>;
  processQueuedJobs: (c: AppContext, input: ProcessQueueConfig) => Promise<ProcessQueueRunResult>;
  processQueueInputWithDefaults: (input: ProcessQueueRequest) => ProcessQueueConfig;
  issueBadgeQueueJobFromRequest: (request: ReturnType<typeof parseIssueBadgeRequest>) => IssueBadgeQueueEnvelope;
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

      return parsed.filter((value): value is string => typeof value === 'string' && value.length > 0);
    } catch {
      return [];
    }
  };

  const authorizeProgrammaticRequest = async (
    c: AppContext,
    input: {
      tenantId: string;
      requiredScope: 'queue.issue' | 'queue.revoke';
    },
  ): Promise<Response | null> => {
    const rawApiKey = c.req.header('x-api-key')?.trim();

    if (rawApiKey === undefined || rawApiKey.length === 0) {
      return c.json(
        {
          error: 'x-api-key header is required',
        },
        401,
      );
    }

    const nowIso = new Date().toISOString();
    const keyHash = await sha256Hex(rawApiKey);
    const keyRecord = await findActiveTenantApiKeyByHash(resolveDatabase(c.env), {
      keyHash,
      nowIso,
    });

    if (keyRecord === null) {
      return c.json(
        {
          error: 'Invalid or expired API key',
        },
        401,
      );
    }

    if (keyRecord.tenantId !== input.tenantId) {
      return c.json(
        {
          error: 'API key tenant does not match request tenant',
        },
        403,
      );
    }

    const scopes = parseApiKeyScopes(keyRecord.scopesJson);
    const hasRequiredScope = scopes.includes('*') || scopes.includes(input.requiredScope);

    if (!hasRequiredScope) {
      return c.json(
        {
          error: `API key is missing required scope: ${input.requiredScope}`,
        },
        403,
      );
    }

    await touchTenantApiKeyLastUsedAt(resolveDatabase(c.env), keyRecord.id, nowIso);
    return null;
  };

  app.post('/v1/jobs/process', async (c) => {
    const configuredToken = c.env.JOB_PROCESSOR_TOKEN?.trim();

    if (configuredToken !== undefined && configuredToken.length > 0) {
      const authorizationHeader = c.req.header('authorization');
      const expectedAuthorization = `Bearer ${configuredToken}`;

      if (authorizationHeader !== expectedAuthorization) {
        return c.json(
          {
            error: 'Unauthorized',
          },
          401,
        );
      }
    }

    const request = parseProcessQueueRequest(await readJsonBodyOrEmptyObject(c));
    const result = await processQueuedJobs(c, processQueueInputWithDefaults(request));

    return c.json(
      {
        status: 'ok',
        ...result,
      },
      200,
    );
  });

  app.post('/v1/issue', async (c) => {
    const payload = await c.req.json<unknown>();
    const request = parseIssueBadgeRequest(payload);
    const queued = issueBadgeQueueJobFromRequest(request);

    await enqueueJobQueueMessage(resolveDatabase(c.env), {
      tenantId: queued.job.tenantId,
      jobType: queued.job.jobType,
      payload: queued.job.payload,
      idempotencyKey: queued.job.idempotencyKey,
    });

    return c.json(
      {
        status: 'queued',
        jobType: queued.job.jobType,
        assertionId: queued.assertionId,
        idempotencyKey: queued.job.idempotencyKey,
      },
      202,
    );
  });

  app.post('/v1/revoke', async (c) => {
    const payload = await c.req.json<unknown>();
    const request = parseRevokeBadgeRequest(payload);
    const queued = revokeBadgeQueueJobFromRequest(request);

    await enqueueJobQueueMessage(resolveDatabase(c.env), {
      tenantId: queued.job.tenantId,
      jobType: queued.job.jobType,
      payload: queued.job.payload,
      idempotencyKey: queued.job.idempotencyKey,
    });

    return c.json(
      {
        status: 'queued',
        jobType: queued.job.jobType,
        assertionId: request.assertionId,
        revocationId: queued.revocationId,
        idempotencyKey: queued.job.idempotencyKey,
      },
      202,
    );
  });

  app.post('/v1/programmatic/issue', async (c) => {
    const payload = await c.req.json<unknown>();
    const request = parseIssueBadgeRequest(payload);
    const authError = await authorizeProgrammaticRequest(c, {
      tenantId: request.tenantId,
      requiredScope: 'queue.issue',
    });

    if (authError !== null) {
      return authError;
    }

    const queued = issueBadgeQueueJobFromRequest(request);

    await enqueueJobQueueMessage(resolveDatabase(c.env), {
      tenantId: queued.job.tenantId,
      jobType: queued.job.jobType,
      payload: queued.job.payload,
      idempotencyKey: queued.job.idempotencyKey,
    });

    return c.json(
      {
        status: 'queued',
        channel: 'programmatic_api_key',
        jobType: queued.job.jobType,
        assertionId: queued.assertionId,
        idempotencyKey: queued.job.idempotencyKey,
      },
      202,
    );
  });

  app.post('/v1/programmatic/revoke', async (c) => {
    const payload = await c.req.json<unknown>();
    const request = parseRevokeBadgeRequest(payload);
    const authError = await authorizeProgrammaticRequest(c, {
      tenantId: request.tenantId,
      requiredScope: 'queue.revoke',
    });

    if (authError !== null) {
      return authError;
    }

    const queued = revokeBadgeQueueJobFromRequest(request);

    await enqueueJobQueueMessage(resolveDatabase(c.env), {
      tenantId: queued.job.tenantId,
      jobType: queued.job.jobType,
      payload: queued.job.payload,
      idempotencyKey: queued.job.idempotencyKey,
    });

    return c.json(
      {
        status: 'queued',
        channel: 'programmatic_api_key',
        jobType: queued.job.jobType,
        assertionId: request.assertionId,
        revocationId: queued.revocationId,
        idempotencyKey: queued.job.idempotencyKey,
      },
      202,
    );
  });
};
