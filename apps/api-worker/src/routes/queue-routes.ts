import { enqueueJobQueueMessage, type SqlDatabase } from '@credtrail/db';
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
    readJsonBodyOrEmptyObject,
    processQueuedJobs,
    processQueueInputWithDefaults,
    issueBadgeQueueJobFromRequest,
    revokeBadgeQueueJobFromRequest,
  } = input;

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
};
