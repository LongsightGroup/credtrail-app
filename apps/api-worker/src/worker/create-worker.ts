import { captureSentryException, logError, logInfo, type ObservabilityContext } from '@credtrail/core-domain';
import type { Hono } from 'hono';
import type { AppBindings, AppEnv } from '../app';

interface CreateApiWorkerInput {
  app: Hono<AppEnv>;
  queueProcessorRequestFromSchedule: (env: AppBindings) => Request;
  observabilityContext: (bindings: AppBindings) => ObservabilityContext;
}

export const createApiWorker = (input: CreateApiWorkerInput): ExportedHandler<AppBindings> => {
  const { app, queueProcessorRequestFromSchedule, observabilityContext } = input;

  return {
    fetch(request, env, executionCtx): Promise<Response> {
      return Promise.resolve(app.fetch(request, env, executionCtx));
    },
    async scheduled(event, env, executionCtx): Promise<void> {
      const request = queueProcessorRequestFromSchedule(env);
      const response = await app.fetch(request, env, executionCtx);
      const responseBody = await response.text();

      if (!response.ok) {
        await captureSentryException({
          context: observabilityContext(env),
          dsn: env.SENTRY_DSN,
          error: new Error('Scheduled queue processing failed'),
          message: 'Scheduled queue processing failed',
          extra: {
            cron: event.cron,
            status: response.status,
            responseBody,
          },
        });

        logError(observabilityContext(env), 'scheduled_queue_processing_failed', {
          cron: event.cron,
          status: response.status,
          responseBody,
        });
        return;
      }

      logInfo(observabilityContext(env), 'scheduled_queue_processing_succeeded', {
        cron: event.cron,
        status: response.status,
        responseBody,
      });
    },
  };
};
