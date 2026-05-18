import {
  captureSentryException,
  logError,
  logInfo,
  type ObservabilityContext,
} from "@credtrail/core-domain";
import type { Hono } from "hono";
import type { AppBindings, AppEnv } from "../app";
import type { ProcessQueueRunResult } from "../queue/processing";
import { createR2ImmutableCredentialStore } from "../storage/r2-immutable-credential-store";

export interface WorkerRuntimeBindings extends Omit<AppBindings, "BADGE_OBJECTS"> {
  BADGE_OBJECTS: R2Bucket;
}

interface CreateApiWorkerInput {
  app: Hono<AppEnv>;
  processScheduledQueue: (env: AppBindings) => Promise<ProcessQueueRunResult>;
  observabilityContext: (bindings: AppBindings) => ObservabilityContext;
}

export const createApiWorker = (
  input: CreateApiWorkerInput,
): ExportedHandler<WorkerRuntimeBindings> => {
  const { app, processScheduledQueue, observabilityContext } = input;
  const appBindingsFromRuntime = (env: WorkerRuntimeBindings): AppBindings => {
    return {
      ...env,
      BADGE_OBJECTS: createR2ImmutableCredentialStore(env.BADGE_OBJECTS),
    };
  };

  return {
    fetch(request, env, executionCtx): Promise<Response> {
      const appBindings = appBindingsFromRuntime(env);
      return Promise.resolve(app.fetch(request, appBindings, executionCtx));
    },
    async scheduled(event, env): Promise<void> {
      const appBindings = appBindingsFromRuntime(env);

      try {
        const result = await processScheduledQueue(appBindings);

        logInfo(observabilityContext(appBindings), "scheduled_queue_processing_succeeded", {
          cron: event.cron,
          ...result,
        });
      } catch (error: unknown) {
        const detail = error instanceof Error ? error.message : "Unknown queue processing failure";

        await captureSentryException({
          context: observabilityContext(appBindings),
          dsn: appBindings.SENTRY_DSN,
          error,
          message: "Scheduled queue processing failed",
          extra: {
            cron: event.cron,
            detail,
          },
        });

        logError(observabilityContext(appBindings), "scheduled_queue_processing_failed", {
          cron: event.cron,
          detail,
        });
        return;
      }
    },
  };
};
