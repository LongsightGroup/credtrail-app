import { describe, expect, it } from "vitest";
import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import worker, { app } from "./index";
import type { AppBindings } from "./app";
import type { WorkerRuntimeBindings } from "./worker/create-worker";

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
        uploaded: new Date("2026-02-16T00:00:00.000Z"),
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

const createRuntimeEnv = (): WorkerRuntimeBindings => {
  return {
    APP_ENV: "test",
    PLATFORM_DOMAIN: "credtrail.test",
    BADGE_OBJECTS: {} as R2Bucket,
  };
};

const executionContext: ExecutionContext = {
  waitUntil: (_promise: Promise<unknown>) => undefined,
  passThroughOnException: () => undefined,
  props: undefined,
};

describe("runtime parity smoke", () => {
  it("returns equivalent discovery responses via app.fetch and worker.fetch", async () => {
    const request = new Request("https://credtrail.test/ims/ob/v3p0/discovery");
    const env = createEnv();
    const runtimeEnv = createRuntimeEnv();

    const directResponse = await app.fetch(request, env, executionContext);
    if (worker.fetch === undefined) {
      throw new Error("Expected worker.fetch to be defined");
    }

    const workerResponse = await worker.fetch(
      request as unknown as Request<unknown, IncomingRequestCfProperties>,
      runtimeEnv,
      executionContext,
    );

    expect(directResponse.status).toBe(200);
    expect(workerResponse.status).toBe(200);
    expect(await workerResponse.text()).toBe(await directResponse.text());
  });
});
