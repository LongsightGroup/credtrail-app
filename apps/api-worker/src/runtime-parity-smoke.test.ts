import { describe, expect, it } from "vitest";
import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import worker, { app } from "./index";
import type { AppBindings } from "./app/types";
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
    PUBLIC_APP_ORIGIN: "https://credtrail.test",
    BADGE_OBJECTS: createNoopStore(),
  };
};

const createRuntimeEnv = (): WorkerRuntimeBindings => {
  return {
    APP_ENV: "test",
    PLATFORM_DOMAIN: "credtrail.test",
    PUBLIC_APP_ORIGIN: "https://credtrail.test",
    BADGE_OBJECTS: {} as R2Bucket,
  };
};

class NoopSpan {
  get isTraced(): boolean {
    return false;
  }

  setAttribute(_key: string, _value: boolean | number | string): this {
    return this;
  }

  setAttributes(_attributes: Record<string, boolean | number | string | undefined>): this {
    return this;
  }

  end(): void {
    return undefined;
  }
}

const tracing: Tracing = {
  enterSpan: (_name, callback, ...args) => callback(new NoopSpan(), ...args),
  startActiveSpan: (_name, callback, ...args) => callback(new NoopSpan(), ...args),
  startSpan: (_name) => new NoopSpan(),
  Span: NoopSpan,
};

const executionContext: ExecutionContext = {
  waitUntil: (_promise: Promise<unknown>) => undefined,
  passThroughOnException: () => undefined,
  exports: {},
  props: undefined,
  tracing,
  abort: (reason?: unknown) => {
    if (reason instanceof Error) {
      throw reason;
    }
    throw new Error("Execution aborted", { cause: reason });
  },
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
