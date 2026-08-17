import { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SqlDatabase, SqlQueryResult, SqlRunResult } from "@credtrail/db";
import type { AppBindings, AppEnv } from "./app/types";
import { createAppLogger } from "./app/observability";
import { LTI_JWKS_PATH } from "./lti/constants";
import { registerLtiRoutes } from "./routes/lti-routes";

interface StoredLtiToolKeyRow {
  readonly id: string;
  readonly keyId: string;
  readonly publicJwkJson: string;
  readonly privateJwkJson: string;
  readonly isActive: number | boolean;
  readonly createdAt: string;
  readonly updatedAt: string;
}

interface FakeLtiToolKeyDb {
  readonly db: SqlDatabase;
  readonly getRow: () => StoredLtiToolKeyRow | null;
  readonly insertCount: () => number;
  readonly selectCount: () => number;
}

const fakeEnv: AppBindings = {
  APP_ENV: "test",
  BADGE_OBJECTS: {
    head: vi.fn(async () => null),
    get: vi.fn(async () => null),
    put: vi.fn(async () => null),
    delete: vi.fn(async () => undefined),
  },
  PLATFORM_DOMAIN: "credtrail.test",
  PUBLIC_APP_ORIGIN: "https://credtrail.test",
};

const successfulRun = (rowsWritten: number): SqlRunResult => {
  return {
    success: true,
    meta: {
      rowsWritten,
    },
  };
};

const storedLtiToolKeyRow = (
  input: {
    readonly keyId?: string | undefined;
    readonly publicJwk?: Readonly<Record<string, unknown>> | undefined;
    readonly privateJwk?: Readonly<Record<string, unknown>> | undefined;
  } = {},
): StoredLtiToolKeyRow => {
  const nowIso = "2026-01-01T00:00:00.000Z";

  return {
    id: "lti_key_test",
    keyId: input.keyId ?? "credtrail-lti-main",
    publicJwkJson: JSON.stringify(
      input.publicJwk ?? {
        kty: "RSA",
        kid: "stored-public-key",
        n: "test-modulus",
        e: "AQAB",
      },
    ),
    privateJwkJson: JSON.stringify(
      input.privateJwk ?? {
        kty: "RSA",
        kid: "stored-private-key",
        d: "unused-private-material",
      },
    ),
    isActive: 1,
    createdAt: nowIso,
    updatedAt: nowIso,
  };
};

const createLtiToolKeyDb = (
  input: {
    readonly row?: StoredLtiToolKeyRow | null | undefined;
    readonly failReads?: boolean | undefined;
    readonly failWrites?: boolean | undefined;
  } = {},
): FakeLtiToolKeyDb => {
  let row = input.row ?? null;
  let insertCount = 0;
  let selectCount = 0;

  const db: SqlDatabase = {
    prepare(sql: string) {
      let params: readonly unknown[] = [];

      const statement = {
        bind(...boundParams: unknown[]) {
          params = boundParams;
          return statement;
        },
        async first<T>(): Promise<T | null> {
          if (!sql.includes("FROM lti_tool_keys")) {
            return null;
          }

          selectCount += 1;

          if (input.failReads === true) {
            throw new Error("key storage unavailable");
          }

          // SAFETY: this fake implements the lti_tool_keys SELECT projection used by
          // findActiveLtiToolKey; callers choose T through that production query.
          return row as T | null;
        },
        async all<T>(): Promise<SqlQueryResult<T>> {
          return {
            ...successfulRun(0),
            results: [],
          };
        },
        async run(): Promise<SqlRunResult> {
          if (!sql.includes("INSERT INTO lti_tool_keys")) {
            return successfulRun(0);
          }

          insertCount += 1;

          if (input.failWrites === true) {
            throw new Error("key storage unavailable");
          }

          const [id, keyId, publicJwkJson, privateJwkJson, isActive, createdAt, updatedAt] = params;

          if (
            typeof id !== "string" ||
            typeof keyId !== "string" ||
            typeof publicJwkJson !== "string" ||
            typeof privateJwkJson !== "string" ||
            (typeof isActive !== "number" && typeof isActive !== "boolean") ||
            typeof createdAt !== "string" ||
            typeof updatedAt !== "string"
          ) {
            throw new Error("Unexpected LTI tool key bind params");
          }

          row = {
            id,
            keyId,
            publicJwkJson,
            privateJwkJson,
            isActive,
            createdAt,
            updatedAt,
          };

          return successfulRun(1);
        },
      };

      return statement;
    },
  };

  return {
    db,
    getRow: () => row,
    insertCount: () => insertCount,
    selectCount: () => selectCount,
  };
};

const createRouteApp = (
  input: {
    readonly db?: SqlDatabase | undefined;
    readonly withLogger?: boolean | undefined;
  } = {},
): Hono<AppEnv> => {
  const app = new Hono<AppEnv>();
  const db = input.db ?? createLtiToolKeyDb({ row: storedLtiToolKeyRow() }).db;

  if (input.withLogger !== false) {
    app.use("*", async (c, next) => {
      c.set("requestId", "test-request");
      c.set(
        "appLogger",
        createAppLogger({
          context: {
            service: "api-worker",
            environment: "test",
          },
          fields: {
            requestId: "test-request",
            method: c.req.method,
            path: new URL(c.req.url).pathname,
          },
        }),
      );
      await next();
    });
  }

  registerLtiRoutes({
    app,
    resolveLtiIssuerRegistry: async () => ({}),
    resolveDatabase: () => db,
    sha256Hex: async () => "hash",
    createLtiSession: async () => {
      throw new Error("createLtiSession is not used by JWKS tests");
    },
    issueBadgeForTenant: async () => {
      throw new Error("issueBadgeForTenant is not used by JWKS tests");
    },
  });

  return app;
};

describe("LTI JWKS route", () => {
  let consoleError: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
  });

  afterEach(() => {
    consoleError.mockRestore();
  });

  it("serves the stored CredTrail LTI tool public JWKS", async () => {
    const publicJwk = {
      kty: "RSA",
      kid: "stored-key-id",
      n: "test-modulus",
      e: "AQAB",
      ext: true,
    };
    const fakeDb = createLtiToolKeyDb({
      row: storedLtiToolKeyRow({
        publicJwk,
        privateJwk: {
          invalid: "private material is not read for JWKS",
        },
      }),
    });

    const response = await createRouteApp({ db: fakeDb.db }).request(
      LTI_JWKS_PATH,
      undefined,
      fakeEnv,
    );
    const body = await response.json<{ keys: ReadonlyArray<Record<string, unknown>> }>();

    expect(response.status).toBe(200);
    expect(body).toEqual({
      keys: [
        {
          ...publicJwk,
          use: "sig",
          alg: "RS256",
          kid: "credtrail-lti-main",
        },
      ],
    });
    expect(fakeDb.selectCount()).toBe(1);
    expect(fakeDb.insertCount()).toBe(0);
  });

  it("creates LTI tool key material when no active key exists", async () => {
    const fakeDb = createLtiToolKeyDb();

    const response = await createRouteApp({ db: fakeDb.db }).request(
      LTI_JWKS_PATH,
      undefined,
      fakeEnv,
    );
    const body = await response.json<{ keys: ReadonlyArray<Record<string, unknown>> }>();
    const key = body.keys[0];

    expect(response.status).toBe(200);
    expect(key).toMatchObject({
      kty: "RSA",
      use: "sig",
      alg: "RS256",
      kid: "credtrail-lti-main",
    });
    expect(key).not.toHaveProperty("d");
    expect(fakeDb.getRow()).not.toBeNull();
    expect(fakeDb.insertCount()).toBe(1);
  });

  it("caches resolved JWKS for the registered route", async () => {
    const fakeDb = createLtiToolKeyDb({
      row: storedLtiToolKeyRow(),
    });
    const app = createRouteApp({ db: fakeDb.db });

    const firstResponse = await app.request(LTI_JWKS_PATH, undefined, fakeEnv);
    const secondResponse = await app.request(LTI_JWKS_PATH, undefined, fakeEnv);
    const firstBody = await firstResponse.json<unknown>();
    const secondBody = await secondResponse.json<unknown>();

    expect(firstResponse.status).toBe(200);
    expect(secondResponse.status).toBe(200);
    expect(secondBody).toEqual(firstBody);
    expect(fakeDb.selectCount()).toBe(1);
  });

  it("returns a generic 500 response when JWKS resolution fails", async () => {
    const fakeDb = createLtiToolKeyDb({ failReads: true });

    const response = await createRouteApp({ db: fakeDb.db }).request(
      LTI_JWKS_PATH,
      undefined,
      fakeEnv,
    );
    const body = await response.json<{ error: string }>();

    expect(response.status).toBe(500);
    expect(body).toEqual({
      error: "Internal server error",
    });
    const errorRecord = JSON.parse(String(consoleError.mock.calls[0]?.[0])) as Record<
      string,
      unknown
    >;
    expect(errorRecord).toMatchObject({
      level: "error",
      message: "lti_jwks_failed",
      requestId: "test-request",
      component: "lti",
      detail: "key storage unavailable",
    });
  });

  it("returns a generic 500 response when request logging is not registered", async () => {
    const fakeDb = createLtiToolKeyDb({ failReads: true });

    const response = await createRouteApp({ db: fakeDb.db, withLogger: false }).request(
      LTI_JWKS_PATH,
      undefined,
      fakeEnv,
    );
    const body = await response.json<{ error: string }>();

    expect(response.status).toBe(500);
    expect(body).toEqual({
      error: "Internal server error",
    });
    expect(consoleError).not.toHaveBeenCalled();
  });
});
