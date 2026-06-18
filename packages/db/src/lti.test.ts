import { describe, expect, it } from "vitest";
import { LtiIssuerTenantConflictError, upsertLtiIssuerRegistration } from "./lti";
import type { SqlDatabase, SqlQueryResult, SqlRunResult } from "./tenant-scope";

interface LtiIssuerRegistrationRow {
  issuer: string;
  tenantId: string;
  authorizationEndpoint: string;
  clientId: string;
  platformJwksEndpoint: string | null;
  tokenEndpoint: string | null;
  clientSecret: string | null;
  createdAt: string;
  updatedAt: string;
}

const successfulRun = (rowsWritten: number): SqlRunResult => {
  return {
    success: true,
    meta: {
      rowsWritten,
    },
  };
};

const createLtiIssuerRegistrationDb = (): {
  db: SqlDatabase;
  preparedSql: readonly string[];
  getRow: () => LtiIssuerRegistrationRow | null;
} => {
  const preparedSql: string[] = [];
  let row: LtiIssuerRegistrationRow | null = null;

  const db: SqlDatabase = {
    prepare(sql: string) {
      preparedSql.push(sql);
      let params: readonly unknown[] = [];

      return {
        bind(...boundParams: unknown[]) {
          params = boundParams;
          return this;
        },
        async first<T>(): Promise<T | null> {
          if (!sql.includes("FROM lti_issuer_registrations") || row === null) {
            return null;
          }

          return row.issuer === params[0] ? (row as T) : null;
        },
        async all<T>(): Promise<SqlQueryResult<T>> {
          return {
            ...successfulRun(0),
            results: [],
          };
        },
        async run(): Promise<SqlRunResult> {
          if (!sql.includes("INSERT INTO lti_issuer_registrations")) {
            return successfulRun(0);
          }

          const [
            issuer,
            tenantId,
            authorizationEndpoint,
            clientId,
            platformJwksEndpoint,
            tokenEndpoint,
            clientSecret,
            createdAt,
            updatedAt,
          ] = params;

          if (
            typeof issuer !== "string" ||
            typeof tenantId !== "string" ||
            typeof authorizationEndpoint !== "string" ||
            typeof clientId !== "string" ||
            typeof createdAt !== "string" ||
            typeof updatedAt !== "string"
          ) {
            throw new Error("Unexpected LTI issuer registration bind params");
          }

          if (row !== null && row.tenantId !== tenantId) {
            return successfulRun(0);
          }

          row = {
            issuer,
            tenantId,
            authorizationEndpoint,
            clientId,
            platformJwksEndpoint:
              typeof platformJwksEndpoint === "string"
                ? platformJwksEndpoint
                : (row?.platformJwksEndpoint ?? null),
            tokenEndpoint:
              typeof tokenEndpoint === "string" ? tokenEndpoint : (row?.tokenEndpoint ?? null),
            clientSecret:
              typeof clientSecret === "string" ? clientSecret : (row?.clientSecret ?? null),
            createdAt: row?.createdAt ?? createdAt,
            updatedAt,
          };

          return successfulRun(1);
        },
      };
    },
  };

  return {
    db,
    preparedSql,
    getRow: () => row,
  };
};

describe("upsertLtiIssuerRegistration", () => {
  it("inserts and updates same-tenant issuer registrations", async () => {
    const fake = createLtiIssuerRegistrationDb();

    const inserted = await upsertLtiIssuerRegistration(fake.db, {
      issuer: "https://canvas.test/",
      tenantId: "tenant-a",
      authorizationEndpoint: "https://canvas.test/api/lti/authorize_redirect",
      clientId: "client-1",
      platformJwksEndpoint: "https://canvas.test/api/lti/security/jwks",
      tokenEndpoint: "https://canvas.test/login/oauth2/token",
    });
    const updated = await upsertLtiIssuerRegistration(fake.db, {
      issuer: "https://canvas.test",
      tenantId: "tenant-a",
      authorizationEndpoint: "https://canvas.test/new-authorize",
      clientId: "client-2",
    });

    expect(inserted.issuer).toBe("https://canvas.test");
    expect(updated).toMatchObject({
      issuer: "https://canvas.test",
      tenantId: "tenant-a",
      authorizationEndpoint: "https://canvas.test/new-authorize",
      clientId: "client-2",
      platformJwksEndpoint: "https://canvas.test/api/lti/security/jwks",
      tokenEndpoint: "https://canvas.test/login/oauth2/token",
    });
    expect(fake.preparedSql.join("\n")).toContain(
      "WHERE lti_issuer_registrations.tenant_id = excluded.tenant_id",
    );
  });

  it("rejects cross-tenant issuer upserts without changing the stored owner", async () => {
    const fake = createLtiIssuerRegistrationDb();

    await upsertLtiIssuerRegistration(fake.db, {
      issuer: "https://canvas.test",
      tenantId: "tenant-a",
      authorizationEndpoint: "https://canvas.test/api/lti/authorize_redirect",
      clientId: "client-1",
      platformJwksEndpoint: "https://canvas.test/api/lti/security/jwks",
      tokenEndpoint: "https://canvas.test/login/oauth2/token",
    });

    await expect(
      upsertLtiIssuerRegistration(fake.db, {
        issuer: "https://canvas.test/",
        tenantId: "tenant-b",
        authorizationEndpoint: "https://canvas.test/new-authorize",
        clientId: "client-2",
      }),
    ).rejects.toBeInstanceOf(LtiIssuerTenantConflictError);
    expect(fake.getRow()).toMatchObject({
      issuer: "https://canvas.test",
      tenantId: "tenant-a",
      authorizationEndpoint: "https://canvas.test/api/lti/authorize_redirect",
      clientId: "client-1",
    });
  });
});
