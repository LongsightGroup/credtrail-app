import { describe, expect, it } from "vitest";
import type { SqlDatabase } from "@credtrail/db";
import {
  buildHostedMagicLinkToken,
  createBetterAuthDatabaseAdapter,
  parseHostedMagicLinkToken,
} from "./better-auth-runtime";

interface FakeAdapter {
  create: (input: {
    model: string;
    data: Record<string, unknown>;
    select?: string[];
  }) => Promise<Record<string, unknown>>;
  findOne: (input: {
    model: string;
    where?: {
      field: string;
      operator:
        | "eq"
        | "ne"
        | "lt"
        | "lte"
        | "gt"
        | "gte"
        | "in"
        | "not_in"
        | "contains"
        | "starts_with"
        | "ends_with";
      value: unknown;
      connector: "AND" | "OR";
    }[];
    select?: string[];
  }) => Promise<Record<string, unknown> | null>;
}

const createFakeDb = (
  rows: Record<string, unknown>[] = [],
): {
  adapter: FakeAdapter;
  statements: {
    sql: string;
    params: unknown[];
  }[];
} => {
  const statements: {
    sql: string;
    params: unknown[];
  }[] = [];

  const db = {
    prepare(sql: string) {
      const statement = {
        sql,
        params: [] as unknown[],
      };
      statements.push(statement);

      return {
        bind(...params: unknown[]) {
          statement.params = params;

          return {
            all() {
              return Promise.resolve({
                results: rows,
              });
            },
            first() {
              return Promise.resolve(rows[0] ?? null);
            },
            run() {
              return Promise.resolve({
                success: true,
              });
            },
          };
        },
      };
    },
  } as unknown as SqlDatabase;

  const adapter = (
    createBetterAuthDatabaseAdapter(db) as unknown as (input: unknown) => FakeAdapter
  )({});

  return {
    adapter,
    statements,
  };
};

describe("better auth runtime adapter", () => {
  it("creates both tenant-scoped and post-authentication-selection magic-link tokens", () => {
    const scopedToken = buildHostedMagicLinkToken("tenant_123");
    const unscopedToken = buildHostedMagicLinkToken();

    expect(parseHostedMagicLinkToken(scopedToken)).toEqual({ tenantId: "tenant_123" });
    expect(parseHostedMagicLinkToken(unscopedToken)).toBeNull();
  });

  it("writes verification rows using the snake_case auth schema", async () => {
    const { adapter, statements } = createFakeDb();

    await adapter.create({
      model: "verification",
      data: {
        id: "ver_123",
        identifier: "student@example.edu",
        value: "token_123",
        expiresAt: "2026-03-19T01:00:00.000Z",
      },
    });

    expect(statements).toHaveLength(1);
    expect(statements[0]?.sql).toContain('"auth"."verification"');
    expect(statements[0]?.sql).toContain('"expires_at"');
    expect(statements[0]?.sql).toContain('"created_at"');
    expect(statements[0]?.sql).toContain('"updated_at"');
    expect(statements[0]?.sql).not.toContain('"expiresAt"');
    expect(statements[0]?.params).toContain("student@example.edu");
    expect(statements[0]?.params).toContain("token_123");
    expect(statements[0]?.params).toContain("2026-03-19T01:00:00.000Z");
  });

  it("reads snake_case auth rows back as Better Auth camelCase fields", async () => {
    const { adapter, statements } = createFakeDb([
      {
        id: "ba_usr_123",
        email: "admin@example.edu",
        email_verified: true,
        two_factor_enabled: true,
        created_at: "2026-03-18T20:00:00.000Z",
        updated_at: "2026-03-18T20:05:00.000Z",
      },
    ]);

    const row = await adapter.findOne({
      model: "user",
      where: [
        {
          field: "emailVerified",
          operator: "eq",
          value: true,
          connector: "AND",
        },
      ],
      select: ["id", "emailVerified", "createdAt", "updatedAt"],
    });

    expect(statements).toHaveLength(1);
    expect(statements[0]?.sql).toContain('"email_verified" AS "emailVerified"');
    expect(statements[0]?.sql).toContain('"created_at" AS "createdAt"');
    expect(statements[0]?.sql).toContain('"updated_at" AS "updatedAt"');
    expect(statements[0]?.sql).toContain('WHERE "email_verified" = ?');
    expect(row?.id).toBe("ba_usr_123");
    expect(row?.emailVerified).toBe(true);
    expect(row?.createdAt).toEqual(new Date("2026-03-18T20:00:00.000Z"));
    expect(row?.updatedAt).toEqual(new Date("2026-03-18T20:05:00.000Z"));
  });
});
