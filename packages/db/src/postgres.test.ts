import { expect, it } from "vitest";

import { createPostgresDatabase } from "./postgres";
import { describeDbIntegration, requireTestDatabaseUrl } from "./postgres-test-support";

describeDbIntegration("postgres adapter integration", () => {
  it.each([
    { label: "pg pool", connectionMode: "pool" as const },
    { label: "pg single-use", connectionMode: "single-use" as const },
  ])(
    "supports question-mark placeholders and ON CONFLICT DO NOTHING semantics with $label",
    async ({ connectionMode }) => {
      const tableName = `test_adapter_users_${crypto.randomUUID().replace(/-/g, "")}`;
      const db = createPostgresDatabase({
        databaseUrl: requireTestDatabaseUrl(),
        connectionMode,
      });

      try {
        await db
          .prepare(
            `
          CREATE TABLE ${tableName} (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE
          )
        `,
          )
          .run();

        await db
          .prepare(
            `
          INSERT INTO ${tableName} (id, email)
          VALUES (?, ?)
          ON CONFLICT DO NOTHING
        `,
          )
          .bind("usr_first", "student@example.edu")
          .run();

        await db
          .prepare(
            `
          INSERT INTO ${tableName} (id, email)
          VALUES (?, ?)
          ON CONFLICT DO NOTHING
        `,
          )
          .bind("usr_duplicate", "student@example.edu")
          .run();

        const rows = await db
          .prepare(
            `
          SELECT id, email
          FROM ${tableName}
          WHERE email = ?
          ORDER BY id ASC
        `,
          )
          .bind("student@example.edu")
          .all<{ id: string; email: string }>();

        expect(rows.results).toHaveLength(1);
        expect(rows.results[0]?.id).toBe("usr_first");

        const singleRow = await db
          .prepare(
            `
          SELECT id, email
          FROM ${tableName}
          WHERE id = ?
          LIMIT 1
        `,
          )
          .bind("usr_first")
          .first<{ id: string; email: string }>();

        expect(singleRow).not.toBeNull();
        expect(singleRow?.email).toBe("student@example.edu");

        const aliasedRow = await db
          .prepare(
            `
          SELECT email AS recipientEmail
          FROM ${tableName}
          WHERE id = ?
          LIMIT 1
        `,
          )
          .bind("usr_first")
          .first<{ recipientEmail: string }>();

        expect(aliasedRow).not.toBeNull();
        expect(aliasedRow?.recipientEmail).toBe("student@example.edu");
      } finally {
        await db.prepare(`DROP TABLE IF EXISTS ${tableName}`).run();
      }
    },
  );
});
