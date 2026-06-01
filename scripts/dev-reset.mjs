import { createPostgresDatabase } from "@credtrail/db/postgres";

import { loadLocalDevEnv, requireEnv } from "./local-dev-env.mjs";
import {
  localDevDemoAdminEmail,
  localDevDemoTenantId,
} from "./local-dev-demo-defaults.mjs";

loadLocalDevEnv();

const tenantId = process.env.CREDTRAIL_DEV_TENANT_ID?.trim() || localDevDemoTenantId;
const adminEmail = process.env.CREDTRAIL_DEV_ADMIN_EMAIL?.trim() || localDevDemoAdminEmail;
const databaseUrl = requireEnv("DATABASE_URL");
const db = createPostgresDatabase({ databaseUrl, connectionMode: "single-use" });

const run = async (sql, ...bindings) => {
  await db.prepare(sql).bind(...bindings).run();
};

const main = async () => {
  await run("DELETE FROM assertions WHERE tenant_id = ?", tenantId);
  await run("DELETE FROM learner_profiles WHERE tenant_id = ?", tenantId);
  await run("DELETE FROM tenants WHERE id = ?", tenantId);
  await run(
    `
    DELETE FROM users
    WHERE lower(email) = lower(?)
      AND NOT EXISTS (
        SELECT 1
        FROM memberships
        WHERE memberships.user_id = users.id
      )
    `,
    adminEmail,
  );

  console.log(
    JSON.stringify(
      {
        status: "reset",
        tenantId,
        adminEmail,
        next: "Run pnpm dev:seed, or pnpm dev:up to reseed and start Wrangler.",
      },
      null,
      2,
    ),
  );
};

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
