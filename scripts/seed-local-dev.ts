import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  ensureInstitutionOrgUnitForTenant,
  upsertBadgeTemplateById,
  upsertTenant,
  upsertTenantMembershipRole,
  upsertUserByEmail,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

const loadLocalDevEnv = (cwd: string = process.cwd()): void => {
  try {
    const envPath = join(cwd, ".dev.vars.local");
    const contents = readFileSync(envPath, "utf8");

    for (const rawLine of contents.split(/\r?\n/g)) {
      const line = rawLine.trim();

      if (line.length === 0 || line.startsWith("#")) {
        continue;
      }

      const separatorIndex = line.indexOf("=");

      if (separatorIndex === -1) {
        continue;
      }

      const key = line.slice(0, separatorIndex).trim();
      let value = line.slice(separatorIndex + 1).trim();

      if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1);
      }

      if (process.env[key] === undefined) {
        process.env[key] = value;
      }
    }
  } catch (error: unknown) {
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "ENOENT"
    ) {
      return;
    }

    throw error;
  }
};

const requireEnv = (name: string): string => {
  const value = process.env[name]?.trim();

  if (value === undefined || value.length === 0) {
    throw new Error(`${name} is required`);
  }

  return value;
};

loadLocalDevEnv();

const databaseUrl = requireEnv("DATABASE_URL");
const adminEmail = process.env.CREDTRAIL_DEV_ADMIN_EMAIL?.trim() || "admin@credtrail.local";
const tenantId = process.env.CREDTRAIL_DEV_TENANT_ID?.trim() || "tenant_123";
const tenantSlug = process.env.CREDTRAIL_DEV_TENANT_SLUG?.trim() || "demo-university";
const db = createPostgresDatabase({ databaseUrl, connectionMode: "single-use" });

const main = async (): Promise<void> => {
  await upsertTenant(db, {
    id: tenantId,
    slug: tenantSlug,
    displayName: "Demo University",
    planTier: "institution",
    issuerDomain: "localhost",
    didWeb: "did:web:localhost",
    isActive: true,
  });

  const ownerOrgUnitId = await ensureInstitutionOrgUnitForTenant(db, tenantId);
  const adminUser = await upsertUserByEmail(db, adminEmail);

  await upsertTenantMembershipRole(db, {
    tenantId,
    userId: adminUser.id,
    role: "owner",
  });

  await upsertBadgeTemplateById(db, {
    id: "badge_template_foundations",
    tenantId,
    slug: "foundations",
    title: "Foundations Badge",
    description: "Awarded for completing the local demo foundations workflow.",
    criteriaUri: "https://localhost/criteria/foundations",
    createdByUserId: adminUser.id,
    ownerOrgUnitId,
    governanceMetadataJson: '{"source":"local_dev_seed","stability":"institution_registry"}',
  });

  await upsertBadgeTemplateById(db, {
    id: "badge_template_capstone",
    tenantId,
    slug: "capstone",
    title: "Capstone Badge",
    description: "Awarded for demonstrating the capstone skill in the local demo environment.",
    criteriaUri: "https://localhost/criteria/capstone",
    createdByUserId: adminUser.id,
    ownerOrgUnitId,
    governanceMetadataJson: '{"source":"local_dev_seed","stability":"institution_registry"}',
  });

  console.log(
    JSON.stringify(
      {
        status: "seeded",
        tenantId,
        tenantSlug,
        adminEmail,
        adminUserId: adminUser.id,
        loginNextPath: `/tenants/${encodeURIComponent(tenantId)}/admin`,
      },
      null,
      2,
    ),
  );
};

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
