import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  activateBadgeIssuanceRuleVersion,
  createAssertion,
  createBadgeIssuanceRule,
  ensureInstitutionOrgUnitForTenant,
  findAssertionByPublicId,
  listBadgeIssuanceRules,
  resolveLearnerProfileForIdentity,
  upsertBadgeTemplateById,
  upsertTenant,
  upsertTenantMembershipRole,
  upsertUserByEmail,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import localDevDemoContract from "./local-dev-demo-contract";

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
const tenantSlug = process.env.CREDTRAIL_DEV_TENANT_SLUG?.trim() || "demo-university";
const db = createPostgresDatabase({ databaseUrl, connectionMode: "single-use" });
const {
  localDevDemoAdminEmail,
  localDevDemoLearnerEmail,
  localDevDemoRoutes,
  localDevDemoRule,
  localDevDemoTemplates,
  localDevDemoTenantId,
  localDevDemoTrustedCredentialFixture,
} = localDevDemoContract;
const adminEmail = process.env.CREDTRAIL_DEV_ADMIN_EMAIL?.trim() || localDevDemoAdminEmail;
const tenantId = process.env.CREDTRAIL_DEV_TENANT_ID?.trim() || localDevDemoTenantId;

interface SeedLocalR2CredentialObjectResult {
  status: "seeded" | "skipped";
  bucketName: string;
  key: string;
  persistTo: string;
  detail?: string | undefined;
}

const shouldSeedLocalR2 = (): boolean => {
  return process.env.CREDTRAIL_DEV_SEED_R2?.trim().toLowerCase() !== "false";
};

const seedLocalR2CredentialObject = (
  bucketName: string,
  key: string,
  credential: unknown,
): SeedLocalR2CredentialObjectResult => {
  const persistTo = process.env.CREDTRAIL_DEV_R2_PERSIST_TO?.trim() || ".wrangler/state";

  if (!shouldSeedLocalR2()) {
    return {
      status: "skipped",
      bucketName,
      key,
      persistTo,
      detail: "CREDTRAIL_DEV_SEED_R2=false",
    };
  }

  const tempDirectory = mkdtempSync(join(tmpdir(), "credtrail-local-r2-"));
  const tempFile = join(tempDirectory, "credential.jsonld");

  try {
    writeFileSync(tempFile, `${JSON.stringify(credential)}\n`, "utf8");

    const result = spawnSync(
      "pnpm",
      [
        "exec",
        "wrangler",
        "r2",
        "object",
        "put",
        `${bucketName}/${key}`,
        "--file",
        tempFile,
        "--content-type",
        "application/ld+json",
        "--cache-control",
        "public, max-age=31536000, immutable",
        "--local",
        "--persist-to",
        persistTo,
      ],
      {
        cwd: process.cwd(),
        encoding: "utf8",
      },
    );

    if (result.status !== 0) {
      const stderr = result.stderr.trim();
      const stdout = result.stdout.trim();
      const detail = stderr.length > 0 ? stderr : stdout;

      throw new Error(
        `Unable to seed local R2 credential object "${bucketName}/${key}"${
          detail.length === 0 ? "" : `: ${detail}`
        }`,
      );
    }

    return {
      status: "seeded",
      bucketName,
      key,
      persistTo,
    };
  } finally {
    rmSync(tempDirectory, { recursive: true, force: true });
  }
};

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

  for (const template of localDevDemoTemplates) {
    await upsertBadgeTemplateById(db, {
      id: template.id,
      tenantId,
      slug: template.slug,
      title: template.title,
      description: template.description,
      criteriaUri: template.criteriaUri,
      imageUri: template.imageUri,
      trustedCredentialMetadataJson: template.trustedCredentialMetadataJson,
      createdByUserId: adminUser.id,
      ownerOrgUnitId,
      governanceMetadataJson: '{"source":"local_dev_seed","stability":"institution_registry"}',
    });
  }

  const existingRules = await listBadgeIssuanceRules(db, { tenantId });
  let seededRule = existingRules.find((rule) => rule.name === localDevDemoRule.name) ?? null;
  let seededRuleVersionId = seededRule?.activeVersionId ?? null;

  if (seededRule === null) {
    const createdRule = await createBadgeIssuanceRule(db, {
      tenantId,
      name: localDevDemoRule.name,
      description: localDevDemoRule.description,
      badgeTemplateId: localDevDemoRule.badgeTemplateId,
      lmsProviderKind: localDevDemoRule.lmsProviderKind,
      lmsConnectionId: localDevDemoRule.lmsConnectionId,
      ruleJson: JSON.stringify(localDevDemoRule.definition),
      changeSummary: "Seeded local demo rule",
      createdByUserId: adminUser.id,
    });

    const activeVersion = await activateBadgeIssuanceRuleVersion(db, {
      tenantId,
      ruleId: createdRule.rule.id,
      versionId: createdRule.version.id,
      actorUserId: adminUser.id,
      activatedAt: createdRule.version.createdAt,
    });

    seededRule = createdRule.rule;
    seededRuleVersionId = activeVersion?.id ?? createdRule.version.id;
  }

  const learnerProfile = await resolveLearnerProfileForIdentity(db, {
    tenantId,
    identityType: "email",
    identityValue: localDevDemoLearnerEmail,
    displayName: "Ada Lovelace",
  });

  const trustedDemo = localDevDemoTrustedCredentialFixture;
  const existingTrustedAssertion = await findAssertionByPublicId(db, trustedDemo.publicId);

  if (existingTrustedAssertion === null) {
    await createAssertion(db, {
      id: trustedDemo.assertionId,
      tenantId,
      publicId: trustedDemo.publicId,
      learnerProfileId: learnerProfile.id,
      badgeTemplateId: trustedDemo.badgeTemplateId,
      recipientIdentity: localDevDemoLearnerEmail,
      recipientIdentityType: "email",
      vcR2Key: trustedDemo.assertion.vcR2Key,
      statusListIndex: trustedDemo.assertion.statusListIndex ?? 7,
      idempotencyKey: trustedDemo.assertion.idempotencyKey,
      issuedAt: trustedDemo.assertion.issuedAt,
      issuedByUserId: adminUser.id,
      recipientIdentifiers: [
        {
          identifierType: "emailAddress",
          identifierValue: localDevDemoLearnerEmail,
        },
      ],
    });
  }

  const localR2Seed = seedLocalR2CredentialObject(
    process.env.CREDTRAIL_DEV_R2_BUCKET?.trim() || "credtrail-badges-local",
    trustedDemo.assertion.vcR2Key,
    trustedDemo.credential,
  );

  console.log(
    JSON.stringify(
      {
        status: "seeded",
        tenantId,
        tenantSlug,
        adminEmail,
        adminUserId: adminUser.id,
        learnerEmail: localDevDemoLearnerEmail,
        learnerProfileId: learnerProfile.id,
        badgeTemplateIds: localDevDemoTemplates.map((template) => template.id),
        badgeRule: {
          id: seededRule?.id ?? null,
          activeVersionId: seededRuleVersionId,
          name: localDevDemoRule.name,
        },
        publicCredential: {
          publicId: trustedDemo.publicId,
          route: trustedDemo.routeFamily.publicCredential,
          r2Object: localR2Seed,
        },
        loginNextPath: `/tenants/${encodeURIComponent(tenantId)}/admin`,
        demoRoutes: localDevDemoRoutes(tenantId),
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
