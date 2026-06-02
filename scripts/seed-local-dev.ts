import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
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
  upsertTenantLmsConnection,
  upsertTenantMembershipRole,
  upsertUserByEmail,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { loadLocalDevEnv, requireEnv } from "./local-dev-env.mjs";
import localDevDemoContract from "./local-dev-demo-contract";

loadLocalDevEnv();

const databaseUrl = requireEnv("DATABASE_URL");
const requestedTenantId = process.env.CREDTRAIL_DEV_TENANT_ID?.trim();
const requestedTenantSlug = process.env.CREDTRAIL_DEV_TENANT_SLUG?.trim();
const db = createPostgresDatabase({ databaseUrl, connectionMode: "single-use" });
const {
  localDevDemoAdminEmail,
  localDevDemoLearnerEmail,
  localDevDemoLmsConnection,
  localDevDemoRoutes,
  localDevDemoRule,
  localDevDemoTemplates,
  localDevDemoTenantId,
  localDevDemoTrustedCredentialFixture,
} = localDevDemoContract;
const adminEmail = process.env.CREDTRAIL_DEV_ADMIN_EMAIL?.trim() || localDevDemoAdminEmail;

interface SeedLocalR2CredentialObjectResult {
  status: "seeded" | "skipped";
  bucketName: string;
  key: string;
  persistTo: string;
  detail?: string | undefined;
}

interface LocalDevSeedTenantConfig {
  tenantId: string;
  tenantSlug: string;
  displayName: string;
  issuerDomain: string;
  didWeb: string;
  fixtureSuffix: string;
  lmsDisplayName: string;
  lmsProviderKind: "canvas" | "sakai";
  lmsApiBaseUrl: string;
  lmsAuthorizationEndpoint?: string | undefined;
  lmsTokenEndpoint?: string | undefined;
  lmsClientId?: string | undefined;
  lmsScope?: string | undefined;
  seedTrustedCredential: boolean;
}

interface SeedLocalTenantResult {
  tenantId: string;
  tenantSlug: string;
  adminEmail: string;
  adminUserId: string;
  learnerEmail: string;
  learnerProfileId: string;
  badgeTemplateIds: string[];
  lmsConnectionId: string;
  badgeRule: {
    id: string | null;
    activeVersionId: string | null;
    name: string;
  };
  publicCredential?: {
    publicId: string;
    route: string;
    r2Object: SeedLocalR2CredentialObjectResult;
  };
  loginNextPath: string;
  demoRoutes: ReturnType<typeof localDevDemoRoutes>;
}

const shouldSeedLocalR2 = (): boolean => {
  return process.env.CREDTRAIL_DEV_SEED_R2?.trim().toLowerCase() !== "false";
};

const wranglerLocalR2ObjectPath = (bucketName: string, key: string): string => {
  return `${bucketName}/${key.replaceAll("%", "%25")}`;
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
        wranglerLocalR2ObjectPath(bucketName, key),
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

const scopedFixtureId = (baseId: string, suffix: string): string => {
  return suffix.length === 0 ? baseId : `${baseId}_${suffix}`;
};

const scopedFixtureSlug = (baseSlug: string, suffix: string): string => {
  return suffix.length === 0 ? baseSlug : `${baseSlug}-${suffix}`;
};

const buildSeedTenantConfigs = (): LocalDevSeedTenantConfig[] => {
  const hasRequestedTenant = requestedTenantId !== undefined && requestedTenantId.length > 0;
  const primaryTenantId = requestedTenantId ?? localDevDemoTenantId;
  const primaryTenantSlug = requestedTenantSlug ?? "demo-university";
  const primarySuffix = primaryTenantId === localDevDemoTenantId ? "" : primaryTenantId;
  const configs: LocalDevSeedTenantConfig[] = [
    {
      tenantId: primaryTenantId,
      tenantSlug: primaryTenantSlug,
      displayName: "Demo University",
      issuerDomain: primarySuffix.length === 0 ? "localhost" : `${primaryTenantId}.localhost`,
      didWeb:
        primarySuffix.length === 0 ? "did:web:localhost" : `did:web:${primaryTenantId}.localhost`,
      fixtureSuffix: primarySuffix,
      lmsDisplayName: localDevDemoLmsConnection.displayName,
      lmsProviderKind: localDevDemoLmsConnection.providerKind,
      lmsApiBaseUrl: localDevDemoLmsConnection.apiBaseUrl,
      lmsAuthorizationEndpoint: localDevDemoLmsConnection.authorizationEndpoint,
      lmsTokenEndpoint: localDevDemoLmsConnection.tokenEndpoint,
      lmsClientId: localDevDemoLmsConnection.clientId,
      lmsScope: localDevDemoLmsConnection.scope,
      seedTrustedCredential: primarySuffix.length === 0,
    },
  ];

  if (!hasRequestedTenant && process.env.CREDTRAIL_DEV_SEED_SAKAI?.trim() !== "false") {
    configs.push({
      tenantId: "sakai",
      tenantSlug: "sakai",
      displayName: "Sakai Demo University",
      issuerDomain: "sakai.localhost",
      didWeb: "did:web:sakai.localhost",
      fixtureSuffix: "sakai",
      lmsDisplayName: "Local Demo Sakai",
      lmsProviderKind: "sakai",
      lmsApiBaseUrl: "https://sakai.localhost.invalid",
      lmsClientId: "local-demo-sakai-client",
      lmsScope: "site.upd",
      seedTrustedCredential: false,
    });
  }

  return configs;
};

const seedLocalTenant = async (
  config: LocalDevSeedTenantConfig,
): Promise<SeedLocalTenantResult> => {
  await upsertTenant(db, {
    id: config.tenantId,
    slug: config.tenantSlug,
    displayName: config.displayName,
    planTier: "institution",
    issuerDomain: config.issuerDomain,
    didWeb: config.didWeb,
    isActive: true,
  });

  const ownerOrgUnitId = await ensureInstitutionOrgUnitForTenant(db, config.tenantId);
  const adminUser = await upsertUserByEmail(db, adminEmail);

  await upsertTenantMembershipRole(db, {
    tenantId: config.tenantId,
    userId: adminUser.id,
    role: "owner",
  });

  for (const template of localDevDemoTemplates) {
    await upsertBadgeTemplateById(db, {
      id: scopedFixtureId(template.id, config.fixtureSuffix),
      tenantId: config.tenantId,
      slug: scopedFixtureSlug(template.slug, config.fixtureSuffix),
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

  const lmsConnectionId = scopedFixtureId(localDevDemoLmsConnection.id, config.fixtureSuffix);

  await upsertTenantLmsConnection(db, {
    id: lmsConnectionId,
    tenantId: config.tenantId,
    displayName: config.lmsDisplayName,
    providerKind: config.lmsProviderKind,
    apiBaseUrl: config.lmsApiBaseUrl,
    authorizationEndpoint: config.lmsAuthorizationEndpoint,
    tokenEndpoint: config.lmsTokenEndpoint,
    clientId: config.lmsClientId,
    scope: config.lmsScope,
  });

  const existingRules = await listBadgeIssuanceRules(db, { tenantId: config.tenantId });
  let seededRule = existingRules.find((rule) => rule.name === localDevDemoRule.name) ?? null;
  let seededRuleVersionId = seededRule?.activeVersionId ?? null;

  if (seededRule === null) {
    const createdRule = await createBadgeIssuanceRule(db, {
      tenantId: config.tenantId,
      name: localDevDemoRule.name,
      description: localDevDemoRule.description,
      badgeTemplateId: scopedFixtureId(localDevDemoRule.badgeTemplateId, config.fixtureSuffix),
      lmsProviderKind: config.lmsProviderKind,
      lmsConnectionId,
      ruleJson: JSON.stringify(localDevDemoRule.definition),
      changeSummary: "Seeded local demo rule",
      createdByUserId: adminUser.id,
    });

    const activeVersion = await activateBadgeIssuanceRuleVersion(db, {
      tenantId: config.tenantId,
      ruleId: createdRule.rule.id,
      versionId: createdRule.version.id,
      actorUserId: adminUser.id,
      activatedAt: createdRule.version.createdAt,
    });

    seededRule = createdRule.rule;
    seededRuleVersionId = activeVersion?.id ?? createdRule.version.id;
  }

  const learnerProfile = await resolveLearnerProfileForIdentity(db, {
    tenantId: config.tenantId,
    identityType: "email",
    identityValue: localDevDemoLearnerEmail,
    displayName: "Ada Lovelace",
  });

  const trustedDemo = localDevDemoTrustedCredentialFixture;
  let publicCredential: SeedLocalTenantResult["publicCredential"];

  if (config.seedTrustedCredential) {
    const existingTrustedAssertion = await findAssertionByPublicId(db, trustedDemo.publicId);

    if (existingTrustedAssertion === null) {
      await createAssertion(db, {
        id: trustedDemo.assertionId,
        tenantId: config.tenantId,
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

    publicCredential = {
      publicId: trustedDemo.publicId,
      route: trustedDemo.routeFamily.publicCredential,
      r2Object: localR2Seed,
    };
  }

  return {
    tenantId: config.tenantId,
    tenantSlug: config.tenantSlug,
    adminEmail,
    adminUserId: adminUser.id,
    learnerEmail: localDevDemoLearnerEmail,
    learnerProfileId: learnerProfile.id,
    badgeTemplateIds: localDevDemoTemplates.map((template) =>
      scopedFixtureId(template.id, config.fixtureSuffix),
    ),
    lmsConnectionId,
    badgeRule: {
      id: seededRule?.id ?? null,
      activeVersionId: seededRuleVersionId,
      name: localDevDemoRule.name,
    },
    publicCredential,
    loginNextPath: `/tenants/${encodeURIComponent(config.tenantId)}/admin`,
    demoRoutes: localDevDemoRoutes(config.tenantId),
  };
};

const main = async (): Promise<void> => {
  const seededTenants: SeedLocalTenantResult[] = [];

  for (const config of buildSeedTenantConfigs()) {
    seededTenants.push(await seedLocalTenant(config));
  }

  const primaryTenant = seededTenants[0];

  if (primaryTenant === undefined) {
    throw new Error("No local dev tenants were seeded.");
  }

  console.log(
    JSON.stringify(
      {
        status: "seeded",
        ...primaryTenant,
        seededTenants,
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
