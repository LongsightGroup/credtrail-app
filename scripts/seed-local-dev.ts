import { readFileSync } from "node:fs";

import {
  activateBadgeIssuanceRuleVersion,
  badgeAchievementSnapshotFromRuleVersion,
  badgeAchievementSnapshotFromTemplate,
  badgeAchievementSnapshotsEqual,
  badgeIssuanceRuleIdentityForBuilderDraft,
  ensureInstitutionOrgUnitForTenant,
  findAssertionByPublicId,
  findBadgeIssuanceRuleById,
  findBadgeTemplateById,
  findTenantSigningRegistrationByDid,
  finalizeAssertionIssuance,
  listBadgeIssuanceRules,
  listBadgeIssuanceRuleVersions,
  resolveLearnerProfileForIdentity,
  upsertBadgeTemplateById,
  upsertTenant,
  upsertTenantLmsConnection,
  upsertTenantMembershipRole,
  upsertTenantSigningRegistration,
  upsertUserByEmail,
} from "@credtrail/db";
import { createDidWeb, generateTenantDidSigningMaterial } from "@credtrail/core-domain";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { authorPreparedBadgeRule } from "../apps/api-worker/src/badges/badge-rule-authoring-service";
import { ensureLocalDevBadgeTemplateArtwork } from "./local-dev-badge-artwork";
import { loadLocalDevEnv, requireEnv } from "./local-dev-env.mjs";
import localDevDemoContract from "./local-dev-demo-contract";
import {
  createWranglerLocalR2Store,
  ensureWranglerLocalR2Object,
  type EnsuredWranglerLocalR2Object,
} from "./wrangler-local-r2-store";

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
const localR2BucketName = process.env.CREDTRAIL_DEV_R2_BUCKET?.trim() || "credtrail-badges-local";
const localR2PersistTo = process.env.CREDTRAIL_DEV_R2_PERSIST_TO?.trim() || ".wrangler/state";
const publicAppOrigin = requireEnv("PUBLIC_APP_ORIGIN");
const appliedAnalyticsArtworkBytes = new Uint8Array(
  readFileSync(new URL("./assets/local-dev-applied-analytics-badge.png", import.meta.url)),
);

interface SeedLocalR2CredentialObjectResult extends EnsuredWranglerLocalR2Object {
  bucketName: string;
  persistTo: string;
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

const localSeedObjectStore = createWranglerLocalR2Store({
  bucketName: localR2BucketName,
  persistTo: localR2PersistTo,
});

const scopedFixtureId = (baseId: string, suffix: string): string => {
  return suffix.length === 0 ? baseId : `${baseId}_${suffix}`;
};

const scopedFixtureSlug = (baseSlug: string, suffix: string): string => {
  return suffix.length === 0 ? baseSlug : `${baseSlug}-${suffix}`;
};

const deleteLocalDevSeedRule = async (tenantId: string, ruleId: string): Promise<void> => {
  await db
    .prepare("DELETE FROM badge_issuance_rules WHERE tenant_id = ? AND id = ?")
    .bind(tenantId, ruleId)
    .run();
};

const ensureLocalDevTenantSigning = async (config: LocalDevSeedTenantConfig): Promise<void> => {
  const existingRegistration = await findTenantSigningRegistrationByDid(db, config.didWeb);

  if (existingRegistration !== null && existingRegistration.privateJwkJson !== null) {
    return;
  }

  const signingMaterial = await generateTenantDidSigningMaterial({ did: config.didWeb });
  await upsertTenantSigningRegistration(db, {
    tenantId: config.tenantId,
    did: signingMaterial.did,
    keyId: signingMaterial.keyId,
    publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
    privateJwkJson: JSON.stringify(signingMaterial.privateJwk),
  });
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
      didWeb: createDidWeb({ host: "localhost", pathSegments: [primaryTenantId] }),
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
      didWeb: createDidWeb({ host: "localhost", pathSegments: ["sakai"] }),
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
  await ensureLocalDevTenantSigning(config);

  const ownerOrgUnitId = await ensureInstitutionOrgUnitForTenant(db, config.tenantId);
  const adminUser = await upsertUserByEmail(db, adminEmail);

  await upsertTenantMembershipRole(db, {
    tenantId: config.tenantId,
    userId: adminUser.id,
    role: "owner",
  });

  for (const template of localDevDemoTemplates) {
    const badgeTemplateId = scopedFixtureId(template.id, config.fixtureSuffix);
    const imageUri =
      template.artworkAsset === "applied_analytics"
        ? await ensureLocalDevBadgeTemplateArtwork({
            store: localSeedObjectStore,
            publicAppOrigin,
            tenantId: config.tenantId,
            badgeTemplateId,
            mimeType: "image/png",
            bytes: appliedAnalyticsArtworkBytes,
            originalFilename: "local-dev-applied-analytics-badge.png",
          })
        : null;

    await upsertBadgeTemplateById(db, {
      id: badgeTemplateId,
      tenantId: config.tenantId,
      slug: scopedFixtureSlug(template.slug, config.fixtureSuffix),
      title: template.title,
      description: template.description,
      criteriaUri: template.criteriaUri,
      imageUri,
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

  const badgeTemplateId = scopedFixtureId(localDevDemoRule.badgeTemplateId, config.fixtureSuffix);
  const seededRuleBuilderDraftId = scopedFixtureId("brd_local_dev_seed_rule", config.fixtureSuffix);
  const seededRuleIdentity = await badgeIssuanceRuleIdentityForBuilderDraft(
    config.tenantId,
    seededRuleBuilderDraftId,
  );
  const existingRules = await listBadgeIssuanceRules(db, { tenantId: config.tenantId });

  for (const rule of existingRules) {
    const isSupersededSeedRule =
      rule.id !== seededRuleIdentity.ruleId &&
      rule.name === localDevDemoRule.name &&
      rule.badgeTemplateId === badgeTemplateId &&
      rule.lmsConnectionId === lmsConnectionId &&
      rule.createdByUserId === adminUser.id;

    if (isSupersededSeedRule) {
      await deleteLocalDevSeedRule(config.tenantId, rule.id);
    }
  }

  let seededRule = await findBadgeIssuanceRuleById(db, config.tenantId, seededRuleIdentity.ruleId);
  let seededRuleVersionId = seededRule?.activeVersionId ?? null;
  const seededTemplate = await findBadgeTemplateById(db, config.tenantId, badgeTemplateId);

  if (seededTemplate === null) {
    throw new Error(`Unable to load seeded badge template "${badgeTemplateId}"`);
  }

  if (seededRule !== null) {
    const versions = await listBadgeIssuanceRuleVersions(db, {
      tenantId: config.tenantId,
      ruleId: seededRule.id,
    });
    const activeVersion = versions.find((version) => version.id === seededRule?.activeVersionId);
    const ruleJson = JSON.stringify(localDevDemoRule.definition);
    const hasCurrentSeedContract =
      seededRule.name === localDevDemoRule.name &&
      seededRule.description === localDevDemoRule.description &&
      seededRule.badgeTemplateId === badgeTemplateId &&
      seededRule.lmsProviderKind === config.lmsProviderKind &&
      seededRule.lmsConnectionId === lmsConnectionId &&
      activeVersion !== undefined &&
      activeVersion.status === "active" &&
      activeVersion.ruleJson === ruleJson &&
      activeVersion.snapshot.name === localDevDemoRule.name &&
      activeVersion.snapshot.description === localDevDemoRule.description &&
      activeVersion.snapshot.orgUnitId === seededTemplate.ownerOrgUnitId &&
      activeVersion.snapshot.ownerOrgUnitId === seededTemplate.ownerOrgUnitId &&
      activeVersion.snapshot.lmsProviderKind === config.lmsProviderKind &&
      activeVersion.snapshot.lmsConnectionId === lmsConnectionId &&
      badgeAchievementSnapshotsEqual(
        badgeAchievementSnapshotFromRuleVersion(activeVersion.snapshot),
        badgeAchievementSnapshotFromTemplate(seededTemplate),
      );

    if (!hasCurrentSeedContract) {
      await deleteLocalDevSeedRule(config.tenantId, seededRule.id);
      seededRule = null;
      seededRuleVersionId = null;
    }
  }

  if (seededRule === null) {
    const authoredRule = await authorPreparedBadgeRule({
      kind: "create",
      db,
      store: localSeedObjectStore,
      publicAppOrigin,
      tenantId: config.tenantId,
      actorUserId: adminUser.id,
      actorRole: "owner",
      lmsConnection: {
        id: lmsConnectionId,
        providerKind: config.lmsProviderKind,
      },
      ruleJson: JSON.stringify(localDevDemoRule.definition),
      request: {
        name: localDevDemoRule.name,
        description: localDevDemoRule.description,
        badgeTemplateId,
        badgeTemplateReuseAcknowledged: true,
        lmsConnectionId,
        definition: localDevDemoRule.definition,
        changeSummary: "Seeded local demo rule",
        action: "save_draft",
        builderDraftId: seededRuleBuilderDraftId,
      },
    });

    if (authoredRule.status === "failed") {
      throw new Error(`Unable to author local demo badge rule (${authoredRule.reason})`);
    }

    const activeVersion = await activateBadgeIssuanceRuleVersion(db, {
      tenantId: config.tenantId,
      ruleId: authoredRule.rule.id,
      versionId: authoredRule.version.id,
      actorUserId: adminUser.id,
      activatedAt: authoredRule.version.createdAt,
    });

    seededRule = authoredRule.rule;
    seededRuleVersionId = activeVersion?.id ?? authoredRule.version.id;
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
      const finalizedAssertion = await finalizeAssertionIssuance(db, {
        assertion: {
          id: trustedDemo.assertionId,
          tenantId: config.tenantId,
          publicId: trustedDemo.publicId,
          learnerProfileId: learnerProfile.id,
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
        },
        achievementSource: {
          kind: "template_snapshot",
          snapshot: trustedDemo.assertion.achievementSnapshot,
          provenance: { source: "programmatic" },
        },
        buildAuditLog: (assertion) => ({
          tenantId: config.tenantId,
          actorUserId: adminUser.id,
          action: "assertion.issued",
          targetType: "assertion",
          targetId: assertion.id,
          metadata: {
            assertionPublicId: assertion.publicId,
            badgeTemplateId: assertion.badgeTemplateId,
            recipientIdentity: assertion.recipientIdentity,
            recipientIdentityType: assertion.recipientIdentityType,
            issuedAt: assertion.issuedAt,
            source: "local_dev_seed",
          },
        }),
      });

      if (finalizedAssertion.status !== "issued") {
        throw new Error("Unable to finalize the seeded trusted credential assertion");
      }
    }

    const ensuredCredential = await ensureWranglerLocalR2Object(localSeedObjectStore, {
      key: trustedDemo.assertion.vcR2Key,
      value: JSON.stringify(trustedDemo.credential),
      contentType: "application/ld+json",
      cacheControl: "public, max-age=31536000, immutable",
    });
    const localR2Seed: SeedLocalR2CredentialObjectResult = {
      ...ensuredCredential,
      bucketName: localR2BucketName,
      persistTo: localR2PersistTo,
    };

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
