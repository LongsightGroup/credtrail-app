import { expect, it } from "vitest";

import {
  listTenantAssertions,
  listTenantAssertionLedgerExportRows,
  findBadgeTemplateById,
  SYNCHRONOUS_EXPORT_ROW_LIMIT,
  upsertUserByEmail,
  type SqlDatabase,
} from "./index";
import {
  cleanupTestResources,
  createTestTenantFixture,
  describeDbIntegration,
  seedAssertion,
  seedAssertionAttribution,
  seedBadgeTemplate,
  seedLedgerOrgTree,
  seedLifecycleEvent,
  uniqueTestId,
} from "./postgres-test-support";

const seedLedgerRows = async (): Promise<{
  db: SqlDatabase;
  tenantId: string;
  issuerUserId: string;
  badgeTemplateId: string;
  assertionMatchId: string;
  microbiologyProgramId: string;
}> => {
  const fixture = await createTestTenantFixture({
    displayName: "CredTrail University",
  });
  const orgTree = await seedLedgerOrgTree(fixture.db, fixture.tenantId);
  const issuer = await upsertUserByEmail(fixture.db, `${uniqueTestId("issuer")}@example.edu`);
  const badgeTemplateId = await seedBadgeTemplate(fixture.db, {
    tenantId: fixture.tenantId,
    title: "Foundations of Microbiology",
  });
  const assertionMatchId = uniqueTestId("assertion_match");
  const oldAssertionId = uniqueTestId("assertion_old_issue_date");
  const revokedAssertionId = uniqueTestId("assertion_wrong_state");
  const otherLeafAssertionId = uniqueTestId("assertion_wrong_leaf");

  await seedAssertion(fixture.db, {
    id: assertionMatchId,
    tenantId: fixture.tenantId,
    publicId: uniqueTestId("public_match"),
    badgeTemplateId,
    recipientIdentity: "learner.one@example.edu",
    issuedAt: "2026-03-10T15:45:00.000Z",
    issuedByUserId: issuer.id,
  });
  await seedAssertionAttribution(fixture.db, {
    assertionId: assertionMatchId,
    tenantId: fixture.tenantId,
    badgeTemplateId,
    orgUnitId: orgTree.microbiologyProgramId,
    attributionSource: "historical_backfill",
    attributedAt: "2026-03-10T15:45:00.000Z",
  });
  await seedLifecycleEvent(fixture.db, {
    tenantId: fixture.tenantId,
    assertionId: assertionMatchId,
    fromState: "active",
    toState: "suspended",
    reasonCode: "administrative_hold",
    reason: "Paused during registrar review",
    transitionedAt: "2026-03-12T10:15:00.000Z",
  });

  await seedAssertion(fixture.db, {
    id: oldAssertionId,
    tenantId: fixture.tenantId,
    publicId: uniqueTestId("public_old"),
    badgeTemplateId,
    recipientIdentity: "learner.old@example.edu",
    issuedAt: "2026-02-01T09:00:00.000Z",
    issuedByUserId: issuer.id,
  });
  await seedAssertionAttribution(fixture.db, {
    assertionId: oldAssertionId,
    tenantId: fixture.tenantId,
    badgeTemplateId,
    orgUnitId: orgTree.microbiologyProgramId,
    attributionSource: "historical_backfill",
    attributedAt: "2026-02-01T09:00:00.000Z",
  });
  await seedLifecycleEvent(fixture.db, {
    tenantId: fixture.tenantId,
    assertionId: oldAssertionId,
    fromState: "active",
    toState: "suspended",
    reasonCode: "administrative_hold",
    reason: "Paused during registrar review",
    transitionedAt: "2026-03-12T10:15:00.000Z",
  });

  await seedAssertion(fixture.db, {
    id: revokedAssertionId,
    tenantId: fixture.tenantId,
    publicId: uniqueTestId("public_revoked"),
    badgeTemplateId,
    recipientIdentity: "learner.revoked@example.edu",
    issuedAt: "2026-03-11T08:00:00.000Z",
    issuedByUserId: issuer.id,
    revokedAt: "2026-03-15T00:00:00.000Z",
  });
  await seedAssertionAttribution(fixture.db, {
    assertionId: revokedAssertionId,
    tenantId: fixture.tenantId,
    badgeTemplateId,
    orgUnitId: orgTree.microbiologyProgramId,
    attributionSource: "issuance_snapshot",
    attributedAt: "2026-03-11T08:00:00.000Z",
  });
  await seedLifecycleEvent(fixture.db, {
    tenantId: fixture.tenantId,
    assertionId: revokedAssertionId,
    fromState: "suspended",
    toState: "revoked",
    reasonCode: "issuer_requested",
    reason: "Credential revoked after policy violation",
    transitionedAt: "2026-03-15T00:00:00.000Z",
  });

  await seedAssertion(fixture.db, {
    id: otherLeafAssertionId,
    tenantId: fixture.tenantId,
    publicId: uniqueTestId("public_other_leaf"),
    badgeTemplateId,
    recipientIdentity: "learner.two@example.edu",
    issuedAt: "2026-03-11T09:00:00.000Z",
    issuedByUserId: issuer.id,
  });
  await seedAssertionAttribution(fixture.db, {
    assertionId: otherLeafAssertionId,
    tenantId: fixture.tenantId,
    badgeTemplateId,
    orgUnitId: orgTree.biochemistryProgramId,
    attributionSource: "historical_backfill",
    attributedAt: "2026-03-11T09:00:00.000Z",
  });
  await seedLifecycleEvent(fixture.db, {
    tenantId: fixture.tenantId,
    assertionId: otherLeafAssertionId,
    fromState: "active",
    toState: "suspended",
    reasonCode: "administrative_hold",
    reason: "Paused during registrar review",
    transitionedAt: "2026-03-12T10:15:00.000Z",
  });

  return {
    db: fixture.db,
    tenantId: fixture.tenantId,
    issuerUserId: issuer.id,
    badgeTemplateId,
    assertionMatchId,
    microbiologyProgramId: orgTree.microbiologyProgramId,
  };
};

describeDbIntegration("ledger export foundation", () => {
  it("filters badge record rows by issued date, template, state, and exact-match leaf orgUnitId", async () => {
    const fixture = await seedLedgerRows();

    try {
      const result = await listTenantAssertions(fixture.db, {
        tenantId: fixture.tenantId,
        issuedFrom: "2026-03-01",
        issuedTo: "2026-03-31",
        badgeTemplateId: fixture.badgeTemplateId,
        orgUnitId: fixture.microbiologyProgramId,
        state: "suspended",
      });

      expect(result).toEqual([
        expect.objectContaining({
          assertionId: fixture.assertionMatchId,
          state: "suspended",
        }),
      ]);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.issuerUserId],
      });
    }
  });

  it("filters ledger export rows by issued date, template, state, and exact-match leaf orgUnitId", async () => {
    const fixture = await seedLedgerRows();

    try {
      const result = await listTenantAssertionLedgerExportRows(fixture.db, {
        tenantId: fixture.tenantId,
        issuedFrom: "2026-03-01",
        issuedTo: "2026-03-31",
        badgeTemplateId: fixture.badgeTemplateId,
        orgUnitId: fixture.microbiologyProgramId,
        state: "suspended",
      });

      expect(result).toEqual({
        status: "ok",
        rowLimit: SYNCHRONOUS_EXPORT_ROW_LIMIT,
        rows: [
          expect.objectContaining({
            assertionId: fixture.assertionMatchId,
            orgUnitId: fixture.microbiologyProgramId,
            state: "suspended",
          }),
        ],
      });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.issuerUserId],
      });
    }
  });

  it("returns stable leaf attribution, lifecycle details, and current-tree lineage convenience fields", async () => {
    const fixture = await seedLedgerRows();

    try {
      const result = await listTenantAssertionLedgerExportRows(fixture.db, {
        tenantId: fixture.tenantId,
        recipientQuery: "learner.one",
      });

      expect(result).toEqual({
        status: "ok",
        rowLimit: SYNCHRONOUS_EXPORT_ROW_LIMIT,
        rows: [
          expect.objectContaining({
            assertionId: fixture.assertionMatchId,
            badgeTemplateId: fixture.badgeTemplateId,
            badgeTitle: "Foundations of Microbiology",
            recipientIdentity: "learner.one@example.edu",
            recipientIdentityType: "email",
            issuedAt: "2026-03-10T15:45:00.000Z",
            orgUnitId: fixture.microbiologyProgramId,
            orgUnitDisplayName: "Microbiology Program",
            attributionSource: "historical_backfill",
            state: "suspended",
            source: "lifecycle_event",
            reasonCode: "administrative_hold",
            reason: "Paused during registrar review",
            transitionedAt: "2026-03-12T10:15:00.000Z",
            currentInstitutionName: "CredTrail University Institution",
            currentCollegeName: "College of Science",
            currentDepartmentName: "Biology Department",
            currentProgramName: "Microbiology Program",
          }),
        ],
      });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.issuerUserId],
      });
    }
  });

  it("returns an explicit too_large status above the synchronous export cap", async () => {
    const fixture = await createTestTenantFixture({
      displayName: "CredTrail University",
    });
    const orgTree = await seedLedgerOrgTree(fixture.db, fixture.tenantId);
    const badgeTemplateId = await seedBadgeTemplate(fixture.db, {
      tenantId: fixture.tenantId,
      title: "Foundations of Microbiology",
    });
    const idPrefix = uniqueTestId("assertion_bulk");
    const publicPrefix = uniqueTestId("public_bulk");
    const vcPrefix = `tenants/${fixture.tenantId}/assertions/${idPrefix}`;
    const idempotencyPrefix = uniqueTestId("idem_bulk");
    const nowIso = new Date().toISOString();
    const template = await findBadgeTemplateById(fixture.db, fixture.tenantId, badgeTemplateId);

    if (template === null) {
      throw new Error("Expected seeded badge template");
    }

    const achievementSnapshotJson = JSON.stringify({
      badgeTemplateId: template.id,
      title: template.title,
      description: template.description,
      criteriaUri: template.criteriaUri,
      imageUri: template.imageUri,
      trustedCredentialMetadataJson: template.trustedCredentialMetadataJson,
    });

    try {
      await fixture.db
        .prepare(
          `
          INSERT INTO assertions (
            id,
            tenant_id,
            public_id,
            learner_profile_id,
            badge_template_id,
            achievement_snapshot_json,
            recipient_identity,
            recipient_identity_type,
            vc_r2_key,
            status_list_index,
            idempotency_key,
            issued_at,
            issued_by_user_id,
            revoked_at,
            created_at,
            updated_at
          )
          SELECT
            ? || series.value::text,
            ?,
            ? || series.value::text,
            NULL,
            ?,
            ?,
            'learner.' || series.value::text || '@example.edu',
            'email',
            ? || series.value::text || '.jsonld',
            series.value,
            ? || series.value::text,
            '2026-03-10T15:00:00.000Z',
            NULL,
            NULL,
            ?,
            ?
          FROM generate_series(1, ?) AS series(value)
        `,
        )
        .bind(
          idPrefix,
          fixture.tenantId,
          publicPrefix,
          badgeTemplateId,
          achievementSnapshotJson,
          vcPrefix,
          idempotencyPrefix,
          nowIso,
          nowIso,
          SYNCHRONOUS_EXPORT_ROW_LIMIT + 1,
        )
        .run();

      await fixture.db
        .prepare(
          `
          INSERT INTO assertion_reporting_attributions (
            assertion_id,
            tenant_id,
            badge_template_id,
            org_unit_id,
            attribution_source,
            attributed_at,
            created_at,
            updated_at
          )
          SELECT
            ? || series.value::text,
            ?,
            ?,
            ?,
            'historical_backfill',
            '2026-03-10T15:00:00.000Z',
            ?,
            ?
          FROM generate_series(1, ?) AS series(value)
        `,
        )
        .bind(
          idPrefix,
          fixture.tenantId,
          badgeTemplateId,
          orgTree.microbiologyProgramId,
          nowIso,
          nowIso,
          SYNCHRONOUS_EXPORT_ROW_LIMIT + 1,
        )
        .run();

      const result = await listTenantAssertionLedgerExportRows(fixture.db, {
        tenantId: fixture.tenantId,
      });

      expect(result).toEqual({
        status: "too_large",
        rowLimit: SYNCHRONOUS_EXPORT_ROW_LIMIT,
      });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });
});
