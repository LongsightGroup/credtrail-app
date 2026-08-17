import { findBadgeTemplateById } from "./badge-templates";
import { serializeAssertionAchievementSnapshot } from "./assertion-achievement-snapshot.js";
import {
  insertAssertionRecipientIdentifiers,
  uniqueRecipientIdentifiers,
} from "./assertion-recipient-identifiers";
import { runSqlTransaction, type SqlDatabase } from "./tenant-scope";
import type {
  AssertionRecord,
  AssertionStatusListEntryRecord,
  CreateAssertionInput,
  RecordAssertionRevocationInput,
  RecordAssertionRevocationResult,
} from "./assertion-types.js";
import { upsertAssertionReportingAttribution } from "./assertion-reporting-attribution.js";
import { findAssertionById } from "./assertion-reads.js";
import { enqueueLearnerEvidenceChange } from "./learner-evidence-change-jobs.js";

export const createAssertion = async (
  db: SqlDatabase,
  input: CreateAssertionInput,
): Promise<AssertionRecord> => {
  const nowIso = new Date().toISOString();
  const assertionPublicId = input.publicId ?? crypto.randomUUID();
  const recipientIdentifiers = uniqueRecipientIdentifiers(input.recipientIdentifiers ?? []);
  const badgeTemplateId = input.achievementSnapshot.badgeTemplateId;

  await db
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
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
    )
    .bind(
      input.id,
      input.tenantId,
      assertionPublicId,
      input.learnerProfileId ?? null,
      badgeTemplateId,
      serializeAssertionAchievementSnapshot(input.achievementSnapshot),
      input.recipientIdentity,
      input.recipientIdentityType,
      input.vcR2Key,
      input.statusListIndex,
      input.idempotencyKey,
      input.issuedAt,
      input.issuedByUserId ?? null,
      nowIso,
      nowIso,
    )
    .run();

  await insertAssertionRecipientIdentifiers(db, input.id, recipientIdentifiers);
  const badgeTemplate = await findBadgeTemplateById(db, input.tenantId, badgeTemplateId);

  if (badgeTemplate === null) {
    throw new Error(`Badge template ${badgeTemplateId} not found for tenant ${input.tenantId}`);
  }

  await upsertAssertionReportingAttribution(db, {
    assertionId: input.id,
    tenantId: input.tenantId,
    badgeTemplateId,
    orgUnitId: badgeTemplate.ownerOrgUnitId,
    attributionSource: "issuance_snapshot",
    attributedAt: input.issuedAt,
  });

  return {
    id: input.id,
    tenantId: input.tenantId,
    publicId: assertionPublicId,
    learnerProfileId: input.learnerProfileId ?? null,
    badgeTemplateId,
    achievementSnapshot: input.achievementSnapshot,
    achievementSnapshotStatus: "captured",
    recipientIdentity: input.recipientIdentity,
    recipientIdentityType: input.recipientIdentityType,
    vcR2Key: input.vcR2Key,
    statusListIndex: input.statusListIndex,
    idempotencyKey: input.idempotencyKey,
    issuedAt: input.issuedAt,
    issuedByUserId: input.issuedByUserId ?? null,
    revokedAt: null,
    createdAt: nowIso,
    updatedAt: nowIso,
  };
};

/** Atomically reserves one status-list index that will never be issued again for this tenant. */
export const reserveAssertionStatusListIndex = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<number> => {
  const row = await db
    .prepare(
      `
      INSERT INTO assertion_status_list_counters AS counters (
        tenant_id,
        next_index
      )
      VALUES (?, 1)
      ON CONFLICT (tenant_id) DO UPDATE
      SET next_index = counters.next_index + 1
      RETURNING next_index - 1 AS statusListIndex
    `,
    )
    .bind(tenantId)
    .first<{ statusListIndex: number }>();

  if (row === null) {
    throw new Error(`Unable to reserve status list index for tenant "${tenantId}"`);
  }

  return row.statusListIndex;
};

export const listAssertionStatusListEntries = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<AssertionStatusListEntryRecord[]> => {
  const result = await db
    .prepare(
      `
      SELECT
        status_list_index AS statusListIndex,
        revoked_at AS revokedAt
      FROM assertions
      WHERE tenant_id = ?
        AND status_list_index IS NOT NULL
      ORDER BY status_list_index ASC
    `,
    )
    .bind(tenantId)
    .all<AssertionStatusListEntryRecord>();

  return result.results;
};

export const recordAssertionRevocation = async (
  db: SqlDatabase,
  input: RecordAssertionRevocationInput,
): Promise<RecordAssertionRevocationResult> => {
  return runSqlTransaction(db, async (transaction) => {
    const lockedAssertion = await transaction
      .prepare(
        `SELECT id FROM assertions
         WHERE tenant_id = ? AND id = ?
         LIMIT 1
         FOR UPDATE`,
      )
      .bind(input.tenantId, input.assertionId)
      .first<{ id: string }>();

    if (lockedAssertion === null) {
      throw new Error(`Assertion "${input.assertionId}" not found for tenant "${input.tenantId}"`);
    }

    const assertion = await findAssertionById(transaction, input.tenantId, input.assertionId);

    if (assertion === null) {
      throw new Error(`Locked assertion "${input.assertionId}" could not be loaded`);
    }

    const effectiveRevokedAt = assertion.revokedAt ?? input.revokedAt;

    if (assertion.revokedAt === null) {
      await transaction
        .prepare(
          `
          UPDATE assertions
          SET revoked_at = ?,
              updated_at = ?
          WHERE tenant_id = ?
            AND id = ?
            AND revoked_at IS NULL
        `,
        )
        .bind(effectiveRevokedAt, input.revokedAt, input.tenantId, input.assertionId)
        .run();
    }

    await transaction
      .prepare(
        `
        INSERT INTO revocations (
          id,
          tenant_id,
          assertion_id,
          reason,
          idempotency_key,
          revoked_by_user_id,
          revoked_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT DO NOTHING
      `,
      )
      .bind(
        input.revocationId,
        input.tenantId,
        input.assertionId,
        input.reason,
        input.idempotencyKey,
        input.revokedByUserId ?? null,
        effectiveRevokedAt,
        input.revokedAt,
      )
      .run();

    if (assertion.learnerProfileId !== null && assertion.revokedAt === null) {
      await enqueueLearnerEvidenceChange(transaction, {
        tenantId: input.tenantId,
        learnerProfileId: assertion.learnerProfileId,
        trigger: "assertion_revoked",
        evidenceEventId: input.revocationId,
        requestedAt: input.revokedAt,
      });
    }

    return {
      status: assertion.revokedAt === null ? "revoked" : "already_revoked",
      revokedAt: effectiveRevokedAt,
    };
  });
};
