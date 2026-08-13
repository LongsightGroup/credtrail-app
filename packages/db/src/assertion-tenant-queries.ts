import {
  bindLearnerProfileOrEmailAccessParams,
  buildLearnerProfileOrEmailAccessFilter,
} from "./learner-assertion-access-sql";
import { assertionAchievementSnapshotSelectSql } from "./assertion-achievement-snapshot-sql.js";
import { listLearnerIdentitiesByProfile } from "./learner-profiles";
import { listTenantOrgUnits } from "./tenant-org-units";
import { normalizeEmail } from "./users";
import type { SqlDatabase, SqlQueryResult } from "./tenant-scope";
import { SYNCHRONOUS_EXPORT_ROW_LIMIT } from "./assertion-types.js";
import type {
  LearnerRecordAssertionExportRecord,
  ListLearnerRecordAssertionExportsInput,
  ListTenantAssertionLedgerExportRowsInput,
  ListTenantAssertionsInput,
  TenantAssertionLedgerExportResult,
  TenantAssertionSummaryRecord,
} from "./assertion-types.js";
import {
  mapLearnerRecordAssertionExportRow,
  mapTenantAssertionLedgerExportRow,
  mapTenantAssertionSummaryRow,
} from "./assertion-internal.js";
import type {
  LearnerRecordAssertionExportRow,
  TenantAssertionLedgerExportRow,
  TenantAssertionSummaryRow,
} from "./assertion-internal.js";
import { backfillAssertionReportingAttributionsForTenant } from "./assertion-reporting-attribution.js";
import {
  assertionReportingAttributionJoinSql,
  buildAssertionRecordFilterSql,
} from "./assertion-record-filter-sql.js";

export const listLearnerRecordAssertionExports = async (
  db: SqlDatabase,
  input: ListLearnerRecordAssertionExportsInput,
): Promise<LearnerRecordAssertionExportRecord[]> => {
  const identities = await listLearnerIdentitiesByProfile(
    db,
    input.tenantId,
    input.learnerProfileId,
  );
  const emailAliases = Array.from(
    new Set(
      identities
        .filter((identity) => identity.identityType === "email")
        .map((identity) => normalizeEmail(identity.identityValue)),
    ),
  );
  const learnerAccessFilter = buildLearnerProfileOrEmailAccessFilter(emailAliases);
  const params: unknown[] = [
    input.tenantId,
    ...bindLearnerProfileOrEmailAccessParams(input.learnerProfileId, emailAliases),
  ];
  const result = await db
    .prepare(
      `
      SELECT
        assertions.id AS assertionId,
        assertions.public_id AS assertionPublicId,
        assertions.tenant_id AS tenantId,
        assertions.learner_profile_id AS learnerProfileId,
        assertions.badge_template_id AS badgeTemplateId,
        ${assertionAchievementSnapshotSelectSql},
        assertions.recipient_identity AS recipientIdentity,
        assertions.recipient_identity_type AS recipientIdentityType,
        assertions.vc_r2_key AS vcR2Key,
        assertions.status_list_index AS statusListIndex,
        assertions.idempotency_key AS idempotencyKey,
        assertions.issued_at AS issuedAt,
        assertions.issued_by_user_id AS issuedByUserId,
        assertions.revoked_at AS revokedAt,
        tenants.display_name AS issuerName,
        assertions.created_at AS createdAt,
        assertions.updated_at AS updatedAt
      FROM assertions
      INNER JOIN tenants
        ON tenants.id = assertions.tenant_id
      WHERE assertions.tenant_id = ?
        AND ${learnerAccessFilter}
      ORDER BY assertions.issued_at DESC, assertions.id DESC
    `,
    )
    .bind(...params)
    .all<LearnerRecordAssertionExportRow>();

  return result.results.map((row) => mapLearnerRecordAssertionExportRow(row));
};

export const listTenantAssertions = async (
  db: SqlDatabase,
  input: ListTenantAssertionsInput,
): Promise<TenantAssertionSummaryRecord[]> => {
  if (input.orgUnitId !== undefined) {
    await backfillAssertionReportingAttributionsForTenant(db, input.tenantId);
  }

  const queryLimit = Math.max(1, Math.min(input.limit ?? 100, 500));
  const { whereClauses, params } = buildAssertionRecordFilterSql(input, {
    context: "ledger",
  });

  const listStatement = (): Promise<SqlQueryResult<TenantAssertionSummaryRow>> =>
    db
      .prepare(
        `
        SELECT
          assertions.id AS assertionId,
          assertions.tenant_id AS tenantId,
          assertions.public_id AS publicId,
          assertions.badge_template_id AS badgeTemplateId,
          ${assertionAchievementSnapshotSelectSql},
          assertions.recipient_identity AS recipientIdentity,
          assertions.recipient_identity_type AS recipientIdentityType,
          assertions.issued_at AS issuedAt,
          assertions.issued_by_user_id AS issuedByUserId,
          assertions.revoked_at AS revokedAt,
          lifecycle.to_state AS latestToState,
          lifecycle.reason_code AS latestReasonCode,
          lifecycle.reason AS latestReason,
          lifecycle.transitioned_at AS latestTransitionedAt
        FROM assertions
        ${input.orgUnitId === undefined ? "" : assertionReportingAttributionJoinSql}
        LEFT JOIN assertion_lifecycle_events lifecycle
          ON lifecycle.id = (
            SELECT ale.id
            FROM assertion_lifecycle_events ale
            WHERE ale.tenant_id = assertions.tenant_id
              AND ale.assertion_id = assertions.id
            ORDER BY ale.transitioned_at DESC, ale.created_at DESC, ale.id DESC
            LIMIT 1
          )
        WHERE ${whereClauses.join("\n          AND ")}
        ORDER BY assertions.issued_at DESC, assertions.id DESC
        LIMIT ?
      `,
      )
      .bind(...params, queryLimit)
      .all<TenantAssertionSummaryRow>();

  const result = await listStatement();

  return result.results.map((row) => mapTenantAssertionSummaryRow(row));
};

export const listTenantAssertionLedgerExportRows = async (
  db: SqlDatabase,
  input: ListTenantAssertionLedgerExportRowsInput,
): Promise<TenantAssertionLedgerExportResult> => {
  await backfillAssertionReportingAttributionsForTenant(db, input.tenantId);

  const { whereClauses, params } = buildAssertionRecordFilterSql(input, {
    context: "ledger",
  });

  const rowLimit = SYNCHRONOUS_EXPORT_ROW_LIMIT;
  const listStatement = (): Promise<SqlQueryResult<TenantAssertionLedgerExportRow>> =>
    db
      .prepare(
        `
        SELECT
          assertions.id AS assertionId,
          assertions.tenant_id AS tenantId,
          assertions.public_id AS publicId,
          assertions.badge_template_id AS badgeTemplateId,
          ${assertionAchievementSnapshotSelectSql},
          assertions.recipient_identity AS recipientIdentity,
          assertions.recipient_identity_type AS recipientIdentityType,
          assertions.issued_at AS issuedAt,
          assertions.issued_by_user_id AS issuedByUserId,
          assertions.revoked_at AS revokedAt,
          lifecycle.to_state AS latestToState,
          lifecycle.reason_code AS latestReasonCode,
          lifecycle.reason AS latestReason,
          lifecycle.transitioned_at AS latestTransitionedAt,
          attribution.org_unit_id AS orgUnitId,
          COALESCE(org_units.display_name, attribution.org_unit_id) AS orgUnitDisplayName,
          attribution.attribution_source AS attributionSource
        FROM assertions
        ${assertionReportingAttributionJoinSql}
        LEFT JOIN tenant_org_units org_units
          ON org_units.tenant_id = assertions.tenant_id
          AND org_units.id = attribution.org_unit_id
        LEFT JOIN assertion_lifecycle_events lifecycle
          ON lifecycle.id = (
            SELECT ale.id
            FROM assertion_lifecycle_events ale
            WHERE ale.tenant_id = assertions.tenant_id
              AND ale.assertion_id = assertions.id
            ORDER BY ale.transitioned_at DESC, ale.created_at DESC, ale.id DESC
            LIMIT 1
          )
        WHERE ${whereClauses.join("\n          AND ")}
        ORDER BY assertions.issued_at DESC, assertions.id DESC
        LIMIT ?
      `,
      )
      .bind(...params, rowLimit + 1)
      .all<TenantAssertionLedgerExportRow>();

  const rows = (await listStatement()).results;
  const orgUnits = await listTenantOrgUnits(db, {
    tenantId: input.tenantId,
  });
  const orgUnitsById = new Map(orgUnits.map((orgUnit) => [orgUnit.id, orgUnit] as const));

  if (rows.length > rowLimit) {
    return {
      status: "too_large",
      rowLimit,
    };
  }

  return {
    status: "ok",
    rowLimit,
    rows: rows.map((row) => mapTenantAssertionLedgerExportRow(row, orgUnitsById)),
  };
};
