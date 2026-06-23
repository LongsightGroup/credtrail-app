import { listBadgeTemplateOwnershipEvents } from "./badge-templates";
import type { BadgeTemplateOwnershipEventRecord } from "./badge-templates";
import type { SqlDatabase, SqlQueryResult, SqlRunResult } from "./tenant-scope";
import type {
  AssertionReportingAttributionRecord,
  AssertionReportingAttributionSource,
} from "./assertion-types.js";
import { resolveAssertionReportingAttribution } from "./assertion-reporting-summaries.js";
import { mapAssertionReportingAttributionRow } from "./assertion-internal.js";
import type { AssertionReportingAttributionRow } from "./assertion-internal.js";

export const findAssertionReportingAttributionByAssertionId = async (
  db: SqlDatabase,
  assertionId: string,
): Promise<AssertionReportingAttributionRecord | null> => {
  const lookupStatement = (): Promise<AssertionReportingAttributionRow | null> =>
    db
      .prepare(
        `
        SELECT
          assertion_id AS assertionId,
          tenant_id AS tenantId,
          badge_template_id AS badgeTemplateId,
          org_unit_id AS orgUnitId,
          attribution_source AS attributionSource,
          attributed_at AS attributedAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM assertion_reporting_attributions
        WHERE assertion_id = ?
        LIMIT 1
      `,
      )
      .bind(assertionId)
      .first<AssertionReportingAttributionRow>();

  const row = await lookupStatement();

  return row === null ? null : mapAssertionReportingAttributionRow(row);
};

export const upsertAssertionReportingAttribution = async (
  db: SqlDatabase,
  input: {
    assertionId: string;
    tenantId: string;
    badgeTemplateId: string;
    orgUnitId: string;
    attributionSource: AssertionReportingAttributionSource;
    attributedAt: string;
  },
): Promise<AssertionReportingAttributionRecord> => {
  const nowIso = new Date().toISOString();
  const upsertStatement = (): Promise<SqlRunResult> =>
    db
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
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (assertion_id)
        DO UPDATE SET
          tenant_id = excluded.tenant_id,
          badge_template_id = excluded.badge_template_id,
          org_unit_id = excluded.org_unit_id,
          attribution_source = excluded.attribution_source,
          attributed_at = excluded.attributed_at,
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        input.assertionId,
        input.tenantId,
        input.badgeTemplateId,
        input.orgUnitId,
        input.attributionSource,
        input.attributedAt,
        nowIso,
        nowIso,
      )
      .run();

  await upsertStatement();

  const attribution = await findAssertionReportingAttributionByAssertionId(db, input.assertionId);

  if (attribution === null) {
    throw new Error(`Unable to load reporting attribution for assertion "${input.assertionId}"`);
  }

  return attribution;
};

export const backfillAssertionReportingAttributionsForTenant = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<number> => {
  type MissingAttributionRow = {
    assertionId: string;
    badgeTemplateId: string;
    currentOwnerOrgUnitId: string;
    issuedAt: string;
  };

  const missingStatement = (): Promise<SqlQueryResult<MissingAttributionRow>> =>
    db
      .prepare(
        `
        SELECT
          assertions.id AS assertionId,
          assertions.badge_template_id AS badgeTemplateId,
          badge_templates.owner_org_unit_id AS currentOwnerOrgUnitId,
          assertions.issued_at AS issuedAt
        FROM assertions
        INNER JOIN badge_templates
          ON badge_templates.tenant_id = assertions.tenant_id
          AND badge_templates.id = assertions.badge_template_id
        LEFT JOIN assertion_reporting_attributions attribution
          ON attribution.assertion_id = assertions.id
        WHERE assertions.tenant_id = ?
          AND attribution.assertion_id IS NULL
        ORDER BY assertions.issued_at ASC, assertions.id ASC
      `,
      )
      .bind(tenantId)
      .all<MissingAttributionRow>();

  const missingRows = (await missingStatement()).results;
  const ownershipEventsByTemplateId = new Map<string, BadgeTemplateOwnershipEventRecord[]>();

  for (const badgeTemplateId of new Set(missingRows.map((row) => row.badgeTemplateId))) {
    ownershipEventsByTemplateId.set(
      badgeTemplateId,
      await listBadgeTemplateOwnershipEvents(db, {
        tenantId,
        badgeTemplateId,
      }),
    );
  }

  for (const row of missingRows) {
    const attribution = resolveAssertionReportingAttribution({
      issuedAt: row.issuedAt,
      currentOwnerOrgUnitId: row.currentOwnerOrgUnitId,
      ownershipEvents: ownershipEventsByTemplateId.get(row.badgeTemplateId) ?? [],
    });

    await upsertAssertionReportingAttribution(db, {
      assertionId: row.assertionId,
      tenantId,
      badgeTemplateId: row.badgeTemplateId,
      orgUnitId: attribution.orgUnitId,
      attributionSource: attribution.attributionSource,
      attributedAt: attribution.attributedAt,
    });
  }

  return missingRows.length;
};
