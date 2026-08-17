import type { SqlDatabase, SqlRunResult } from "./tenant-scope";
import type {
  AssertionReportingAttributionRecord,
  AssertionReportingAttributionSource,
} from "./assertion-types.js";
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
