import type { SqlDatabase, SqlRunResult } from "./tenant-scope";

export type AssertionIssuanceProvenanceSource =
  | "lti_roster"
  | "rule_evaluate"
  | "manual"
  | "programmatic";

export interface AssertionIssuanceProvenanceRecord {
  assertionId: string;
  tenantId: string;
  source: AssertionIssuanceProvenanceSource;
  ruleId: string | null;
  versionId: string | null;
  provenanceJson: string | null;
  createdAt: string;
}

export interface CreateAssertionIssuanceProvenanceInput {
  assertionId: string;
  tenantId: string;
  source: AssertionIssuanceProvenanceSource;
  ruleId?: string | undefined;
  versionId?: string | undefined;
  provenanceJson?: string | undefined;
}

interface AssertionIssuanceProvenanceRow {
  assertionId: string;
  tenantId: string;
  source: AssertionIssuanceProvenanceSource;
  ruleId: string | null;
  versionId: string | null;
  provenanceJson: string | null;
  createdAt: string;
}

const mapAssertionIssuanceProvenanceRow = (
  row: AssertionIssuanceProvenanceRow,
): AssertionIssuanceProvenanceRecord => {
  return {
    assertionId: row.assertionId,
    tenantId: row.tenantId,
    source: row.source,
    ruleId: row.ruleId,
    versionId: row.versionId,
    provenanceJson: row.provenanceJson,
    createdAt: row.createdAt,
  };
};

export const createAssertionIssuanceProvenance = async (
  db: SqlDatabase,
  input: CreateAssertionIssuanceProvenanceInput,
): Promise<AssertionIssuanceProvenanceRecord> => {
  const createdAt = new Date().toISOString();
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO assertion_issuance_provenance (
          assertion_id,
          tenant_id,
          source,
          rule_id,
          version_id,
          provenance_json,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        input.assertionId,
        input.tenantId,
        input.source,
        input.ruleId ?? null,
        input.versionId ?? null,
        input.provenanceJson ?? null,
        createdAt,
      )
      .run();

  await insertStatement();

  const record = await findAssertionIssuanceProvenanceByAssertionId(db, {
    tenantId: input.tenantId,
    assertionId: input.assertionId,
  });

  if (record === null) {
    throw new Error(
      `Unable to load assertion issuance provenance for assertion "${input.assertionId}"`,
    );
  }

  return record;
};

export const findAssertionIssuanceProvenanceByAssertionId = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    assertionId: string;
  },
): Promise<AssertionIssuanceProvenanceRecord | null> => {
  const lookupStatement = (): Promise<AssertionIssuanceProvenanceRow | null> =>
    db
      .prepare(
        `
        SELECT
          assertion_id AS assertionId,
          tenant_id AS tenantId,
          source,
          rule_id AS ruleId,
          version_id AS versionId,
          provenance_json AS provenanceJson,
          created_at AS createdAt
        FROM assertion_issuance_provenance
        WHERE tenant_id = ?
          AND assertion_id = ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, input.assertionId)
      .first<AssertionIssuanceProvenanceRow>();

  const row = await lookupStatement();

  return row === null ? null : mapAssertionIssuanceProvenanceRow(row);
};
