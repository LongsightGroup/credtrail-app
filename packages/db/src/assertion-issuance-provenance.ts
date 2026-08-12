import {
  assertionIssuanceProvenanceInputSchema,
  type AssertionIssuanceProvenanceInput,
} from "@credtrail/validation";
import type { SqlDatabase, SqlRunResult } from "./tenant-scope";

export type AssertionIssuanceProvenanceSource = AssertionIssuanceProvenanceInput["source"];

interface AssertionIssuanceProvenanceRecordBase {
  readonly assertionId: string;
  readonly tenantId: string;
  readonly createdAt: string;
}

export type AssertionIssuanceProvenanceRecord = AssertionIssuanceProvenanceRecordBase &
  (
    | {
        readonly source: "manual" | "programmatic";
        readonly ruleId: null;
        readonly versionId: null;
        readonly provenanceJson: null;
      }
    | {
        readonly source: "lti_roster" | "rule_evaluate";
        readonly ruleId: string;
        readonly versionId: string;
        readonly provenanceJson: string;
      }
  );

export type CreateAssertionIssuanceProvenanceInput = {
  readonly assertionId: string;
  readonly tenantId: string;
} & AssertionIssuanceProvenanceInput;

interface AssertionIssuanceProvenanceRow {
  assertionId: string;
  tenantId: string;
  source: string;
  ruleId: string | null;
  versionId: string | null;
  provenanceJson: string | null;
  createdAt: string;
}

const mapAssertionIssuanceProvenanceRow = (
  row: AssertionIssuanceProvenanceRow,
): AssertionIssuanceProvenanceRecord => {
  const parsed = assertionIssuanceProvenanceInputSchema.parse({
    source: row.source,
    ...(row.ruleId === null ? {} : { ruleId: row.ruleId }),
    ...(row.versionId === null ? {} : { versionId: row.versionId }),
    ...(row.provenanceJson === null ? {} : { provenanceJson: row.provenanceJson }),
  });

  if (parsed.source === "manual" || parsed.source === "programmatic") {
    return {
      assertionId: row.assertionId,
      tenantId: row.tenantId,
      createdAt: row.createdAt,
      source: parsed.source,
      ruleId: null,
      versionId: null,
      provenanceJson: null,
    };
  }

  return {
    assertionId: row.assertionId,
    tenantId: row.tenantId,
    createdAt: row.createdAt,
    source: parsed.source,
    ruleId: parsed.ruleId,
    versionId: parsed.versionId,
    provenanceJson: parsed.provenanceJson,
  };
};

export const createAssertionIssuanceProvenance = async (
  db: SqlDatabase,
  input: CreateAssertionIssuanceProvenanceInput,
): Promise<AssertionIssuanceProvenanceRecord> => {
  const createdAt = new Date().toISOString();
  const ruleBacked = input.source === "lti_roster" || input.source === "rule_evaluate";
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
        ruleBacked ? input.ruleId : null,
        ruleBacked ? input.versionId : null,
        ruleBacked ? input.provenanceJson : null,
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
