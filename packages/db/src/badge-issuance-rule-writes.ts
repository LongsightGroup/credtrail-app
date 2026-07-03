import { createPrefixedId } from "./shared-helpers";
import { runSqlTransaction, type SqlDatabase, type SqlRunResult } from "./tenant-scope";
import { findBadgeTemplateById } from "./badge-templates.js";
import type {
  CreateBadgeIssuanceRuleInput,
  CreateBadgeIssuanceRuleResult,
  CreateBadgeIssuanceRuleVersionInput,
  DeleteDraftBadgeIssuanceRuleResult,
  UpdateBadgeIssuanceRuleDraftInput,
  UpdateBadgeIssuanceRuleDraftResult,
  BadgeIssuanceRuleVersionRecord,
} from "./badge-issuance-rule-types.js";
import {
  canDeleteBadgeIssuanceRuleDraft,
  canEditBadgeIssuanceRuleDraft,
  findBadgeIssuanceRuleById,
  findBadgeIssuanceRuleVersionById,
  listBadgeIssuanceRuleVersions,
  type BadgeIssuanceRuleVersionNumberRow,
} from "./badge-issuance-rule-reads.js";

export const createBadgeIssuanceRuleWithConnection = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleInput,
): Promise<CreateBadgeIssuanceRuleResult> => {
  const nowIso = new Date().toISOString();
  const ruleId = createPrefixedId("brl");
  const versionId = createPrefixedId("brv");
  const badgeTemplate = await findBadgeTemplateById(db, input.tenantId, input.badgeTemplateId);

  if (badgeTemplate === null) {
    throw new Error(
      `Badge template "${input.badgeTemplateId}" not found for tenant "${input.tenantId}"`,
    );
  }

  const insertRuleStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO badge_issuance_rules (
          id,
          tenant_id,
          name,
          description,
          badge_template_id,
          owner_org_unit_id,
          lms_provider_kind,
          lms_connection_id,
          active_version_id,
          created_by_user_id,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
      `,
      )
      .bind(
        ruleId,
        input.tenantId,
        input.name,
        input.description ?? null,
        input.badgeTemplateId,
        badgeTemplate.ownerOrgUnitId,
        input.lmsProviderKind,
        input.lmsConnectionId,
        input.createdByUserId ?? null,
        nowIso,
        nowIso,
      )
      .run();
  const insertVersionStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO badge_issuance_rule_versions (
          id,
          tenant_id,
          rule_id,
          version_number,
          status,
          rule_json,
          change_summary,
          created_by_user_id,
          approved_by_user_id,
          approved_at,
          activated_by_user_id,
          activated_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, 1, 'draft', ?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)
      `,
      )
      .bind(
        versionId,
        input.tenantId,
        ruleId,
        input.ruleJson,
        input.changeSummary ?? null,
        input.createdByUserId ?? null,
        nowIso,
        nowIso,
      )
      .run();

  await insertRuleStatement();
  await insertVersionStatement();

  const rule = await findBadgeIssuanceRuleById(db, input.tenantId, ruleId);
  const version = await findBadgeIssuanceRuleVersionById(db, {
    tenantId: input.tenantId,
    ruleId,
    versionId,
  });

  if (rule === null || version === null) {
    throw new Error(`Unable to create badge issuance rule "${ruleId}"`);
  }

  return {
    rule,
    version,
  };
};

export const createBadgeIssuanceRule = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleInput,
): Promise<CreateBadgeIssuanceRuleResult> => {
  return runSqlTransaction(db, async (transactionDb) =>
    createBadgeIssuanceRuleWithConnection(transactionDb, input),
  );
};

const createBadgeIssuanceRuleVersionInDatabase = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleVersionInput,
): Promise<BadgeIssuanceRuleVersionRecord> => {
  const nowIso = new Date().toISOString();
  const versionId = createPrefixedId("brv");
  const nextVersionStatement = (): Promise<BadgeIssuanceRuleVersionNumberRow | null> =>
    db
      .prepare(
        `
        SELECT MAX(version_number) AS maxVersionNumber
        FROM badge_issuance_rule_versions
        WHERE tenant_id = ?
          AND rule_id = ?
      `,
      )
      .bind(input.tenantId, input.ruleId)
      .first<BadgeIssuanceRuleVersionNumberRow>();
  const insertStatement = (versionNumber: number): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO badge_issuance_rule_versions (
          id,
          tenant_id,
          rule_id,
          version_number,
          status,
          rule_json,
          change_summary,
          created_by_user_id,
          approved_by_user_id,
          approved_at,
          activated_by_user_id,
          activated_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, 'draft', ?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)
      `,
      )
      .bind(
        versionId,
        input.tenantId,
        input.ruleId,
        versionNumber,
        input.ruleJson,
        input.changeSummary ?? null,
        input.createdByUserId ?? null,
        nowIso,
        nowIso,
      )
      .run();

  const maxRow = await nextVersionStatement();

  const currentMax =
    maxRow?.maxVersionNumber === null || maxRow?.maxVersionNumber === undefined
      ? 0
      : Number(maxRow.maxVersionNumber);
  const nextVersionNumber = Number.isFinite(currentMax) ? Math.floor(currentMax) + 1 : 1;
  await insertStatement(nextVersionNumber);

  const version = await findBadgeIssuanceRuleVersionById(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId,
  });

  if (version === null) {
    throw new Error(
      `Unable to create badge issuance rule version for rule "${input.ruleId}" in tenant "${input.tenantId}"`,
    );
  }

  return version;
};

export const createBadgeIssuanceRuleVersion = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleVersionInput,
): Promise<BadgeIssuanceRuleVersionRecord> => {
  return runSqlTransaction(db, async (transactionDb) =>
    createBadgeIssuanceRuleVersionInDatabase(transactionDb, input),
  );
};

export const updateBadgeIssuanceRuleDraft = async (
  db: SqlDatabase,
  input: UpdateBadgeIssuanceRuleDraftInput,
): Promise<UpdateBadgeIssuanceRuleDraftResult> => {
  const existingRule = await findBadgeIssuanceRuleById(db, input.tenantId, input.ruleId);

  if (existingRule === null) {
    return { status: "not_found" };
  }

  const versions = await listBadgeIssuanceRuleVersions(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
  });

  if (!canEditBadgeIssuanceRuleDraft(existingRule, versions)) {
    return {
      status: "not_editable",
      rule: existingRule,
      versions,
    };
  }

  const nowIso = new Date().toISOString();
  const badgeTemplate = await findBadgeTemplateById(db, input.tenantId, input.badgeTemplateId);

  if (badgeTemplate === null) {
    throw new Error(
      `Badge template "${input.badgeTemplateId}" not found for tenant "${input.tenantId}"`,
    );
  }

  // Product decision: editing from the builder preserves history by appending a new draft version.
  return runSqlTransaction(db, async (transactionDb) => {
    const updateRuleStatement = (): Promise<SqlRunResult> =>
      transactionDb
        .prepare(
          `
          UPDATE badge_issuance_rules
          SET
            name = ?,
            description = ?,
            badge_template_id = ?,
            owner_org_unit_id = ?,
            lms_provider_kind = ?,
            lms_connection_id = ?,
            updated_at = ?
          WHERE tenant_id = ?
            AND id = ?
        `,
        )
        .bind(
          input.name,
          input.description ?? null,
          input.badgeTemplateId,
          badgeTemplate.ownerOrgUnitId,
          input.lmsProviderKind,
          input.lmsConnectionId,
          nowIso,
          input.tenantId,
          input.ruleId,
        )
        .run();

    await updateRuleStatement();

    const version = await createBadgeIssuanceRuleVersionInDatabase(transactionDb, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      ruleJson: input.ruleJson,
      changeSummary: input.changeSummary,
      createdByUserId: input.createdByUserId,
    });
    const rule = await findBadgeIssuanceRuleById(transactionDb, input.tenantId, input.ruleId);

    if (rule === null) {
      throw new Error(`Unable to update badge issuance rule "${input.ruleId}"`);
    }

    return {
      status: "updated",
      rule,
      version,
    };
  });
};

export const deleteDraftBadgeIssuanceRule = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    ruleId: string;
  },
): Promise<DeleteDraftBadgeIssuanceRuleResult> => {
  const existingRule = await findBadgeIssuanceRuleById(db, input.tenantId, input.ruleId);

  if (existingRule === null) {
    return { status: "not_found" };
  }

  const versions = await listBadgeIssuanceRuleVersions(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
  });

  if (!canDeleteBadgeIssuanceRuleDraft(existingRule, versions)) {
    return {
      status: "not_deletable",
      rule: existingRule,
      versions,
    };
  }

  await db
    .prepare(
      `
      DELETE FROM badge_issuance_rules
      WHERE tenant_id = ?
        AND id = ?
    `,
    )
    .bind(input.tenantId, input.ruleId)
    .run();

  return {
    status: "deleted",
    rule: existingRule,
    versions,
  };
};
