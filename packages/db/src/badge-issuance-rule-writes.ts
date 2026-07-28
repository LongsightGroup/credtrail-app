import { createPrefixedId } from "./shared-helpers";
import { runSqlTransaction, type SqlDatabase, type SqlRunResult } from "./tenant-scope";
import { resolveActiveRuleOrgUnit } from "./badge-issuance-rule-org-units.js";
import { findBadgeTemplateById } from "./badge-templates.js";
import {
  badgeIssuanceRuleIdentityForBuilderDraft,
  type BadgeIssuanceRuleIdentity,
} from "./badge-issuance-rule-builder-identity.js";
import type {
  CreateBadgeIssuanceRuleInput,
  CreateBadgeIssuanceRuleResult,
  CreateBadgeIssuanceRuleVersionInput,
  DeleteDraftBadgeIssuanceRuleResult,
  PromoteBadgeIssuanceRuleBuilderDraftResult,
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
import { takeBadgeIssuanceRuleBuilderDraftForPromotion } from "./badge-issuance-rule-builder-drafts.js";

const createBadgeIssuanceRuleWithIdentity = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleInput,
  identity: BadgeIssuanceRuleIdentity,
): Promise<CreateBadgeIssuanceRuleResult> => {
  const nowIso = new Date().toISOString();
  const { ruleId, versionId } = identity;
  const badgeTemplate = await findBadgeTemplateById(db, input.tenantId, input.badgeTemplateId);

  if (badgeTemplate === null) {
    throw new Error(
      `Badge template "${input.badgeTemplateId}" not found for tenant "${input.tenantId}"`,
    );
  }

  const ruleOrgUnitId = input.orgUnitId ?? badgeTemplate.ownerOrgUnitId;
  await resolveActiveRuleOrgUnit(db, {
    tenantId: input.tenantId,
    orgUnitId: ruleOrgUnitId,
  });

  // Snapshot the template ownership scope separately from the rule's canonical governance scope.
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
          org_unit_id,
          owner_org_unit_id,
          lms_provider_kind,
          lms_connection_id,
          active_version_id,
          created_by_user_id,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
      `,
      )
      .bind(
        ruleId,
        input.tenantId,
        input.name,
        input.description ?? null,
        input.badgeTemplateId,
        ruleOrgUnitId,
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

/** Creates a badge rule with fresh server-owned resource identities. */
export const createBadgeIssuanceRuleWithConnection = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleInput,
): Promise<CreateBadgeIssuanceRuleResult> => {
  return createBadgeIssuanceRuleWithIdentity(db, input, {
    ruleId: createPrefixedId("brl"),
    versionId: createPrefixedId("brv"),
  });
};

/** Creates a badge rule and its first draft version atomically. */
export const createBadgeIssuanceRule = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleInput,
): Promise<CreateBadgeIssuanceRuleResult> => {
  return runSqlTransaction(db, async (transactionDb) =>
    createBadgeIssuanceRuleWithConnection(transactionDb, input),
  );
};

/** Promotes one builder identity using the caller's existing SQL transaction. */
export const createBadgeIssuanceRuleFromBuilderDraftWithinTransaction = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleInput & {
    readonly builderDraftId: string;
    readonly builderUserId: string;
  },
): Promise<PromoteBadgeIssuanceRuleBuilderDraftResult> => {
  const identity = await badgeIssuanceRuleIdentityForBuilderDraft(
    input.tenantId,
    input.builderDraftId,
  );
  await db
    .prepare("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))")
    .bind(`${input.tenantId}:${input.builderDraftId}`)
    .run();

  const existingRule = await findBadgeIssuanceRuleById(db, input.tenantId, identity.ruleId);

  if (existingRule !== null) {
    if (existingRule.createdByUserId !== input.builderUserId) {
      return {
        status: "unavailable",
      };
    }

    const existingVersion = await findBadgeIssuanceRuleVersionById(db, {
      tenantId: input.tenantId,
      ruleId: identity.ruleId,
      versionId: identity.versionId,
    });

    if (existingVersion === null) {
      throw new Error(`Promoted badge rule "${identity.ruleId}" has no initial version`);
    }

    return {
      status: "replayed",
      draft: {
        rule: existingRule,
        version: existingVersion,
      },
    };
  }

  const draftAvailability = await takeBadgeIssuanceRuleBuilderDraftForPromotion(db, {
    tenantId: input.tenantId,
    userId: input.builderUserId,
    draftId: input.builderDraftId,
  });

  if (draftAvailability === "unavailable") {
    return {
      status: "unavailable",
    };
  }

  return {
    status: "created",
    draft: await createBadgeIssuanceRuleWithIdentity(db, input, identity),
  };
};

/** Idempotently promotes one builder identity into a formal rule. */
export const createBadgeIssuanceRuleFromBuilderDraft = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleInput & {
    readonly builderDraftId: string;
    readonly builderUserId: string;
  },
): Promise<PromoteBadgeIssuanceRuleBuilderDraftResult> => {
  return runSqlTransaction(db, (transactionDb) =>
    createBadgeIssuanceRuleFromBuilderDraftWithinTransaction(transactionDb, input),
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

/** Updates a rule draft using the caller's existing SQL transaction. */
export const updateBadgeIssuanceRuleDraftWithinTransaction = async (
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

  const ruleOrgUnitId = input.orgUnitId ?? existingRule.orgUnitId;
  await resolveActiveRuleOrgUnit(db, {
    tenantId: input.tenantId,
    orgUnitId: ruleOrgUnitId,
  });

  // Product decision: editing from the builder preserves history by appending a new draft version.
  // Draft edits refresh template ownership metadata; rule scope is preserved unless explicitly changed.
  const updateRuleStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
          UPDATE badge_issuance_rules
          SET
            name = ?,
            description = ?,
            badge_template_id = ?,
            org_unit_id = ?,
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
        ruleOrgUnitId,
        badgeTemplate.ownerOrgUnitId,
        input.lmsProviderKind,
        input.lmsConnectionId,
        nowIso,
        input.tenantId,
        input.ruleId,
      )
      .run();

  await updateRuleStatement();

  const version = await createBadgeIssuanceRuleVersionInDatabase(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    ruleJson: input.ruleJson,
    changeSummary: input.changeSummary,
    createdByUserId: input.createdByUserId,
  });
  const rule = await findBadgeIssuanceRuleById(db, input.tenantId, input.ruleId);

  if (rule === null) {
    throw new Error(`Unable to update badge issuance rule "${input.ruleId}"`);
  }

  return {
    status: "updated",
    rule,
    version,
  };
};

export const updateBadgeIssuanceRuleDraft = async (
  db: SqlDatabase,
  input: UpdateBadgeIssuanceRuleDraftInput,
): Promise<UpdateBadgeIssuanceRuleDraftResult> => {
  return runSqlTransaction(db, (transactionDb) =>
    updateBadgeIssuanceRuleDraftWithinTransaction(transactionDb, input),
  );
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
