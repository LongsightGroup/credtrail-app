import { createPrefixedId } from "./shared-helpers";
import { runSqlTransaction, type SqlDatabase, type SqlRunResult } from "./tenant-scope";
import { resolveActiveRuleOrgUnit } from "./badge-issuance-rule-org-units.js";
import { findBadgeTemplateById, type BadgeTemplateRecord } from "./badge-templates.js";
import { assertBadgeTemplateArtworkUsesManagedReference } from "./badge-template-artwork-policy.js";
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
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
} from "./badge-issuance-rule-types.js";
import { findBadgeIssuanceRuleById } from "./badge-issuance-rule-reads.js";
import {
  canDeleteBadgeIssuanceRuleDraft,
  canEditBadgeIssuanceRuleDraft,
  findBadgeIssuanceRuleVersionById,
  listBadgeIssuanceRuleVersions,
  type BadgeIssuanceRuleVersionNumberRow,
} from "./badge-issuance-rule-version-reads.js";
import { takeBadgeIssuanceRuleBuilderDraftForPromotion } from "./badge-issuance-rule-builder-drafts.js";
import { lockBadgeIssuanceRuleForTransition } from "./badge-issuance-rule-approval-storage.js";

const createBadgeIssuanceRuleWithIdentity = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleInput,
  identity: BadgeIssuanceRuleIdentity,
  badgeTemplate: BadgeTemplateRecord,
): Promise<CreateBadgeIssuanceRuleResult> => {
  const nowIso = new Date().toISOString();
  const { ruleId, versionId } = identity;

  if (badgeTemplate.tenantId !== input.tenantId || badgeTemplate.id !== input.badgeTemplateId) {
    throw new Error(
      `Badge template "${badgeTemplate.id}" does not match rule authoring input "${input.badgeTemplateId}"`,
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
          snapshot_name,
          snapshot_description,
          snapshot_badge_template_id,
          snapshot_badge_template_title,
          snapshot_badge_template_description,
          snapshot_badge_template_criteria_uri,
          snapshot_badge_template_image_uri,
          snapshot_badge_template_trusted_credential_metadata_json,
          snapshot_org_unit_id,
          snapshot_owner_org_unit_id,
          snapshot_lms_provider_kind,
          snapshot_lms_connection_id,
          change_summary,
          created_by_user_id,
          approved_by_user_id,
          approved_at,
          activated_by_user_id,
          activated_at,
          created_at,
          updated_at
        )
        VALUES (
          ?, ?, ?, 1, 'draft', ?,
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          ?, ?, NULL, NULL, NULL, NULL, ?, ?
        )
      `,
      )
      .bind(
        versionId,
        input.tenantId,
        ruleId,
        input.ruleJson,
        input.name,
        input.description ?? null,
        input.badgeTemplateId,
        badgeTemplate.title,
        badgeTemplate.description,
        badgeTemplate.criteriaUri,
        badgeTemplate.imageUri,
        badgeTemplate.trustedCredentialMetadataJson ?? null,
        ruleOrgUnitId,
        badgeTemplate.ownerOrgUnitId,
        input.lmsProviderKind,
        input.lmsConnectionId,
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

const loadBadgeTemplateForRuleWrite = async (
  db: SqlDatabase,
  input: Pick<CreateBadgeIssuanceRuleInput, "tenantId" | "badgeTemplateId">,
): Promise<BadgeTemplateRecord> => {
  const badgeTemplate = await findBadgeTemplateById(db, input.tenantId, input.badgeTemplateId);

  if (badgeTemplate === null) {
    throw new Error(
      `Badge template "${input.badgeTemplateId}" not found for tenant "${input.tenantId}"`,
    );
  }

  assertBadgeTemplateArtworkUsesManagedReference(badgeTemplate);
  return badgeTemplate;
};

/** Writes a new rule from the template locked by the governing authoring transaction. */
export const createBadgeIssuanceRuleFromLockedTemplate = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleInput,
  badgeTemplate: BadgeTemplateRecord,
): Promise<CreateBadgeIssuanceRuleResult> => {
  return createBadgeIssuanceRuleWithIdentity(
    db,
    input,
    {
      ruleId: createPrefixedId("brl"),
      versionId: createPrefixedId("brv"),
    },
    badgeTemplate,
  );
};

/** Creates a badge rule with fresh server-owned resource identities. */
export const createBadgeIssuanceRuleWithConnection = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleInput,
): Promise<CreateBadgeIssuanceRuleResult> => {
  const badgeTemplate = await loadBadgeTemplateForRuleWrite(db, input);
  return createBadgeIssuanceRuleFromLockedTemplate(db, input, badgeTemplate);
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

type LockedBadgeIssuanceRuleBuilderPromotionResult =
  | {
      readonly status: "ready";
      readonly builderDraftId: string;
      readonly identity: BadgeIssuanceRuleIdentity;
    }
  | {
      readonly status: "replayed";
      readonly draft: CreateBadgeIssuanceRuleResult;
    }
  | {
      readonly status: "unavailable";
    };

/** Finds a completed builder promotion without requiring the original builder draft to remain. */
export const findBadgeIssuanceRuleBuilderPromotionReplay = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly builderDraftId: string;
    readonly builderUserId: string;
  },
): Promise<
  | Extract<LockedBadgeIssuanceRuleBuilderPromotionResult, { readonly status: "replayed" }>
  | Extract<LockedBadgeIssuanceRuleBuilderPromotionResult, { readonly status: "unavailable" }>
  | { readonly status: "not_promoted" }
> => {
  const identity = await badgeIssuanceRuleIdentityForBuilderDraft(
    input.tenantId,
    input.builderDraftId,
  );
  const existingRule = await findBadgeIssuanceRuleById(db, input.tenantId, identity.ruleId);

  if (existingRule === null) {
    return { status: "not_promoted" };
  }

  if (existingRule.createdByUserId !== input.builderUserId) {
    return { status: "unavailable" };
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
};

/** Locks one builder identity and resolves whether promotion is new, replayed, or unavailable. */
export const lockBadgeIssuanceRuleBuilderPromotion = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly builderDraftId: string;
    readonly builderUserId: string;
  },
): Promise<LockedBadgeIssuanceRuleBuilderPromotionResult> => {
  const identity = await badgeIssuanceRuleIdentityForBuilderDraft(
    input.tenantId,
    input.builderDraftId,
  );
  await db
    .prepare("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))")
    .bind(`${input.tenantId}:${input.builderDraftId}`)
    .run();

  const replay = await findBadgeIssuanceRuleBuilderPromotionReplay(db, input);

  if (replay.status !== "not_promoted") {
    return replay;
  }

  const existingDraft = await db
    .prepare(
      `
      SELECT
        user_id AS userId,
        rule_id AS ruleId
      FROM badge_issuance_rule_builder_drafts
      WHERE tenant_id = ?
        AND id = ?
      LIMIT 1
    `,
    )
    .bind(input.tenantId, input.builderDraftId)
    .first<{ userId: string; ruleId: string | null }>();

  if (
    existingDraft !== null &&
    (existingDraft.userId !== input.builderUserId || existingDraft.ruleId !== null)
  ) {
    return { status: "unavailable" };
  }

  return {
    status: "ready",
    builderDraftId: input.builderDraftId,
    identity,
  };
};

/** Consumes a locked builder promotion after all pre-write policy checks have passed. */
export const createBadgeIssuanceRuleFromLockedBuilderPromotion = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleInput & {
    readonly builderDraftId: string;
    readonly builderUserId: string;
    readonly identity: BadgeIssuanceRuleIdentity;
    readonly badgeTemplate: BadgeTemplateRecord;
  },
): Promise<
  | {
      readonly status: "created";
      readonly draft: CreateBadgeIssuanceRuleResult;
    }
  | {
      readonly status: "unavailable";
    }
> => {
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
    draft: await createBadgeIssuanceRuleWithIdentity(
      db,
      input,
      input.identity,
      input.badgeTemplate,
    ),
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
  return runSqlTransaction(db, async (transactionDb) => {
    const promotion = await lockBadgeIssuanceRuleBuilderPromotion(transactionDb, input);

    if (promotion.status !== "ready") {
      return promotion;
    }

    const badgeTemplate = await loadBadgeTemplateForRuleWrite(transactionDb, input);

    return createBadgeIssuanceRuleFromLockedBuilderPromotion(transactionDb, {
      ...input,
      identity: promotion.identity,
      badgeTemplate,
    });
  });
};

const createBadgeIssuanceRuleVersionInDatabase = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleVersionInput,
): Promise<BadgeIssuanceRuleVersionRecord> => {
  const nowIso = new Date().toISOString();
  const versionId = createPrefixedId("brv");
  const rule = await findBadgeIssuanceRuleById(db, input.tenantId, input.ruleId);

  if (rule === null) {
    throw new Error(
      `Badge issuance rule "${input.ruleId}" not found for tenant "${input.tenantId}"`,
    );
  }

  const badgeTemplate = await findBadgeTemplateById(db, input.tenantId, rule.badgeTemplateId);

  if (badgeTemplate === null) {
    throw new Error(
      `Badge template "${rule.badgeTemplateId}" not found for tenant "${input.tenantId}"`,
    );
  }

  assertBadgeTemplateArtworkUsesManagedReference(badgeTemplate);
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
          snapshot_name,
          snapshot_description,
          snapshot_badge_template_id,
          snapshot_badge_template_title,
          snapshot_badge_template_description,
          snapshot_badge_template_criteria_uri,
          snapshot_badge_template_image_uri,
          snapshot_badge_template_trusted_credential_metadata_json,
          snapshot_org_unit_id,
          snapshot_owner_org_unit_id,
          snapshot_lms_provider_kind,
          snapshot_lms_connection_id,
          change_summary,
          created_by_user_id,
          approved_by_user_id,
          approved_at,
          activated_by_user_id,
          activated_at,
          created_at,
          updated_at
        )
        SELECT
          ?,
          rules.tenant_id,
          rules.id,
          ?,
          'draft',
          ?,
          rules.name,
          rules.description,
          rules.badge_template_id,
          templates.title,
          templates.description,
          templates.criteria_uri,
          templates.image_uri,
          templates.trusted_credential_metadata_json,
          rules.org_unit_id,
          rules.owner_org_unit_id,
          rules.lms_provider_kind,
          rules.lms_connection_id,
          ?,
          ?,
          NULL,
          NULL,
          NULL,
          NULL,
          ?,
          ?
        FROM badge_issuance_rules AS rules
        INNER JOIN badge_templates AS templates
          ON templates.id = rules.badge_template_id
          AND templates.tenant_id = rules.tenant_id
        WHERE rules.tenant_id = ?
          AND rules.id = ?
      `,
      )
      .bind(
        versionId,
        versionNumber,
        input.ruleJson,
        input.changeSummary ?? null,
        input.createdByUserId ?? null,
        nowIso,
        nowIso,
        input.tenantId,
        input.ruleId,
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

type LockedBadgeIssuanceRuleDraftUpdateResult =
  | {
      readonly status: "ready";
      readonly rule: BadgeIssuanceRuleRecord;
    }
  | Extract<UpdateBadgeIssuanceRuleDraftResult, { readonly status: "not_found" | "not_editable" }>;

/** Locks and validates a rule before an authoring transaction writes a new draft version. */
export const lockBadgeIssuanceRuleDraftUpdate = async (
  db: SqlDatabase,
  input: Pick<UpdateBadgeIssuanceRuleDraftInput, "tenantId" | "ruleId">,
): Promise<LockedBadgeIssuanceRuleDraftUpdateResult> => {
  const locked = await db
    .prepare(
      `
      SELECT id
      FROM badge_issuance_rules
      WHERE tenant_id = ?
        AND id = ?
      FOR UPDATE
    `,
    )
    .bind(input.tenantId, input.ruleId)
    .first<{ id: string }>();

  if (locked === null) {
    return { status: "not_found" };
  }

  const existingRule = await findBadgeIssuanceRuleById(db, input.tenantId, input.ruleId);

  if (existingRule === null) {
    throw new Error(`Locked badge issuance rule "${input.ruleId}" could not be reloaded`);
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

  return {
    status: "ready",
    rule: existingRule,
  };
};

/** Applies a draft update after the same transaction has locked and validated the rule. */
export const updateLockedBadgeIssuanceRuleDraft = async (
  db: SqlDatabase,
  input: UpdateBadgeIssuanceRuleDraftInput & {
    readonly existingRule: BadgeIssuanceRuleRecord;
    readonly badgeTemplate: BadgeTemplateRecord;
  },
): Promise<Extract<UpdateBadgeIssuanceRuleDraftResult, { readonly status: "updated" }>> => {
  const nowIso = new Date().toISOString();

  if (
    input.badgeTemplate.tenantId !== input.tenantId ||
    input.badgeTemplate.id !== input.badgeTemplateId
  ) {
    throw new Error(
      `Badge template "${input.badgeTemplate.id}" does not match rule authoring input "${input.badgeTemplateId}"`,
    );
  }

  const ruleOrgUnitId = input.orgUnitId ?? input.existingRule.orgUnitId;
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
        input.badgeTemplate.ownerOrgUnitId,
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
  return runSqlTransaction(db, async (transactionDb) => {
    const locked = await lockBadgeIssuanceRuleDraftUpdate(transactionDb, input);

    if (locked.status !== "ready") {
      return locked;
    }

    const badgeTemplate = await loadBadgeTemplateForRuleWrite(transactionDb, input);

    return updateLockedBadgeIssuanceRuleDraft(transactionDb, {
      ...input,
      existingRule: locked.rule,
      badgeTemplate,
    });
  });
};

/** Atomically deletes an incomplete or never-active draft/rejected rule. */
export const deleteDraftBadgeIssuanceRule = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    ruleId: string;
  },
): Promise<DeleteDraftBadgeIssuanceRuleResult> => {
  return runSqlTransaction(db, async (transactionDb) => {
    const existingRule = await lockBadgeIssuanceRuleForTransition(transactionDb, input);

    if (existingRule === null) {
      return { status: "not_found" };
    }

    const versions = await listBadgeIssuanceRuleVersions(transactionDb, {
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

    await transactionDb
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
  });
};
