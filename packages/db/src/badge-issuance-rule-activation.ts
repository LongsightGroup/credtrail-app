import { findBadgeIssuanceRuleById } from "./badge-issuance-rule-reads.js";
import { findBadgeIssuanceRuleVersionById } from "./badge-issuance-rule-version-reads.js";
import {
  automatedBadgeRuleCommandIdempotencyKey,
  badgeIssuanceRuleHasCompleteLmsLearnerPopulation,
  parseBadgeIssuanceRuleDefinitionJson,
  resolveAutomatedBadgeRuleIssuanceTiming,
} from "@credtrail/validation";
import { resolveBadgeRuleApprovalPolicy } from "./badge-rule-approval-policies.js";
import type {
  ActivateBadgeIssuanceRuleVersionInput,
  BadgeIssuanceRuleVersionRecord,
} from "./badge-issuance-rule-types.js";
import { addMonthsToIso } from "./shared-helpers.js";
import { enqueueAutomatedBadgeRuleEvaluation } from "./badge-rule-automated-evaluation-status.js";
import { runSqlTransaction, type SqlDatabase, type SqlRunResult } from "./tenant-scope.js";

/** Activates an approved badge-rule version and deprecates the prior active version atomically. */
export const activateBadgeIssuanceRuleVersion = async (
  db: SqlDatabase,
  input: ActivateBadgeIssuanceRuleVersionInput,
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const activatedAt = input.activatedAt ?? new Date().toISOString();
  const effectiveStartsAt = input.effectiveStartsAt ?? activatedAt;

  return runSqlTransaction(db, async (transactionDb) => {
    const rule = await findBadgeIssuanceRuleById(transactionDb, input.tenantId, input.ruleId);
    const version = await findBadgeIssuanceRuleVersionById(transactionDb, input);

    if (rule === null || version === null) {
      return null;
    }

    const definition = parseBadgeIssuanceRuleDefinitionJson(version.ruleJson);
    const automatedIssuanceTiming = resolveAutomatedBadgeRuleIssuanceTiming(definition);

    if (
      automatedIssuanceTiming !== null &&
      !badgeIssuanceRuleHasCompleteLmsLearnerPopulation(definition)
    ) {
      return null;
    }

    const policy = await resolveBadgeRuleApprovalPolicy(transactionDb, {
      tenantId: input.tenantId,
      orgUnitId: version.snapshot.orgUnitId,
    });
    const recertificationDueAt =
      policy.recertificationIntervalMonths === null
        ? null
        : addMonthsToIso(activatedAt, policy.recertificationIntervalMonths);
    const deprecateExistingStatement = (): Promise<SqlRunResult> =>
      transactionDb
        .prepare(
          `
            UPDATE badge_issuance_rule_versions
            SET
              status = 'deprecated',
              updated_at = ?
            WHERE tenant_id = ?
              AND rule_id = ?
              AND status = 'active'
              AND id <> ?
          `,
        )
        .bind(activatedAt, input.tenantId, input.ruleId, input.versionId)
        .run();
    const activateStatement = (): Promise<SqlRunResult> =>
      transactionDb
        .prepare(
          `
            UPDATE badge_issuance_rule_versions
            SET
              status = 'active',
              activated_by_user_id = ?,
              activated_at = ?,
              effective_starts_at = ?,
              expires_at = ?,
              expired_at = NULL,
              suspended_at = NULL,
              suspended_by_user_id = NULL,
              suspension_reason = NULL,
              recertification_due_at = ?,
              expiry_reminder_sent_at = NULL,
              recertification_reminder_sent_at = NULL,
              updated_at = ?
            WHERE tenant_id = ?
              AND rule_id = ?
              AND id = ?
              AND status = 'approved'
          `,
        )
        .bind(
          input.actorUserId,
          activatedAt,
          effectiveStartsAt,
          input.expiresAt ?? null,
          recertificationDueAt,
          activatedAt,
          input.tenantId,
          input.ruleId,
          input.versionId,
        )
        .run();
    const updateRuleActiveVersionStatement = (): Promise<SqlRunResult> =>
      transactionDb
        .prepare(
          `
            UPDATE badge_issuance_rules
            SET
              active_version_id = ?,
              updated_at = ?
            WHERE tenant_id = ?
              AND id = ?
          `,
        )
        .bind(input.versionId, activatedAt, input.tenantId, input.ruleId)
        .run();

    const activated = await activateStatement();

    if ((activated.meta.rowsWritten ?? 0) === 0) {
      return null;
    }

    await deprecateExistingStatement();
    await updateRuleActiveVersionStatement();

    if (automatedIssuanceTiming === "immediate") {
      await enqueueAutomatedBadgeRuleEvaluation(transactionDb, {
        tenantId: input.tenantId,
        ruleId: input.ruleId,
        versionId: input.versionId,
        payload: {
          ruleId: input.ruleId,
          versionId: input.versionId,
          scheduledFor: activatedAt,
        },
        idempotencyKey: automatedBadgeRuleCommandIdempotencyKey({
          versionId: input.versionId,
          command: { kind: "activation" },
        }),
        triggerKind: "activation",
        queuedAt: activatedAt,
      });
    }

    return findBadgeIssuanceRuleVersionById(transactionDb, input);
  });
};
