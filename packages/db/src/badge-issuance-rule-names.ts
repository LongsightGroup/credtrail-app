import { createAuditLog } from "./audit-logs";
import { lockBadgeIssuanceRuleForTransition } from "./badge-issuance-rule-approval-storage";
import { findBadgeIssuanceRuleById } from "./badge-issuance-rule-reads";
import { runSqlTransaction, type SqlDatabase } from "./tenant-scope";
import type { BadgeIssuanceRuleRecord } from "./badge-issuance-rule-types";

/** Changes current naming metadata atomically with its audit record, without editing any version. */
export const renameBadgeIssuanceRule = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly ruleId: string;
    readonly customLabel: string;
    readonly actorUserId: string;
  },
): Promise<
  | { readonly status: "renamed"; readonly rule: BadgeIssuanceRuleRecord }
  | { readonly status: "not_found" }
> => {
  return runSqlTransaction(db, async (transactionDb) => {
    const rule = await lockBadgeIssuanceRuleForTransition(transactionDb, input);
    if (rule === null) return { status: "not_found" };
    if (rule.customLabel === input.customLabel && rule.name === input.customLabel) {
      return { status: "renamed", rule };
    }
    await transactionDb
      .prepare(`
      UPDATE badge_issuance_rules SET custom_label = ?, name = ?, updated_at = ?
      WHERE tenant_id = ? AND id = ?
    `)
      .bind(
        input.customLabel,
        input.customLabel,
        new Date().toISOString(),
        input.tenantId,
        input.ruleId,
      )
      .run();
    await createAuditLog(transactionDb, {
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      action: "badge_rule.name_updated",
      targetType: "badge_rule",
      targetId: input.ruleId,
      metadata: { previousCustomLabel: rule.customLabel, customLabel: input.customLabel },
    });
    const renamed = await findBadgeIssuanceRuleById(transactionDb, input.tenantId, input.ruleId);
    if (renamed === null) throw new Error("Renamed rule could not be reloaded");
    return { status: "renamed", rule: renamed };
  });
};
