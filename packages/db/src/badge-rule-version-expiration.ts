import {
  automatedBadgeRuleLifecycleWindowMatches,
  parseBadgeIssuanceRuleDefinitionJson,
  resolveAutomatedBadgeRuleIssuanceTiming,
  type IssueBadgeQueueJob,
} from "@credtrail/validation";
import { createAuditLog } from "./audit-logs.js";
import { findBadgeIssuanceRuleVersionById } from "./badge-issuance-rule-version-reads.js";
import type { BadgeIssuanceRuleVersionRecord } from "./badge-issuance-rule-types.js";
import { enqueueJobQueueMessagesOnce } from "./job-queue-enqueue.js";
import { runSqlTransaction, type SqlDatabase } from "./tenant-scope.js";

interface AutomatedBadgeRuleVersionRow {
  readonly ruleJson: string;
  readonly effectiveStartsAt: string | null;
  readonly expiresAt: string | null;
}

interface ExpireActiveBadgeRuleVersionInput {
  readonly tenantId: string;
  readonly ruleId: string;
  readonly versionId: string;
  readonly occurredAt: string;
}

const expireActiveBadgeIssuanceRuleVersionRows = async (
  db: SqlDatabase,
  input: ExpireActiveBadgeRuleVersionInput,
): Promise<boolean> => {
  const result = await db
    .prepare(
      `
      UPDATE badge_issuance_rule_versions
      SET
        status = 'expired',
        expired_at = ?,
        updated_at = ?
      WHERE tenant_id = ?
        AND rule_id = ?
        AND id = ?
        AND status = 'active'
        AND expires_at IS NOT NULL
        AND expires_at <= ?
    `,
    )
    .bind(
      input.occurredAt,
      input.occurredAt,
      input.tenantId,
      input.ruleId,
      input.versionId,
      input.occurredAt,
    )
    .run();

  if ((result.meta.rowsWritten ?? 0) === 0) {
    return false;
  }

  await db
    .prepare(
      `
      UPDATE badge_issuance_rules
      SET
        active_version_id = NULL,
        updated_at = ?
      WHERE tenant_id = ?
        AND id = ?
        AND active_version_id = ?
    `,
    )
    .bind(input.occurredAt, input.tenantId, input.ruleId, input.versionId)
    .run();

  return true;
};

/** Expires an active due rule version and clears its active pointer atomically. */
export const expireBadgeIssuanceRuleVersion = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly ruleId: string;
    readonly versionId: string;
    readonly occurredAt?: string | undefined;
  },
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const occurredAt = input.occurredAt ?? new Date().toISOString();

  return runSqlTransaction(db, async (transactionDb) => {
    const expired = await expireActiveBadgeIssuanceRuleVersionRows(transactionDb, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      versionId: input.versionId,
      occurredAt,
    });

    if (!expired) {
      return null;
    }

    return findBadgeIssuanceRuleVersionById(transactionDb, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      versionId: input.versionId,
    });
  });
};

/** Result of atomically committing one automated badge-rule evaluation. */
export type CommitAutomatedBadgeRuleEvaluationResult =
  | {
      readonly status: "committed";
      readonly issueJobsEnqueued: number;
      readonly versionExpired: boolean;
    }
  | { readonly status: "not_active" }
  | { readonly status: "not_automated" };

/** Atomically guards an automated evaluation, queues its issuances, and finalizes end-of-term rules. */
export const commitAutomatedBadgeRuleEvaluation = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly ruleId: string;
    readonly versionId: string;
    readonly evaluatedAt: string;
    readonly issueJobs: readonly IssueBadgeQueueJob[];
  },
): Promise<CommitAutomatedBadgeRuleEvaluationResult> => {
  return runSqlTransaction(db, async (transactionDb) => {
    const version = await transactionDb
      .prepare(
        `
        SELECT
          versions.rule_json AS ruleJson,
          versions.effective_starts_at AS effectiveStartsAt,
          versions.expires_at AS expiresAt
        FROM badge_issuance_rule_versions AS versions
        INNER JOIN badge_issuance_rules AS rules
          ON rules.tenant_id = versions.tenant_id
          AND rules.id = versions.rule_id
        WHERE versions.tenant_id = ?
          AND versions.rule_id = ?
          AND versions.id = ?
          AND versions.status = 'active'
          AND rules.active_version_id = versions.id
        FOR UPDATE OF versions, rules
      `,
      )
      .bind(input.tenantId, input.ruleId, input.versionId)
      .first<AutomatedBadgeRuleVersionRow>();

    if (version === null) {
      return { status: "not_active" };
    }

    const definition = parseBadgeIssuanceRuleDefinitionJson(version.ruleJson);
    const issuanceTiming = resolveAutomatedBadgeRuleIssuanceTiming(definition);

    if (issuanceTiming === null) {
      return { status: "not_automated" };
    }

    if (
      !automatedBadgeRuleLifecycleWindowMatches({
        effectiveStartsAt: version.effectiveStartsAt,
        expiresAt: version.expiresAt,
        evaluatedAt: input.evaluatedAt,
        issuanceTiming,
      })
    ) {
      return { status: "not_active" };
    }

    const issueJobsEnqueued = await enqueueJobQueueMessagesOnce(transactionDb, {
      messages: input.issueJobs.map((job) => ({
        tenantId: job.tenantId,
        jobType: job.jobType,
        payload: job.payload,
        idempotencyKey: job.idempotencyKey,
      })),
      nowIso: input.evaluatedAt,
    });

    if (issuanceTiming !== "end_of_term") {
      return { status: "committed", issueJobsEnqueued, versionExpired: false };
    }

    const expired = await expireActiveBadgeIssuanceRuleVersionRows(transactionDb, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      versionId: input.versionId,
      occurredAt: input.evaluatedAt,
    });

    if (!expired) {
      throw new Error("Guarded automated rule expiration did not update the active version");
    }

    await createAuditLog(transactionDb, {
      tenantId: input.tenantId,
      action: "badge_rule.version_expired",
      targetType: "badge_rule_version",
      targetId: input.versionId,
      metadata: {
        ruleId: input.ruleId,
        expiresAt: version.expiresAt,
        endOfTermIssuanceJobsEnqueued: issueJobsEnqueued,
      },
      occurredAt: input.evaluatedAt,
    });

    return { status: "committed", issueJobsEnqueued, versionExpired: true };
  });
};
