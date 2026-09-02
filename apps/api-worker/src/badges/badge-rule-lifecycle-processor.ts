import { logError, logInfo, type ObservabilityContext } from "@credtrail/core-domain";
import {
  createAuditLog,
  enqueueAutomatedBadgeRuleEvaluation,
  ensureBadgeRuleRecertificationReview,
  enqueueJobQueueMessageOnce,
  expireBadgeIssuanceRuleVersion,
  findTenantById,
  listActiveTenants,
  listBadgeIssuanceRuleVersionsForAutomatedEvaluation,
  listBadgeIssuanceRuleVersionsDueForExpiry,
  listBadgeIssuanceRuleVersionsDueForExpiryReminder,
  listBadgeIssuanceRuleVersionsDueForRecertification,
  listBadgeIssuanceRuleVersionsDueForRecertificationReminder,
  markBadgeIssuanceRuleVersionExpiryReminderSent,
  markBadgeIssuanceRuleVersionRecertificationReminderSent,
  runSqlTransaction,
  suspendBadgeIssuanceRuleVersionForOverdueRecertification,
  type BadgeRuleLifecycleDueVersionRecord,
  type SqlDatabase,
} from "@credtrail/db";
import type { AppBindings } from "../app/types";
import { sendBadgeRuleLifecycleReminderNotifications } from "../notifications/send-badge-rule-lifecycle-email";
import { mapConcurrentBounded } from "../utils/map-concurrent-bounded";
import { planAutomatedBadgeRuleLifecycle } from "./automated-badge-rule-schedule";

const LIFECYCLE_REMINDER_WINDOW_DAYS = 7;
const RECERTIFICATION_AUTO_SUSPEND_OVERDUE_DAYS = 30;

export interface BadgeRuleLifecycleProcessingResult {
  readonly tenantsScanned: number;
  readonly lifecycleJobsEnqueued: number;
  readonly dueVersionsProcessed: number;
  readonly automatedEvaluationJobsEnqueued: number;
  readonly expiredVersions: number;
  readonly expiryRemindersSent: number;
  readonly recertificationRemindersSent: number;
  readonly recertificationReviewsOpened: number;
  readonly recertificationAutoSuspensions: number;
}

export interface ProcessBadgeRuleLifecycleInput {
  readonly db: SqlDatabase;
  readonly tenantId: string;
  readonly nowIso: string;
  readonly observability: ObservabilityContext;
  readonly env?: AppBindings | undefined;
  readonly adminUrlForTenant?: ((tenantId: string) => string) | undefined;
}

const lifecycleScheduleBucketFromIso = (isoTimestamp: string): string => isoTimestamp.slice(0, 13);

type LifecycleReminderNotificationResult =
  | {
      readonly status: "sent";
    }
  | {
      readonly status: "skipped_no_transport";
    }
  | {
      readonly status: "failed";
    };

const notifyLifecycleReminder = async (
  input: ProcessBadgeRuleLifecycleInput & {
    readonly version: BadgeRuleLifecycleDueVersionRecord;
    readonly reminderType: "expiry" | "recertification";
    readonly dueAt: string;
  },
): Promise<LifecycleReminderNotificationResult> => {
  if (input.env === undefined || input.adminUrlForTenant === undefined) {
    return { status: "skipped_no_transport" };
  }

  const tenant = await findTenantById(input.db, input.tenantId);

  try {
    await sendBadgeRuleLifecycleReminderNotifications(input.db, {
      emailBinding: input.env.EMAIL,
      fromEmail: input.env.TRANSACTIONAL_EMAIL_FROM_ADDRESS,
      fromName: input.env.TRANSACTIONAL_EMAIL_FROM_NAME,
      tenantId: input.tenantId,
      tenantDisplayName: tenant?.displayName ?? input.tenantId,
      ruleName: input.version.snapshot.name,
      versionNumber: input.version.versionNumber,
      dueAt: input.dueAt,
      reminderType: input.reminderType,
      adminUrl: input.adminUrlForTenant(input.tenantId),
    });
    return { status: "sent" };
  } catch (error: unknown) {
    logError(input.observability, "badge_rule_lifecycle_reminder_failed", {
      tenantId: input.tenantId,
      ruleId: input.version.ruleId,
      versionId: input.version.id,
      reminderType: input.reminderType,
      detail: error instanceof Error ? error.message : "Unknown lifecycle reminder error",
    });
    return { status: "failed" };
  }
};

const processReminders = async (input: {
  readonly lifecycleInput: ProcessBadgeRuleLifecycleInput;
  readonly versions: readonly BadgeRuleLifecycleDueVersionRecord[];
  readonly reminderType: "expiry" | "recertification";
  readonly getDueAt: (version: BadgeRuleLifecycleDueVersionRecord) => string | null;
  readonly markSent: (version: BadgeRuleLifecycleDueVersionRecord) => Promise<boolean>;
}): Promise<number> => {
  let remindersSent = 0;

  for (const version of input.versions) {
    const dueAt = input.getDueAt(version);

    if (dueAt === null) {
      continue;
    }

    const notification = await notifyLifecycleReminder({
      ...input.lifecycleInput,
      version,
      reminderType: input.reminderType,
      dueAt,
    });

    if (notification.status !== "sent") {
      continue;
    }

    const marked = await input.markSent(version);

    if (marked) {
      remindersSent += 1;
    }
  }

  return remindersSent;
};

export const enqueueBadgeRuleLifecycleJobsForActiveTenants = async (input: {
  readonly db: SqlDatabase;
  readonly nowIso: string;
}): Promise<{ readonly tenantsScanned: number; readonly lifecycleJobsEnqueued: number }> => {
  const tenants = await listActiveTenants(input.db);
  let lifecycleJobsEnqueued = 0;
  const scheduleBucket = lifecycleScheduleBucketFromIso(input.nowIso);

  for (const tenant of tenants) {
    const inserted = await enqueueJobQueueMessageOnce(input.db, {
      tenantId: tenant.id,
      jobType: "process_badge_rule_lifecycle",
      payload: {
        scheduledFor: input.nowIso,
      },
      idempotencyKey: `badge-rule-lifecycle:${scheduleBucket}`,
      nowIso: input.nowIso,
    });

    if (inserted) {
      lifecycleJobsEnqueued += 1;
    }
  }

  return {
    tenantsScanned: tenants.length,
    lifecycleJobsEnqueued,
  };
};

export const processBadgeRuleLifecycleForTenant = async (
  input: ProcessBadgeRuleLifecycleInput,
): Promise<
  Omit<BadgeRuleLifecycleProcessingResult, "tenantsScanned" | "lifecycleJobsEnqueued">
> => {
  const [
    evaluableVersions,
    dueVersions,
    expiryReminderVersions,
    recertificationReminderVersions,
    recertificationDueVersions,
  ] = await Promise.all([
    listBadgeIssuanceRuleVersionsForAutomatedEvaluation(input.db, {
      tenantId: input.tenantId,
      nowIso: input.nowIso,
    }),
    listBadgeIssuanceRuleVersionsDueForExpiry(input.db, {
      tenantId: input.tenantId,
      nowIso: input.nowIso,
    }),
    listBadgeIssuanceRuleVersionsDueForExpiryReminder(input.db, {
      tenantId: input.tenantId,
      nowIso: input.nowIso,
      reminderWindowDays: LIFECYCLE_REMINDER_WINDOW_DAYS,
    }),
    listBadgeIssuanceRuleVersionsDueForRecertificationReminder(input.db, {
      tenantId: input.tenantId,
      nowIso: input.nowIso,
      reminderWindowDays: LIFECYCLE_REMINDER_WINDOW_DAYS,
    }),
    listBadgeIssuanceRuleVersionsDueForRecertification(input.db, {
      tenantId: input.tenantId,
      nowIso: input.nowIso,
    }),
  ]);
  const automatedLifecyclePlan = planAutomatedBadgeRuleLifecycle({
    tenantId: input.tenantId,
    nowIso: input.nowIso,
    evaluableVersions,
    dueVersions,
  });
  const automatedEvaluationEnqueueResults = await mapConcurrentBounded(
    automatedLifecyclePlan.evaluationCommands,
    { concurrency: 8 },
    (command) =>
      runSqlTransaction(input.db, (transactionDb) =>
        enqueueAutomatedBadgeRuleEvaluation(transactionDb, {
          tenantId: command.tenantId,
          ruleId: command.payload.ruleId,
          versionId: command.payload.versionId,
          payload: command.payload,
          idempotencyKey: command.idempotencyKey,
          triggerKind: command.triggerKind,
          queuedAt: input.nowIso,
        }).then((result) => result.status === "queued"),
      ),
  );
  const automatedEvaluationJobsEnqueued = automatedEvaluationEnqueueResults.filter(
    (inserted) => inserted,
  ).length;
  let expiredVersions = 0;
  let recertificationReviewsOpened = 0;
  let recertificationAutoSuspensions = 0;

  const expiryRemindersSent = await processReminders({
    lifecycleInput: input,
    versions: expiryReminderVersions,
    reminderType: "expiry",
    getDueAt: (version) => version.expiresAt,
    markSent: (version) =>
      markBadgeIssuanceRuleVersionExpiryReminderSent(input.db, {
        tenantId: input.tenantId,
        ruleId: version.ruleId,
        versionId: version.id,
        occurredAt: input.nowIso,
      }),
  });

  const recertificationRemindersSent = await processReminders({
    lifecycleInput: input,
    versions: recertificationReminderVersions,
    reminderType: "recertification",
    getDueAt: (version) => version.recertificationDueAt,
    markSent: (version) =>
      markBadgeIssuanceRuleVersionRecertificationReminderSent(input.db, {
        tenantId: input.tenantId,
        ruleId: version.ruleId,
        versionId: version.id,
        occurredAt: input.nowIso,
      }),
  });

  for (const version of recertificationDueVersions) {
    if (version.recertificationDueAt === null) {
      continue;
    }

    const opened = await ensureBadgeRuleRecertificationReview(input.db, {
      tenantId: input.tenantId,
      ruleId: version.ruleId,
      versionId: version.id,
      dueAt: version.recertificationDueAt,
      requestedAt: input.nowIso,
    });

    if (opened) {
      recertificationReviewsOpened += 1;
      await createAuditLog(input.db, {
        tenantId: input.tenantId,
        action: "badge_rule.recertification_review_opened",
        targetType: "badge_rule_version",
        targetId: version.id,
        metadata: {
          ruleId: version.ruleId,
          recertificationDueAt: version.recertificationDueAt,
        },
        occurredAt: input.nowIso,
      });
    }

    const suspended = await suspendBadgeIssuanceRuleVersionForOverdueRecertification(input.db, {
      tenantId: input.tenantId,
      ruleId: version.ruleId,
      versionId: version.id,
      recertificationDueAt: version.recertificationDueAt,
      overdueDays: RECERTIFICATION_AUTO_SUSPEND_OVERDUE_DAYS,
      occurredAt: input.nowIso,
    });

    if (suspended !== null) {
      recertificationAutoSuspensions += 1;
      await createAuditLog(input.db, {
        tenantId: input.tenantId,
        action: "badge_rule.version_auto_suspended",
        targetType: "badge_rule_version",
        targetId: version.id,
        metadata: {
          ruleId: version.ruleId,
          reason: "recertification_overdue",
          recertificationDueAt: version.recertificationDueAt,
          overdueDays: RECERTIFICATION_AUTO_SUSPEND_OVERDUE_DAYS,
        },
        occurredAt: input.nowIso,
      });
    }
  }

  for (const version of automatedLifecyclePlan.versionsToExpire) {
    const expired = await expireBadgeIssuanceRuleVersion(input.db, {
      tenantId: input.tenantId,
      ruleId: version.ruleId,
      versionId: version.id,
      occurredAt: input.nowIso,
    });

    if (expired !== null) {
      expiredVersions += 1;
      await createAuditLog(input.db, {
        tenantId: input.tenantId,
        action: "badge_rule.version_expired",
        targetType: "badge_rule_version",
        targetId: version.id,
        metadata: {
          ruleId: version.ruleId,
          expiresAt: version.expiresAt,
        },
        occurredAt: input.nowIso,
      });
    }
  }

  logInfo(input.observability, "badge_rule_lifecycle_processed", {
    tenantId: input.tenantId,
    dueVersionsProcessed: dueVersions.length,
    automatedEvaluationJobsEnqueued,
    expiredVersions,
    expiryRemindersSent,
    recertificationRemindersSent,
    recertificationReviewsOpened,
    recertificationAutoSuspensions,
  });

  return {
    dueVersionsProcessed: dueVersions.length,
    automatedEvaluationJobsEnqueued,
    expiredVersions,
    expiryRemindersSent,
    recertificationRemindersSent,
    recertificationReviewsOpened,
    recertificationAutoSuspensions,
  };
};
