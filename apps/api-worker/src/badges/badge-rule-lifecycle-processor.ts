import { logError, logInfo, type ObservabilityContext } from "@credtrail/core-domain";
import {
  createAuditLog,
  deleteFailedJobQueueMessageByIdentity,
  ensureBadgeRuleRecertificationReview,
  enqueueJobQueueMessageOnce,
  expireBadgeIssuanceRuleVersion,
  findBadgeIssuanceRuleById,
  findTenantById,
  listActiveTenants,
  listBadgeIssuanceRuleVersionsDueForExpiry,
  listBadgeIssuanceRuleVersionsDueForExpiryReminder,
  listBadgeIssuanceRuleVersionsDueForRecertification,
  listBadgeIssuanceRuleVersionsDueForRecertificationReminder,
  markBadgeIssuanceRuleVersionExpiryReminderSent,
  markBadgeIssuanceRuleVersionRecertificationReminderSent,
  suspendBadgeIssuanceRuleVersionForOverdueRecertification,
  type BadgeRuleLifecycleDueVersionRecord,
  type SqlDatabase,
} from "@credtrail/db";
import type { AppBindings } from "../app";
import { sendBadgeRuleLifecycleReminderNotifications } from "../notifications/send-badge-rule-lifecycle-email";
import { resolveRuleDefinition } from "../rules/badge-rule-definition-resolver";

const LIFECYCLE_REMINDER_WINDOW_DAYS = 7;
const RECERTIFICATION_AUTO_SUSPEND_OVERDUE_DAYS = 30;

export interface BadgeRuleLifecycleProcessingResult {
  readonly tenantsScanned: number;
  readonly lifecycleJobsEnqueued: number;
  readonly dueVersionsProcessed: number;
  readonly endOfTermJobsEnqueued: number;
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

const ruleUsesEndOfTermIssuance = (ruleJson: string): boolean => {
  return resolveRuleDefinition(ruleJson).options?.issuanceTiming === "end_of_term";
};

const endOfTermIdempotencyKey = (input: {
  readonly ruleId: string;
  readonly versionId: string;
  readonly expiresAt: string | null;
  readonly nowIso: string;
}): string => `end-of-term:${input.ruleId}:${input.versionId}:${input.expiresAt ?? input.nowIso}`;

const notifyLifecycleReminder = async (
  input: ProcessBadgeRuleLifecycleInput & {
    readonly version: BadgeRuleLifecycleDueVersionRecord;
    readonly reminderType: "expiry" | "recertification";
    readonly dueAt: string;
  },
): Promise<boolean> => {
  if (input.env === undefined || input.adminUrlForTenant === undefined) {
    return true;
  }

  const [tenant, rule] = await Promise.all([
    findTenantById(input.db, input.tenantId),
    findBadgeIssuanceRuleById(input.db, input.tenantId, input.version.ruleId),
  ]);

  if (rule === null) {
    return false;
  }

  try {
    await sendBadgeRuleLifecycleReminderNotifications(input.db, {
      emailBinding: input.env.EMAIL,
      fromEmail: input.env.TRANSACTIONAL_EMAIL_FROM_ADDRESS,
      fromName: input.env.TRANSACTIONAL_EMAIL_FROM_NAME,
      tenantId: input.tenantId,
      tenantDisplayName: tenant?.displayName ?? input.tenantId,
      ruleName: rule.name,
      versionNumber: input.version.versionNumber,
      dueAt: input.dueAt,
      reminderType: input.reminderType,
      adminUrl: input.adminUrlForTenant(input.tenantId),
    });
    return true;
  } catch (error: unknown) {
    logError(input.observability, "badge_rule_lifecycle_reminder_failed", {
      tenantId: input.tenantId,
      ruleId: input.version.ruleId,
      versionId: input.version.id,
      reminderType: input.reminderType,
      detail: error instanceof Error ? error.message : "Unknown lifecycle reminder error",
    });
    return false;
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

    const notified = await notifyLifecycleReminder({
      ...input.lifecycleInput,
      version,
      reminderType: input.reminderType,
      dueAt,
    });

    if (!notified) {
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
    dueVersions,
    expiryReminderVersions,
    recertificationReminderVersions,
    recertificationDueVersions,
  ] = await Promise.all([
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
  let endOfTermJobsEnqueued = 0;
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

  for (const version of dueVersions) {
    const usesEndOfTermIssuance = ruleUsesEndOfTermIssuance(version.ruleJson);

    if (usesEndOfTermIssuance) {
      const idempotencyKey = endOfTermIdempotencyKey({
        ruleId: version.ruleId,
        versionId: version.id,
        expiresAt: version.expiresAt,
        nowIso: input.nowIso,
      });

      await deleteFailedJobQueueMessageByIdentity(input.db, {
        tenantId: input.tenantId,
        jobType: "process_end_of_term_badge_rule",
        idempotencyKey,
      });

      const inserted = await enqueueJobQueueMessageOnce(input.db, {
        tenantId: input.tenantId,
        jobType: "process_end_of_term_badge_rule",
        payload: {
          ruleId: version.ruleId,
          versionId: version.id,
          badgeTemplateId: version.badgeTemplateId,
          scheduledFor: input.nowIso,
        },
        idempotencyKey,
        nowIso: input.nowIso,
      });

      if (inserted) {
        endOfTermJobsEnqueued += 1;
      }

      continue;
    }

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
    endOfTermJobsEnqueued,
    expiredVersions,
    expiryRemindersSent,
    recertificationRemindersSent,
    recertificationReviewsOpened,
    recertificationAutoSuspensions,
  });

  return {
    dueVersionsProcessed: dueVersions.length,
    endOfTermJobsEnqueued,
    expiredVersions,
    expiryRemindersSent,
    recertificationRemindersSent,
    recertificationReviewsOpened,
    recertificationAutoSuspensions,
  };
};
