import { logError } from "@credtrail/core-domain";
import { resolveDatabase } from "../app/database";
import { enqueueBadgeRuleLifecycleJobsForActiveTenants } from "../badges/badge-rule-lifecycle-processor";
import type { AppBindings } from "../app/types";
import { observabilityContext } from "../app/observability";

export const runScheduledBadgeRuleLifecycleEnqueue = async (env: AppBindings): Promise<void> => {
  const db = resolveDatabase(env);
  const nowIso = new Date().toISOString();

  try {
    await enqueueBadgeRuleLifecycleJobsForActiveTenants({
      db,
      nowIso,
    });
  } catch (error: unknown) {
    const detail =
      error instanceof Error ? error.message : "Unknown badge rule lifecycle enqueue failure";

    logError(observabilityContext(env), "badge_rule_lifecycle_enqueue_failed", {
      detail,
    });
  }
};
