import { automatedBadgeRuleCommandIdempotencyKey } from "@credtrail/validation";
import { expect, it } from "vitest";
import { createTestBadgeIssuanceRule } from "./badge-issuance-rule-test-fixtures";
import { activateBadgeIssuanceRuleVersion } from "./badge-issuance-rules";
import {
  enqueueAutomatedBadgeRuleEvaluation,
  findAutomatedBadgeRuleEvaluationStatus,
  markAutomatedBadgeRuleEvaluationQueueFailure,
  markAutomatedBadgeRuleEvaluationRetrying,
  markAutomatedBadgeRuleEvaluationRunning,
  markAutomatedBadgeRuleEvaluationSucceeded,
  requestManualAutomatedBadgeRuleEvaluation,
} from "./badge-rule-automated-evaluation-status";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  describeDbIntegration,
} from "./postgres-test-support";
import { runSqlTransaction } from "./tenant-scope";

const ACTIVATED_AT = "2026-09-02T17:00:00.000Z";

const createActiveAutomaticRule = async (
  fixture: Awaited<ReturnType<typeof createBadgeRuleIntegrationFixture>>,
) => {
  const created = await createTestBadgeIssuanceRule(fixture.db, {
    tenantId: fixture.tenantId,
    name: "Status test pathway",
    badgeTemplateId: fixture.badgeTemplateId,
    lmsProviderKind: "sakai",
    lmsConnectionId: fixture.lmsConnectionId,
    ruleJson: JSON.stringify({
      conditions: {
        type: "program_completion",
        courseIds: ["course-101", "course-201", "course-301"],
        minimumCompleted: 3,
      },
      options: { issuanceTiming: "immediate" },
    }),
    createdByUserId: fixture.userId,
  });
  await fixture.db
    .prepare("UPDATE badge_issuance_rule_versions SET status = 'approved' WHERE id = ?")
    .bind(created.version.id)
    .run();
  await activateBadgeIssuanceRuleVersion(fixture.db, {
    tenantId: fixture.tenantId,
    ruleId: created.rule.id,
    versionId: created.version.id,
    actorUserId: fixture.userId,
    activatedAt: ACTIVATED_AT,
  });

  return created;
};

describeDbIntegration("badge rule automated evaluation status", () => {
  it("guards correlated transitions and ignores stale or cross-tenant commands", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createActiveAutomaticRule(fixture);
      const activation = await findAutomatedBadgeRuleEvaluationStatus(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
      });

      expect(activation).toMatchObject({
        status: "queued",
        triggerKind: "activation",
        queuedAt: ACTIVATED_AT,
      });
      expect(activation?.commandId).toBeTruthy();

      const activationCommandId = activation?.commandId ?? "missing-command";
      expect(
        await markAutomatedBadgeRuleEvaluationRunning(fixture.db, {
          tenantId: fixture.tenantId,
          commandId: activationCommandId,
          startedAt: "2026-09-02T17:00:01.000Z",
        }),
      ).toBe(true);
      expect(
        await markAutomatedBadgeRuleEvaluationSucceeded(fixture.db, {
          tenantId: fixture.tenantId,
          commandId: activationCommandId,
          completedAt: "2026-09-02T17:00:02.000Z",
          counts: {
            candidateLearnerCount: 2,
            matchedLearnerCount: 1,
            issueJobsEnqueued: 1,
            learnersMissingEmail: 0,
            learnersAlreadyIssued: 0,
            learnersUnavailable: 0,
            learnerIdentityConflicts: 0,
          },
        }),
      ).toBe(true);

      const nextQueuedAt = "2026-09-02T18:00:00.000Z";
      const next = await runSqlTransaction(fixture.db, (transactionDb) =>
        enqueueAutomatedBadgeRuleEvaluation(transactionDb, {
          tenantId: fixture.tenantId,
          ruleId: created.rule.id,
          versionId: created.version.id,
          payload: {
            ruleId: created.rule.id,
            versionId: created.version.id,
            scheduledFor: nextQueuedAt,
          },
          idempotencyKey: automatedBadgeRuleCommandIdempotencyKey({
            versionId: created.version.id,
            command: { kind: "hour", scheduledFor: nextQueuedAt },
          }),
          triggerKind: "hourly",
          queuedAt: nextQueuedAt,
        }),
      );

      expect(next.status).toBe("queued");
      expect(
        await markAutomatedBadgeRuleEvaluationRunning(fixture.db, {
          tenantId: fixture.tenantId,
          commandId: activationCommandId,
          startedAt: "2026-09-02T18:00:01.000Z",
        }),
      ).toBe(false);
      expect(
        await markAutomatedBadgeRuleEvaluationRunning(fixture.db, {
          tenantId: "other-tenant",
          commandId: next.status === "queued" ? next.commandId : "missing-command",
          startedAt: "2026-09-02T18:00:01.000Z",
        }),
      ).toBe(false);
      await expect(
        findAutomatedBadgeRuleEvaluationStatus(fixture.db, {
          tenantId: "other-tenant",
          ruleId: created.rule.id,
          versionId: created.version.id,
        }),
      ).resolves.toBeNull();
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("records retry counts and a terminal queue failure for the same command", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createActiveAutomaticRule(fixture);
      const queued = await findAutomatedBadgeRuleEvaluationStatus(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
      });
      const commandId = queued?.commandId ?? "missing-command";

      await markAutomatedBadgeRuleEvaluationRunning(fixture.db, {
        tenantId: fixture.tenantId,
        commandId,
        startedAt: "2026-09-02T17:00:01.000Z",
      });
      await markAutomatedBadgeRuleEvaluationRetrying(fixture.db, {
        tenantId: fixture.tenantId,
        commandId,
        attemptedAt: "2026-09-02T17:00:02.000Z",
        reasonTag: "learner_evaluation_unavailable",
        counts: {
          candidateLearnerCount: 3,
          matchedLearnerCount: 1,
          issueJobsEnqueued: 0,
          learnersMissingEmail: 0,
          learnersAlreadyIssued: 0,
          learnersUnavailable: 1,
          learnerIdentityConflicts: 0,
        },
      });
      await markAutomatedBadgeRuleEvaluationQueueFailure(fixture.db, {
        tenantId: fixture.tenantId,
        commandId,
        failedAt: "2026-09-02T17:00:03.000Z",
        terminal: true,
        failureTag: "provider_unavailable",
      });

      await expect(
        findAutomatedBadgeRuleEvaluationStatus(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: created.rule.id,
          versionId: created.version.id,
        }),
      ).resolves.toMatchObject({
        status: "failed",
        reasonTag: "learner_evaluation_unavailable",
        failureTag: "provider_unavailable",
        candidateLearnerCount: 3,
        matchedLearnerCount: 1,
        learnersUnavailable: 1,
      });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("deduplicates an HTTP replay but accepts a second intentional manual command", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createActiveAutomaticRule(fixture);
      const firstRequestId = "123e4567-e89b-42d3-a456-426614174000";
      const secondRequestId = "123e4567-e89b-42d3-a456-426614174001";
      const request = {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        requestId: firstRequestId,
        requestedAt: "2026-09-02T18:05:00.000Z",
      };

      await expect(requestManualAutomatedBadgeRuleEvaluation(fixture.db, request)).resolves.toBe(
        "queued",
      );
      await expect(requestManualAutomatedBadgeRuleEvaluation(fixture.db, request)).resolves.toBe(
        "duplicate",
      );
      await expect(
        requestManualAutomatedBadgeRuleEvaluation(fixture.db, {
          ...request,
          requestId: secondRequestId,
          requestedAt: "2026-09-02T18:06:00.000Z",
        }),
      ).resolves.toBe("queued");

      const manualJobs = await fixture.db
        .prepare(
          `
          SELECT COUNT(*)::text AS count
          FROM job_queue_messages
          WHERE tenant_id = ?
            AND job_type = 'process_automated_badge_rule'
            AND idempotency_key LIKE 'automated-rule:%:manual:%'
        `,
        )
        .bind(fixture.tenantId)
        .first<{ count: string }>();

      expect(manualJobs?.count).toBe("2");
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("rejects contradictory stored status", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createActiveAutomaticRule(fixture);

      await expect(
        fixture.db
          .prepare(
            `
            UPDATE badge_rule_automated_evaluation_status
            SET status = 'succeeded', completed_at = NULL
            WHERE tenant_id = ? AND version_id = ?
          `,
          )
          .bind(fixture.tenantId, created.version.id)
          .run(),
      ).rejects.toThrow(/violates check constraint/);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("rejects a status row that crosses tenant ownership", async () => {
    const ruleFixture = await createBadgeRuleIntegrationFixture();
    const otherTenantFixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createActiveAutomaticRule(ruleFixture);

      await expect(
        ruleFixture.db
          .prepare(
            `
            INSERT INTO badge_rule_automated_evaluation_status (
              tenant_id,
              rule_id,
              version_id,
              command_id,
              trigger_kind,
              status,
              queued_at,
              updated_at
            )
            VALUES (?, ?, ?, ?, 'manual', 'queued', ?, ?)
          `,
          )
          .bind(
            otherTenantFixture.tenantId,
            created.rule.id,
            created.version.id,
            "job_cross_tenant",
            ACTIVATED_AT,
            ACTIVATED_AT,
          )
          .run(),
      ).rejects.toThrow(/violates foreign key constraint/);
    } finally {
      await cleanupTestResources(ruleFixture.db, {
        tenantIds: [ruleFixture.tenantId, otherTenantFixture.tenantId],
        userIds: [ruleFixture.userId, otherTenantFixture.userId],
      });
    }
  });
});
