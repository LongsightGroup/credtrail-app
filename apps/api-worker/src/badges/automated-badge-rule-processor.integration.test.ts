import * as dbModule from "@credtrail/db";
import { parseQueueJob } from "@credtrail/validation";
import { expect, it } from "vitest";
import { createTestBadgeIssuanceRule } from "../../../../packages/db/src/badge-issuance-rule-test-fixtures";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  describeDbIntegration,
} from "../../../../packages/db/src/postgres-test-support";
import type { GradebookAutomatedEvaluationReader } from "../lms/gradebook-types";
import { processAutomatedBadgeRule } from "./automated-badge-rule-processor";
import { processBadgeRuleLifecycleForTenant } from "./badge-rule-lifecycle-processor";

const NOW_ISO = "2026-08-04T10:00:00.000Z";
const COURSE_IDS = ["course-101", "course-201", "course-301"] as const;

const sha256Hex = async (value: string): Promise<string> =>
  Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

const pathwayProvider = (): GradebookAutomatedEvaluationReader => ({
  listLearners: ({ courseId }) =>
    Promise.resolve([
      {
        courseId,
        learnerId: "learner-complete",
        displayName: "Complete Learner",
        email: "complete@example.edu",
      },
      {
        courseId,
        learnerId: "learner-incomplete",
        displayName: "Incomplete Learner",
        email: "incomplete@example.edu",
      },
    ]),
  listSubmissions: () => Promise.resolve([]),
  listGrades: () => Promise.resolve([]),
  listCompletions: ({ courseId, learnerId }) =>
    Promise.resolve([
      {
        courseId,
        learnerId: learnerId ?? "",
        completed: learnerId === "learner-complete" || courseId !== "course-301",
        completedAt: null,
        completionPercent: learnerId === "learner-complete" || courseId !== "course-301" ? 100 : 50,
        sourceState: "gradebook_items",
      },
    ]),
});

describeDbIntegration("processAutomatedBadgeRule", () => {
  it("finds learners across a three-course pathway and queues one idempotent issuance", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createTestBadgeIssuanceRule(fixture.db, {
        tenantId: fixture.tenantId,
        name: "Three-course pathway",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: JSON.stringify({
          conditions: {
            type: "program_completion",
            courseIds: COURSE_IDS,
            minimumCompleted: 3,
          },
          options: { issuanceTiming: "immediate" },
        }),
        createdByUserId: fixture.userId,
      });
      await fixture.db
        .prepare(
          `
          UPDATE badge_templates
          SET
            title = 'Changed after rule approval',
            description = 'Mutable template description',
            criteria_uri = 'https://example.edu/criteria/changed',
            image_uri = 'https://example.edu/badges/changed.png',
            trusted_credential_metadata_json = '{"credentialType":"Certificate"}'
          WHERE tenant_id = ?
            AND id = ?
        `,
        )
        .bind(fixture.tenantId, fixture.badgeTemplateId)
        .run();
      await fixture.db
        .prepare("UPDATE badge_issuance_rule_versions SET status = 'approved' WHERE id = ?")
        .bind(created.version.id)
        .run();
      await dbModule.activateBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        actorUserId: fixture.userId,
        activatedAt: NOW_ISO,
      });
      const payload = {
        ruleId: created.rule.id,
        versionId: created.version.id,
        scheduledFor: NOW_ISO,
      };
      const first = await processAutomatedBadgeRule({
        db: fixture.db,
        tenantId: fixture.tenantId,
        payload,
        sha256Hex,
        gradebookProvider: pathwayProvider(),
      });
      const replay = await processAutomatedBadgeRule({
        db: fixture.db,
        tenantId: fixture.tenantId,
        payload,
        sha256Hex,
        gradebookProvider: pathwayProvider(),
      });
      const queuedIssuance = await fixture.db
        .prepare(
          `
          SELECT payload_json AS payloadJson, idempotency_key AS idempotencyKey
          FROM job_queue_messages
          WHERE tenant_id = ?
            AND job_type = 'issue_badge'
        `,
        )
        .bind(fixture.tenantId)
        .first<{ payloadJson: string; idempotencyKey: string }>();
      const activationJob = await fixture.db
        .prepare(
          `
          SELECT payload_json AS payloadJson
          FROM job_queue_messages
          WHERE tenant_id = ?
            AND job_type = 'process_automated_badge_rule'
        `,
        )
        .bind(fixture.tenantId)
        .first<{ payloadJson: string }>();

      expect(first).toMatchObject({
        status: "processed",
        candidateLearnerCount: 2,
        matchedLearnerCount: 1,
        issueJobsEnqueued: 1,
      });
      expect(replay).toMatchObject({ status: "processed", issueJobsEnqueued: 0 });
      expect(JSON.parse(activationJob?.payloadJson ?? "{}")).toMatchObject({
        ruleId: created.rule.id,
        versionId: created.version.id,
      });
      const queuedIssuancePayload: unknown = JSON.parse(queuedIssuance?.payloadJson ?? "{}");

      expect(queuedIssuancePayload).toMatchObject({
        recipientIdentity: "complete@example.edu",
        lmsLearnerIdentity: {
          connectionId: fixture.lmsConnectionId,
          learnerId: "learner-complete",
        },
        achievementSource: {
          kind: "rule_version",
          provenance: {
            source: "rule_evaluate",
            ruleId: created.rule.id,
            versionId: created.version.id,
          },
        },
      });
      expect(queuedIssuancePayload).not.toHaveProperty("badgeTemplateId");
      expect(queuedIssuancePayload).not.toHaveProperty("achievementSnapshot");
      expect(queuedIssuancePayload).not.toHaveProperty("recipientIdentifiers");
      expect(queuedIssuance?.idempotencyKey).toMatch(/^rule-evaluate:[0-9a-f]{64}$/);
      expect(() =>
        parseQueueJob({
          jobType: "issue_badge",
          tenantId: fixture.tenantId,
          payload: queuedIssuancePayload,
          idempotencyKey: queuedIssuance?.idempotencyKey ?? "",
        }),
      ).not.toThrow();
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("leaves an end-of-term rule active when any learner evaluation is unavailable", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createTestBadgeIssuanceRule(fixture.db, {
        tenantId: fixture.tenantId,
        name: "End-of-term pathway",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: JSON.stringify({
          conditions: {
            type: "program_completion",
            courseIds: COURSE_IDS,
            minimumCompleted: 3,
          },
          options: { issuanceTiming: "end_of_term" },
        }),
        createdByUserId: fixture.userId,
      });
      await fixture.db
        .prepare("UPDATE badge_issuance_rule_versions SET status = 'approved' WHERE id = ?")
        .bind(created.version.id)
        .run();
      await dbModule.activateBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        actorUserId: fixture.userId,
        activatedAt: "2026-01-01T00:00:00.000Z",
        expiresAt: NOW_ISO,
      });
      const baseProvider = pathwayProvider();
      const provider: GradebookAutomatedEvaluationReader = {
        ...baseProvider,
        listCompletions: (request) => {
          if (request.learnerId === "learner-incomplete") {
            return Promise.reject(new Error("Learner gradebook data is unavailable"));
          }

          return baseProvider.listCompletions(request);
        },
      };

      const result = await processAutomatedBadgeRule({
        db: fixture.db,
        tenantId: fixture.tenantId,
        payload: {
          ruleId: created.rule.id,
          versionId: created.version.id,
          scheduledFor: NOW_ISO,
        },
        sha256Hex,
        gradebookProvider: provider,
      });
      const activeVersion = await dbModule.findBadgeIssuanceRuleVersionById(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
      });
      const issueJobCount = await fixture.db
        .prepare(
          `
          SELECT COUNT(*)::text AS count
          FROM job_queue_messages
          WHERE tenant_id = ?
            AND job_type = 'issue_badge'
        `,
        )
        .bind(fixture.tenantId)
        .first<{ count: string }>();
      const auditLogs = await dbModule.listAuditLogs(fixture.db, {
        tenantId: fixture.tenantId,
        action: "badge_rule.version_expired",
        targetId: created.version.id,
      });

      expect(result).toMatchObject({
        status: "retry",
        reason: "learner_evaluation_unavailable",
        matchedLearnerCount: 1,
        learnersUnavailable: 1,
      });
      expect(activeVersion).toMatchObject({ status: "active", expiredAt: null });
      expect(issueJobCount?.count).toBe("0");
      expect(auditLogs).toHaveLength(0);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("does not commit issuance after the active rule is suspended during evaluation", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createTestBadgeIssuanceRule(fixture.db, {
        tenantId: fixture.tenantId,
        name: "Concurrent suspension pathway",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: JSON.stringify({
          conditions: {
            type: "program_completion",
            courseIds: COURSE_IDS,
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
      await dbModule.activateBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        actorUserId: fixture.userId,
        activatedAt: NOW_ISO,
      });
      const baseProvider = pathwayProvider();
      let suspension: Promise<unknown> | undefined;
      const provider: GradebookAutomatedEvaluationReader = {
        ...baseProvider,
        listCompletions: async ({ courseId, learnerId }) => {
          suspension ??= dbModule.suspendBadgeIssuanceRuleVersion(fixture.db, {
            tenantId: fixture.tenantId,
            ruleId: created.rule.id,
            versionId: created.version.id,
            actorUserId: fixture.userId,
            reason: "Concurrent administrator suspension",
            occurredAt: NOW_ISO,
          });
          await suspension;

          return [
            {
              courseId,
              learnerId: learnerId ?? "",
              completed: true,
              completedAt: NOW_ISO,
              completionPercent: 100,
              sourceState: "gradebook_items",
            },
          ];
        },
      };
      const result = await processAutomatedBadgeRule({
        db: fixture.db,
        tenantId: fixture.tenantId,
        payload: {
          ruleId: created.rule.id,
          versionId: created.version.id,
          scheduledFor: NOW_ISO,
        },
        sha256Hex,
        gradebookProvider: provider,
      });
      const issueJobCount = await fixture.db
        .prepare(
          `
          SELECT COUNT(*)::text AS count
          FROM job_queue_messages
          WHERE tenant_id = ?
            AND job_type = 'issue_badge'
        `,
        )
        .bind(fixture.tenantId)
        .first<{ count: string }>();

      expect(result).toEqual({
        status: "noop",
        reason: "rule_version_changed",
      });
      expect(issueJobCount?.count).toBe("0");
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("rejects automated activation when LMS rosters cannot cover every matching learner", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createTestBadgeIssuanceRule(fixture.db, {
        tenantId: fixture.tenantId,
        name: "End-of-term without courses",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: JSON.stringify({
          conditions: {
            type: "prerequisite_badge",
            badgeTemplateId: fixture.badgeTemplateId,
          },
          options: { issuanceTiming: "end_of_term" },
        }),
        createdByUserId: fixture.userId,
      });
      await fixture.db
        .prepare("UPDATE badge_issuance_rule_versions SET status = 'approved' WHERE id = ?")
        .bind(created.version.id)
        .run();
      const activation = await dbModule.activateBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        actorUserId: fixture.userId,
        activatedAt: "2026-01-01T00:00:00.000Z",
        expiresAt: NOW_ISO,
      });
      const version = await dbModule.findBadgeIssuanceRuleVersionById(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
      });
      const rule = await dbModule.findBadgeIssuanceRuleById(
        fixture.db,
        fixture.tenantId,
        created.rule.id,
      );

      expect(activation).toBeNull();
      expect(version).toMatchObject({ status: "approved", activatedAt: null, expiredAt: null });
      expect(rule?.activeVersionId).toBeNull();
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("reports conflicting LMS identities instead of selecting one arbitrarily", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createTestBadgeIssuanceRule(fixture.db, {
        tenantId: fixture.tenantId,
        name: "Identity conflict pathway",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: JSON.stringify({
          conditions: {
            type: "program_completion",
            courseIds: COURSE_IDS,
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
      await dbModule.activateBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        actorUserId: fixture.userId,
        activatedAt: NOW_ISO,
      });
      const provider: GradebookAutomatedEvaluationReader = {
        ...pathwayProvider(),
        listLearners: ({ courseId }) =>
          Promise.resolve([
            {
              courseId,
              learnerId: "learner-primary",
              displayName: "Primary Account",
              email: "shared@example.edu",
            },
            {
              courseId,
              learnerId: "learner-secondary",
              displayName: "Secondary Account",
              email: "SHARED@example.edu",
            },
          ]),
      };
      const result = await processAutomatedBadgeRule({
        db: fixture.db,
        tenantId: fixture.tenantId,
        payload: {
          ruleId: created.rule.id,
          versionId: created.version.id,
          scheduledFor: NOW_ISO,
        },
        sha256Hex,
        gradebookProvider: provider,
      });

      expect(result).toMatchObject({
        status: "processed",
        candidateLearnerCount: 0,
        matchedLearnerCount: 0,
        issueJobsEnqueued: 0,
        learnerIdentityConflicts: 2,
      });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("persists the hourly evaluation schedule through the lifecycle seam", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();
    const scheduledFor = "2026-08-04T11:15:00.000Z";

    try {
      const created = await createTestBadgeIssuanceRule(fixture.db, {
        tenantId: fixture.tenantId,
        name: "Hourly pathway",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: JSON.stringify({
          conditions: {
            type: "program_completion",
            courseIds: COURSE_IDS,
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
      await dbModule.activateBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        actorUserId: fixture.userId,
        activatedAt: NOW_ISO,
      });
      await fixture.db
        .prepare(
          "DELETE FROM job_queue_messages WHERE tenant_id = ? AND job_type = 'process_automated_badge_rule'",
        )
        .bind(fixture.tenantId)
        .run();

      const result = await processBadgeRuleLifecycleForTenant({
        db: fixture.db,
        tenantId: fixture.tenantId,
        nowIso: scheduledFor,
        observability: { service: "api-worker", environment: "test" },
      });
      const scheduledJob = await fixture.db
        .prepare(
          `
          SELECT payload_json AS payloadJson, idempotency_key AS idempotencyKey
          FROM job_queue_messages
          WHERE tenant_id = ?
            AND job_type = 'process_automated_badge_rule'
        `,
        )
        .bind(fixture.tenantId)
        .first<{ payloadJson: string; idempotencyKey: string }>();

      if (scheduledJob === null) {
        throw new Error("Expected persisted automated evaluation job");
      }

      expect(result.automatedEvaluationJobsEnqueued).toBe(1);
      expect(scheduledJob.idempotencyKey).toBe(
        `automated-rule:${created.version.id}:hour:2026-08-04T11`,
      );
      const scheduledPayload: unknown = JSON.parse(scheduledJob.payloadJson);
      expect(scheduledPayload).toEqual({
        ruleId: created.rule.id,
        versionId: created.version.id,
        scheduledFor,
      });
      expect(() =>
        parseQueueJob({
          jobType: "process_automated_badge_rule",
          tenantId: fixture.tenantId,
          payload: scheduledPayload,
          idempotencyKey: scheduledJob.idempotencyKey,
        }),
      ).not.toThrow();
      await fixture.db
        .prepare(
          `
          UPDATE job_queue_messages
          SET status = 'failed', failed_at = ?, attempt_count = max_attempts
          WHERE tenant_id = ?
            AND job_type = 'process_automated_badge_rule'
            AND idempotency_key = ?
        `,
        )
        .bind(scheduledFor, fixture.tenantId, scheduledJob.idempotencyKey)
        .run();

      const retryResult = await processBadgeRuleLifecycleForTenant({
        db: fixture.db,
        tenantId: fixture.tenantId,
        nowIso: scheduledFor,
        observability: { service: "api-worker", environment: "test" },
      });
      const retriedJob = await fixture.db
        .prepare(
          `
          SELECT status, attempt_count AS attemptCount, COUNT(*) OVER ()::text AS totalCount
          FROM job_queue_messages
          WHERE tenant_id = ?
            AND job_type = 'process_automated_badge_rule'
        `,
        )
        .bind(fixture.tenantId)
        .first<{ status: string; attemptCount: number; totalCount: string }>();

      expect(retryResult.automatedEvaluationJobsEnqueued).toBe(1);
      expect(retriedJob).toMatchObject({ status: "pending", attemptCount: 0, totalCount: "1" });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });
});
