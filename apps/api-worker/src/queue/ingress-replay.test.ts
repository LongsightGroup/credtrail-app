import type { JobQueueMessageRecord } from "@credtrail/db";
import { describe, expect, it } from "vitest";
import { replayIssueBadgeQueueMessage, replayRevokeBadgeQueueMessage } from "./ingress-replay";

const persistedMessage = (payload: unknown): JobQueueMessageRecord => ({
  id: "job_123",
  tenantId: "tenant_123",
  jobType: "issue_badge",
  payloadJson: JSON.stringify(payload),
  idempotencyKey: "idem_123",
  attemptCount: 0,
  maxAttempts: 8,
  availableAt: "2026-08-12T12:00:00.000Z",
  leasedUntil: null,
  leaseToken: null,
  lastError: null,
  completedAt: null,
  failedAt: null,
  status: "pending",
  createdAt: "2026-08-12T12:00:00.000Z",
  updatedAt: "2026-08-12T12:00:00.000Z",
});

const payload = {
  assertionId: "assertion_original",
  achievementSource: {
    kind: "template_snapshot",
    snapshot: {
      badgeTemplateId: "badge_template_001",
      title: "Original badge",
      description: null,
      criteriaUri: null,
      imageUri: null,
      trustedCredentialMetadataJson: null,
    },
    provenance: { source: "programmatic" },
  },
  recipientIdentity: "learner@example.edu",
  recipientIdentityType: "email",
  requestedAt: "2026-08-12T12:00:00.000Z",
  requestedByUserId: "usr_admin",
};

const persistedRevokeMessage = (): JobQueueMessageRecord => ({
  ...persistedMessage({
    assertionId: "tenant_123:assertion_456",
    revocationId: "revocation_original",
    reason: "Requested by issuer",
    requestedAt: "2026-08-12T12:00:00.000Z",
    requestedByUserId: "usr_admin",
  }),
  jobType: "revoke_badge",
});

describe("queue ingress replay", () => {
  it("returns the original assertion identity without consulting current template state", () => {
    const result = replayIssueBadgeQueueMessage({
      message: persistedMessage(payload),
      request: {
        tenantId: "tenant_123",
        badgeTemplateId: "badge_template_001",
        recipientIdentity: "learner@example.edu",
        recipientIdentityType: "email",
        idempotencyKey: "idem_123",
      },
      requestedByUserId: "usr_admin",
    });

    expect(result).toMatchObject({
      status: "matched",
      envelope: {
        assertionId: "assertion_original",
        job: {
          payload: {
            achievementSource: payload.achievementSource,
          },
        },
      },
    });
  });

  it("rejects reuse of an idempotency key for a different logical request", () => {
    expect(
      replayIssueBadgeQueueMessage({
        message: persistedMessage(payload),
        request: {
          tenantId: "tenant_123",
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "different@example.edu",
          recipientIdentityType: "email",
          idempotencyKey: "idem_123",
        },
        requestedByUserId: "usr_admin",
      }),
    ).toEqual({ status: "conflict" });
  });

  it("returns the original revocation identity for a matching retry", () => {
    expect(
      replayRevokeBadgeQueueMessage({
        message: persistedRevokeMessage(),
        request: {
          tenantId: "tenant_123",
          assertionId: "tenant_123:assertion_456",
          reason: "Requested by issuer",
          idempotencyKey: "idem_123",
        },
        requestedByUserId: "usr_admin",
      }),
    ).toMatchObject({
      status: "matched",
      envelope: {
        revocationId: "revocation_original",
      },
    });
  });

  it("rejects a revocation retry whose reason changed", () => {
    expect(
      replayRevokeBadgeQueueMessage({
        message: persistedRevokeMessage(),
        request: {
          tenantId: "tenant_123",
          assertionId: "tenant_123:assertion_456",
          reason: "Different reason",
          idempotencyKey: "idem_123",
        },
        requestedByUserId: "usr_admin",
      }),
    ).toEqual({ status: "conflict" });
  });
});
