import { beforeEach, describe, expect, it } from "vitest";
import {
  createQueueIngressTestEnv,
  createQueueIngressTestHarness,
  sampleQueueIngressBadgeTemplate,
} from "./test-support/queue-ingress-harness";

const { app, store } = createQueueIngressTestHarness();

beforeEach(() => {
  store.reset();
});

describe("POST /v1/issue and /v1/revoke", () => {
  it("hides internal queue ingress when JOB_PROCESSOR_TOKEN is not configured", async () => {
    const response = await app.request(
      "/v1/issue",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          tenantId: "tenant_123",
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "learner@example.edu",
          recipientIdentityType: "email",
        }),
      },
      createQueueIngressTestEnv(),
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(404);
    expect(body.error).toBe("Route unavailable");
    expect(store.enqueuedInputs).toHaveLength(0);
  });

  it("stores issue requests as DB-backed queue messages", async () => {
    const response = await app.request(
      "/v1/issue",
      {
        method: "POST",
        headers: {
          authorization: "Bearer processor-secret",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          tenantId: "tenant_123",
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "learner@example.edu",
          recipientIdentityType: "email",
          recipientIdentifiers: [
            {
              identifierType: "studentId",
              identifier: "student-123",
            },
          ],
          recipientDisplayName: "Learner Example",
          issuerImageUri: "https://issuer.example.edu/logo.svg",
          requestedByUserId: "usr_issuer",
        }),
      },
      { ...createQueueIngressTestEnv(), JOB_PROCESSOR_TOKEN: "processor-secret" },
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(202);
    expect(body.status).toBe("queued");
    expect(body.jobType).toBe("issue_badge");
    expect(typeof body.assertionId).toBe("string");
    expect(store.enqueuedInputs).toHaveLength(1);
    expect(store.enqueuedInputs[0]).toMatchObject({
      tenantId: "tenant_123",
      jobType: "issue_badge",
      payload: {
        recipientIdentifiers: [
          {
            identifierType: "studentId",
            identifier: "student-123",
          },
        ],
        recipientDisplayName: "Learner Example",
        issuerImageUri: "https://issuer.example.edu/logo.svg",
      },
    });
  });

  it("rejects templates whose artwork is not managed by CredTrail", async () => {
    store.badgeTemplate = {
      ...sampleQueueIngressBadgeTemplate,
      imageUri: "https://cdn.example/badge.png",
    };
    const response = await app.request(
      "/v1/issue",
      {
        method: "POST",
        headers: {
          authorization: "Bearer processor-secret",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          tenantId: "tenant_123",
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "learner@example.edu",
          recipientIdentityType: "email",
        }),
      },
      { ...createQueueIngressTestEnv(), JOB_PROCESSOR_TOKEN: "processor-secret" },
    );

    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toEqual({
      error: "Upload this badge's artwork in CredTrail before issuing it.",
    });
    expect(store.enqueuedInputs).toHaveLength(0);
  });

  it("rejects templates that do not have approved artwork", async () => {
    store.badgeTemplate = { ...sampleQueueIngressBadgeTemplate, imageUri: null };
    const response = await app.request(
      "/v1/issue",
      {
        method: "POST",
        headers: {
          authorization: "Bearer processor-secret",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          tenantId: "tenant_123",
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "learner@example.edu",
          recipientIdentityType: "email",
        }),
      },
      { ...createQueueIngressTestEnv(), JOB_PROCESSOR_TOKEN: "processor-secret" },
    );

    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toEqual({
      error: "Upload this badge's approved artwork in CredTrail before issuing it.",
    });
    expect(store.enqueuedInputs).toHaveLength(0);
  });

  it("returns 503 when managed artwork storage cannot be checked", async () => {
    const response = await app.request(
      "/v1/issue",
      {
        method: "POST",
        headers: {
          authorization: "Bearer processor-secret",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          tenantId: "tenant_123",
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "learner@example.edu",
          recipientIdentityType: "email",
        }),
      },
      {
        ...createQueueIngressTestEnv(),
        JOB_PROCESSOR_TOKEN: "processor-secret",
        BADGE_OBJECTS: {
          get: async () => {
            throw new Error("R2 unavailable");
          },
          // SAFETY: this failure fixture exercises only the object-read path.
        } as unknown as R2Bucket,
      },
    );

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({
      error: "CredTrail could not check this badge's artwork right now. Try again shortly.",
    });
    expect(store.enqueuedInputs).toHaveLength(0);
  });

  it("stores revoke requests as DB-backed queue messages", async () => {
    const response = await app.request(
      "/v1/revoke",
      {
        method: "POST",
        headers: {
          authorization: "Bearer processor-secret",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          tenantId: "tenant_123",
          assertionId: "tenant_123:assertion_456",
          reason: "Requested by issuer",
          requestedByUserId: "usr_issuer",
        }),
      },
      { ...createQueueIngressTestEnv(), JOB_PROCESSOR_TOKEN: "processor-secret" },
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(202);
    expect(body.status).toBe("queued");
    expect(body.jobType).toBe("revoke_badge");
    expect(typeof body.revocationId).toBe("string");
    expect(store.enqueuedInputs).toHaveLength(1);
    expect(store.enqueuedInputs[0]).toMatchObject({
      tenantId: "tenant_123",
      jobType: "revoke_badge",
    });
  });

  it("rejects internal queue ingress without the processor bearer token", async () => {
    const response = await app.request(
      "/v1/revoke",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          tenantId: "tenant_123",
          assertionId: "tenant_123:assertion_456",
          reason: "Requested by issuer",
        }),
      },
      { ...createQueueIngressTestEnv(), JOB_PROCESSOR_TOKEN: "processor-secret" },
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(401);
    expect(body.error).toBe("Unauthorized");
    expect(store.enqueuedInputs).toHaveLength(0);
  });
});
