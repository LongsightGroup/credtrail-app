import { beforeEach, describe, expect, it } from "vitest";
import {
  createQueueIngressTestEnv,
  createQueueIngressTestHarness,
  sampleQueuedIssueMessage,
  sampleQueueIngressApiKey,
} from "./test-support/queue-ingress-harness";

const { app, store } = createQueueIngressTestHarness();

beforeEach(() => {
  store.reset();
});

describe("POST /v1/programmatic/issue and /v1/programmatic/revoke", () => {
  it("queues issue requests with valid API key scope", async () => {
    store.activeApiKey = sampleQueueIngressApiKey();
    const response = await app.request(
      "/v1/programmatic/issue",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": "ctak_example_secret",
        },
        body: JSON.stringify({
          tenantId: "tenant_123",
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "learner@example.edu",
          recipientIdentityType: "email",
          idempotencyKey: "idem_programmatic_issue_123",
        }),
      },
      createQueueIngressTestEnv(),
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(202);
    expect(body.channel).toBe("programmatic_api_key");
    expect(store.enqueuedInputs).toHaveLength(1);
    expect(store.touchedApiKeys).toHaveLength(1);
    expect(store.enqueuedInputs[0]).toMatchObject({
      idempotencyKey: "idem_programmatic_issue_123",
      payload: { requestedByUserId: "usr_admin" },
    });
  });

  it("replays the original queued assertion without reloading mutable template state", async () => {
    store.activeApiKey = sampleQueueIngressApiKey();
    store.existingMessage = sampleQueuedIssueMessage();
    const response = await app.request(
      "/v1/programmatic/issue",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": "ctak_example_secret",
        },
        body: JSON.stringify({
          tenantId: "tenant_123",
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "learner@example.edu",
          recipientIdentityType: "email",
          idempotencyKey: "idem_programmatic_issue_123",
        }),
      },
      createQueueIngressTestEnv(),
    );

    await expect(response.json()).resolves.toMatchObject({
      status: "queued",
      assertionId: "assertion_original",
      idempotencyKey: "idem_programmatic_issue_123",
    });
    expect(response.status).toBe(202);
    expect(store.badgeTemplateLookups).toHaveLength(0);
    expect(store.enqueuedInputs).toHaveLength(0);
  });

  it("returns the command that wins a concurrent idempotency-key insert", async () => {
    store.activeApiKey = sampleQueueIngressApiKey();
    store.nextEnqueueMessage = sampleQueuedIssueMessage();
    const response = await app.request(
      "/v1/programmatic/issue",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": "ctak_example_secret",
        },
        body: JSON.stringify({
          tenantId: "tenant_123",
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "learner@example.edu",
          recipientIdentityType: "email",
          idempotencyKey: "idem_programmatic_issue_123",
        }),
      },
      createQueueIngressTestEnv(),
    );

    expect(response.status).toBe(202);
    await expect(response.json()).resolves.toMatchObject({
      assertionId: "assertion_original",
      idempotencyKey: "idem_programmatic_issue_123",
    });
    expect(store.badgeTemplateLookups).toHaveLength(1);
    expect(store.enqueuedInputs).toHaveLength(1);
  });

  it("rejects an idempotency key reused for a different issuance request", async () => {
    store.activeApiKey = sampleQueueIngressApiKey();
    store.existingMessage = sampleQueuedIssueMessage();
    const response = await app.request(
      "/v1/programmatic/issue",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": "ctak_example_secret",
        },
        body: JSON.stringify({
          tenantId: "tenant_123",
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "different@example.edu",
          recipientIdentityType: "email",
          idempotencyKey: "idem_programmatic_issue_123",
        }),
      },
      createQueueIngressTestEnv(),
    );

    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toEqual({
      error: "This idempotency key is already assigned to a different request",
    });
    expect(store.badgeTemplateLookups).toHaveLength(0);
    expect(store.enqueuedInputs).toHaveLength(0);
  });

  it("rejects programmatic requests when API key is missing", async () => {
    const response = await app.request(
      "/v1/programmatic/revoke",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          tenantId: "tenant_123",
          assertionId: "tenant_123:assertion_456",
          reason: "Requested by issuer",
          idempotencyKey: "idem_programmatic_revoke_123",
        }),
      },
      createQueueIngressTestEnv(),
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(401);
    expect(body.error).toContain("x-api-key");
    expect(store.enqueuedInputs).toHaveLength(0);
  });

  it("rejects programmatic issue requests without an idempotencyKey", async () => {
    store.activeApiKey = sampleQueueIngressApiKey();
    const response = await app.request(
      "/v1/programmatic/issue",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": "ctak_example_secret",
        },
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

    expect(response.status).toBe(400);
    expect(body.error).toBe("Invalid request payload");
    expect(store.enqueuedInputs).toHaveLength(0);
    expect(store.touchedApiKeys).toHaveLength(0);
  });

  it("rejects programmatic write keys without an owning user", async () => {
    store.activeApiKey = sampleQueueIngressApiKey({ createdByUserId: null });
    const response = await app.request(
      "/v1/programmatic/revoke",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": "ctak_example_secret",
        },
        body: JSON.stringify({
          tenantId: "tenant_123",
          assertionId: "tenant_123:assertion_456",
          reason: "Requested by issuer",
          idempotencyKey: "idem_programmatic_revoke_456",
        }),
      },
      createQueueIngressTestEnv(),
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(403);
    expect(body.error).toContain("owning user");
    expect(store.enqueuedInputs).toHaveLength(0);
  });
});
