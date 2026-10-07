import { beforeEach, describe, expect, it } from "vitest";
import {
  createQueueIngressTestEnv,
  createQueueIngressTestHarness,
  sampleQueuedIssueMessage,
  sampleQueueIngressApiKey,
  sampleQueueIngressBadgeTemplate,
} from "./test-support/queue-ingress-harness";
import { parseQueueJob } from "@credtrail/validation";

const { app, store } = createQueueIngressTestHarness();

beforeEach(() => {
  store.reset();
});

describe("removed internal queue ingress routes", () => {
  it.each(["/v1/issue", "/v1/revoke"])("does not register %s", async (path) => {
    const response = await app.request(
      path,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      },
      createQueueIngressTestEnv(),
    );

    expect(response.status).toBe(404);
  });
});

describe("POST /v1/programmatic/issue and /v1/programmatic/revoke", () => {
  it("rejects a past expiry without persisting a command", async () => {
    store.activeApiKey = sampleQueueIngressApiKey();
    const response = await app.request(
      "/v1/programmatic/issue",
      {
        method: "POST",
        headers: { "content-type": "application/json", "x-api-key": "ctak_example_secret" },
        body: JSON.stringify({
          tenantId: "tenant_123",
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "learner@example.edu",
          recipientIdentityType: "email",
          idempotencyKey: "expiry_past",
          validUntil: "2020-01-01T00:00:00.000Z",
        }),
      },
      createQueueIngressTestEnv(),
    );
    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({
      code: "invalid_expiry",
      error: "Valid until must be later than the issue date.",
    });
    expect(store.enqueuedInputs).toHaveLength(0);
  });

  it.each([
    { persistedExpiry: undefined, requestedExpiry: "2099-12-31T23:59:59.000Z" },
    { persistedExpiry: "2099-12-31T23:59:59.000Z", requestedExpiry: undefined },
    { persistedExpiry: "2099-12-31T23:59:59.000Z", requestedExpiry: "2099-06-30T23:59:59.000Z" },
  ])(
    "rejects reuse of a command key when expiry changes: %j",
    async ({ persistedExpiry, requestedExpiry }) => {
      store.activeApiKey = sampleQueueIngressApiKey();
      const original = sampleQueuedIssueMessage();
      const job = parseQueueJob({
        tenantId: original.tenantId,
        jobType: original.jobType,
        idempotencyKey: original.idempotencyKey,
        payload: JSON.parse(original.payloadJson),
      });
      store.existingMessage = {
        ...original,
        payloadJson: JSON.stringify({ ...job.payload, validUntil: persistedExpiry }),
      };
      const response = await app.request(
        "/v1/programmatic/issue",
        {
          method: "POST",
          headers: { "content-type": "application/json", "x-api-key": "ctak_example_secret" },
          body: JSON.stringify({
            tenantId: "tenant_123",
            badgeTemplateId: "badge_template_001",
            recipientIdentity: "learner@example.edu",
            recipientIdentityType: "email",
            idempotencyKey: original.idempotencyKey,
            validUntil: requestedExpiry,
          }),
        },
        createQueueIngressTestEnv(),
      );
      expect(response.status).toBe(409);
      expect(await response.json()).toMatchObject({ code: "idempotency_conflict" });
      expect(store.enqueuedInputs).toHaveLength(0);
    },
  );

  it("replays a matching command even after its requested expiry has passed", async () => {
    store.activeApiKey = sampleQueueIngressApiKey();
    const original = sampleQueuedIssueMessage();
    const job = parseQueueJob({
      tenantId: original.tenantId,
      jobType: original.jobType,
      idempotencyKey: original.idempotencyKey,
      payload: JSON.parse(original.payloadJson),
    });
    const validUntil = "2020-01-01T00:00:00.000Z";
    store.existingMessage = {
      ...original,
      payloadJson: JSON.stringify({ ...job.payload, validUntil }),
    };
    const response = await app.request(
      "/v1/programmatic/issue",
      {
        method: "POST",
        headers: { "content-type": "application/json", "x-api-key": "ctak_example_secret" },
        body: JSON.stringify({
          tenantId: "tenant_123",
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "learner@example.edu",
          recipientIdentityType: "email",
          idempotencyKey: original.idempotencyKey,
          validUntil,
        }),
      },
      createQueueIngressTestEnv(),
    );
    expect(response.status).toBe(202);
    expect(await response.json()).toMatchObject({ operationId: original.id });
    expect(store.enqueuedInputs).toHaveLength(0);
  });

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
          recipientIdentifiers: [
            {
              identifierType: "studentId",
              identifier: "student-123",
            },
          ],
          recipientDisplayName: "Learner Example",
          issuerImageUri: "https://issuer.example.edu/logo.svg",
          validUntil: "2027-06-30T23:59:59.000Z",
          idempotencyKey: "idem_programmatic_issue_123",
        }),
      },
      createQueueIngressTestEnv(),
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.status).toBe(202);
    expect(body.channel).toBe("programmatic_api_key");
    expect(store.enqueuedInputs).toHaveLength(1);
    expect(store.touchedApiKeys).toHaveLength(1);
    expect(store.enqueuedInputs[0]).toMatchObject({
      idempotencyKey: "idem_programmatic_issue_123",
      payload: {
        requestedByUserId: "usr_admin",
        recipientIdentifiers: [
          {
            identifierType: "studentId",
            identifier: "student-123",
          },
        ],
        recipientDisplayName: "Learner Example",
        issuerImageUri: "https://issuer.example.edu/logo.svg",
        validUntil: "2027-06-30T23:59:59.000Z",
      },
    });
  });

  it.each([
    {
      imageUri: "https://cdn.example/badge.png",
      error: "Upload this badge's artwork in CredTrail before issuing it.",
    },
    {
      imageUri: null,
      error: "Upload this badge's approved artwork in CredTrail before issuing it.",
    },
  ])("rejects an unissuable artwork reference", async ({ imageUri, error }) => {
    store.activeApiKey = sampleQueueIngressApiKey();
    store.badgeTemplate = { ...sampleQueueIngressBadgeTemplate, imageUri };
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

    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toEqual({ code: "artwork_required", error });
    expect(store.enqueuedInputs).toHaveLength(0);
  });

  it("returns 503 when managed artwork storage cannot be checked", async () => {
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
      {
        ...createQueueIngressTestEnv(),
        BADGE_OBJECTS: {
          get: () => Promise.reject(new Error("R2 unavailable")),
          // SAFETY: this failure fixture exercises only the object-read path.
        } as unknown as R2Bucket,
      },
    );

    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({
      code: "storage_unavailable",
      error: "CredTrail could not check this badge's artwork right now. Try again shortly.",
    });
    expect(store.enqueuedInputs).toHaveLength(0);
  });

  it("queues revoke requests with the API key owner as actor", async () => {
    store.activeApiKey = sampleQueueIngressApiKey();
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
          idempotencyKey: "idem_programmatic_revoke_123",
        }),
      },
      createQueueIngressTestEnv(),
    );

    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.status).toBe(202);
    await expect(response.json()).resolves.toMatchObject({
      status: "queued",
      channel: "programmatic_api_key",
      jobType: "revoke_badge",
      assertionId: "tenant_123:assertion_456",
      idempotencyKey: "idem_programmatic_revoke_123",
    });
    expect(store.enqueuedInputs).toHaveLength(1);
    expect(store.enqueuedInputs[0]).toMatchObject({
      tenantId: "tenant_123",
      jobType: "revoke_badge",
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
    expect(response.headers.get("cache-control")).toBe("no-store");
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

    expect(response.headers.get("cache-control")).toBe("no-store");
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

    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toEqual({
      code: "idempotency_conflict",
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

    expect(response.headers.get("cache-control")).toBe("no-store");
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

    expect(response.headers.get("cache-control")).toBe("no-store");
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

    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.status).toBe(403);
    expect(body.error).toContain("owning user");
    expect(store.enqueuedInputs).toHaveLength(0);
  });
});
