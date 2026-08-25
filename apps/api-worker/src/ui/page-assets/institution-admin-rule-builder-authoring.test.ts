import { readFileSync } from "node:fs";
import { createContext, Script } from "node:vm";
import { describe, expect, it } from "vitest";

type AuthoringOutcome = "draft_saved" | "pending_approval" | "approved";
type AuthoringDelivery =
  | { readonly kind: "single_attempt" }
  | { readonly kind: "replay_safe_create"; readonly builderDraftId: string };

interface BrowserResponse {
  readonly ok: boolean;
  readonly payload: unknown;
}

interface BrowserRequestInit {
  readonly method: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
  readonly signal: AbortSignal;
}

type BrowserRequest = (path: string, init: BrowserRequestInit) => Promise<BrowserResponse>;

interface AuthoringController {
  readonly execute: (input: {
    readonly apiPath: string;
    readonly delivery: AuthoringDelivery;
    readonly payload: Readonly<Record<string, unknown>>;
  }) => Promise<
    | { readonly status: "ignored" }
    | {
        readonly status: "unknown";
        readonly requestId: string;
        readonly attemptCount: number;
      }
    | { readonly status: "rejected"; readonly message: string }
    | { readonly status: "completed"; readonly outcome: AuthoringOutcome }
  >;
  readonly resetCompleted: () => void;
  readonly state: () => "idle" | "submitting" | "completed";
}

interface AuthoringControllerDependencies {
  readonly request: BrowserRequest;
  readonly parseResponse: (response: BrowserResponse) => Promise<unknown>;
  readonly createRequestId: () => string;
  readonly reportUnexpectedError: (error: unknown) => void;
  readonly requestTimeoutMs: number | undefined;
  readonly waitBeforeReplay: (delayMs: number) => Promise<void>;
}

interface RuleBuilderAuthoringModule {
  readonly createController: (dependencies: AuthoringControllerDependencies) => AuthoringController;
}

const loadRuleBuilderAuthoringModule = (): RuleBuilderAuthoringModule => {
  const source = readFileSync(
    new URL("./content/js/institution-admin-rule-builder-authoring.js", import.meta.url),
    "utf8",
  );
  const context = createContext({ AbortSignal });
  new Script(
    `${source}\nthis.createController = createRuleBuilderAuthoringController;`,
  ).runInContext(context);
  const loaded = context as {
    readonly createController?: unknown;
  };

  if (typeof loaded.createController !== "function") {
    throw new Error("Rule builder authoring controller did not load");
  }

  // SAFETY: The VM source defines the function, and the runtime guard verifies its callable boundary.
  return loaded as RuleBuilderAuthoringModule;
};

const authoringModule = loadRuleBuilderAuthoringModule();
const createResponseParser = async (response: BrowserResponse): Promise<unknown> => {
  return response.payload;
};

const createTestController = (input: {
  readonly request: BrowserRequest;
  readonly parseResponse?: (response: BrowserResponse) => Promise<unknown>;
  readonly createRequestId?: () => string;
  readonly reportUnexpectedError?: (error: unknown) => void;
  readonly requestTimeoutMs?: number;
  readonly waitBeforeReplay?: (delayMs: number) => Promise<void>;
}): AuthoringController => {
  return authoringModule.createController({
    request: input.request,
    parseResponse: input.parseResponse ?? createResponseParser,
    createRequestId: input.createRequestId ?? (() => "request-1"),
    reportUnexpectedError: input.reportUnexpectedError ?? (() => undefined),
    requestTimeoutMs: input.requestTimeoutMs,
    waitBeforeReplay: input.waitBeforeReplay ?? (() => Promise.resolve()),
  });
};

const singleAttempt: AuthoringDelivery = { kind: "single_attempt" };

describe("rule builder browser authoring controller", () => {
  it.each<{
    readonly action: "save_draft" | "submit_for_approval";
    readonly outcome: AuthoringOutcome;
  }>([
    { action: "save_draft", outcome: "draft_saved" },
    { action: "submit_for_approval", outcome: "pending_approval" },
    { action: "submit_for_approval", outcome: "approved" },
  ])("sends one $action command and returns $outcome", async ({ action, outcome }) => {
    const requests: Array<{
      readonly path: string;
      readonly headers: Readonly<Record<string, string>>;
      readonly body: string;
    }> = [];
    const controller = createTestController({
      request: async (path, init) => {
        requests.push({ path, headers: init.headers, body: init.body });
        return { ok: true, payload: { outcome } };
      },
    });

    const result = await controller.execute({
      apiPath: "/v1/tenants/tenant_123/badge-rules",
      delivery: singleAttempt,
      payload: { name: "Rule", action },
    });

    expect(result.status).toBe("completed");
    expect(result.status === "completed" ? result.outcome : null).toBe(outcome);
    expect(requests).toEqual([
      {
        path: "/v1/tenants/tenant_123/badge-rules",
        headers: {
          "content-type": "application/json",
          "x-request-id": "request-1",
        },
        body: JSON.stringify({ name: "Rule", action }),
      },
    ]);
    expect(controller.state()).toBe("completed");
  });

  it("allows another submission if navigation does not follow a completed command", async () => {
    let requestCount = 0;
    const controller = createTestController({
      request: async () => {
        requestCount += 1;
        return { ok: true, payload: { outcome: "draft_saved" } };
      },
    });
    const input = {
      apiPath: "/author",
      delivery: singleAttempt,
      payload: { action: "save_draft" },
    } as const;

    await controller.execute(input);
    controller.resetCompleted();
    const retried = await controller.execute(input);

    expect(retried).toEqual({ status: "completed", outcome: "draft_saved" });
    expect(requestCount).toBe(2);
  });

  it("ignores a concurrent submission while the first request is pending", async () => {
    let resolveRequest: ((response: BrowserResponse) => void) | undefined;
    let requestCount = 0;
    const controller = createTestController({
      request: () => {
        requestCount += 1;
        return new Promise<BrowserResponse>((resolve) => {
          resolveRequest = resolve;
        });
      },
    });
    const input = {
      apiPath: "/author",
      delivery: singleAttempt,
      payload: { action: "submit_for_approval" },
    } as const;

    const first = controller.execute(input);
    const second = await controller.execute(input);

    expect(controller.state()).toBe("submitting");
    expect(second.status).toBe("ignored");
    expect(requestCount).toBe(1);

    resolveRequest?.({ ok: true, payload: { outcome: "pending_approval" } });
    await first;
  });

  it("returns a rejected command to idle so the user can correct and retry", async () => {
    const controller = createTestController({
      request: async () => ({ ok: false, payload: { error: "Policy needs an approval step." } }),
    });

    const result = await controller.execute({
      apiPath: "/author",
      delivery: singleAttempt,
      payload: { action: "submit_for_approval" },
    });

    expect(result.status).toBe("rejected");
    expect(result.status === "rejected" ? result.message : "").toContain("approval step");
    expect(controller.state()).toBe("idle");
  });

  it("reports request failures before returning an unknown outcome", async () => {
    const defect = new Error("connection unavailable");
    const reportedErrors: unknown[] = [];
    const controller = createTestController({
      request: () => Promise.reject(defect),
      reportUnexpectedError: (error) => {
        reportedErrors.push(error);
      },
    });

    await expect(
      controller.execute({
        apiPath: "/author",
        delivery: singleAttempt,
        payload: { action: "save_draft" },
      }),
    ).resolves.toMatchObject({ status: "unknown" });
    expect(reportedErrors).toEqual([defect]);
  });

  it("reports response parsing failures before returning an unknown outcome", async () => {
    const defect = new Error("response body unavailable");
    const reportedErrors: unknown[] = [];
    const controller = createTestController({
      request: async () => ({ ok: true, payload: { outcome: "draft_saved" } }),
      parseResponse: () => Promise.reject(defect),
      reportUnexpectedError: (error) => {
        reportedErrors.push(error);
      },
    });

    await expect(
      controller.execute({
        apiPath: "/author",
        delivery: singleAttempt,
        payload: { action: "save_draft" },
      }),
    ).resolves.toMatchObject({ status: "unknown" });
    expect(reportedErrors).toEqual([defect]);
  });

  it("times out a request that never returns and makes the controller retryable", async () => {
    const controller = createTestController({
      request: (_path, init) => {
        return new Promise<BrowserResponse>((_resolve, reject) => {
          init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true });
        });
      },
      requestTimeoutMs: 5,
    });

    await expect(
      controller.execute({
        apiPath: "/author",
        delivery: singleAttempt,
        payload: { action: "save_draft" },
      }),
    ).resolves.toEqual({
      status: "unknown",
      requestId: "request-1",
      attemptCount: 1,
    });
    expect(controller.state()).toBe("idle");
  });

  it("retries a replay-safe create with one logical identity and fresh request IDs", async () => {
    let requestCount = 0;
    let requestIdSequence = 0;
    const requests: Array<{
      readonly path: string;
      readonly headers: Readonly<Record<string, string>>;
      readonly body: string;
    }> = [];
    const controller = createTestController({
      request: async (path, init) => {
        requestCount += 1;
        requests.push({ path, headers: init.headers, body: init.body });

        if (requestCount === 1) {
          throw new Error("connection lost after commit");
        }

        return { ok: true, payload: { outcome: "pending_approval" } };
      },
      createRequestId: () => {
        requestIdSequence += 1;
        return `request-${requestIdSequence}`;
      },
    });

    const result = await controller.execute({
      apiPath: "/author",
      delivery: { kind: "replay_safe_create", builderDraftId: "brd-123" },
      payload: { action: "submit_for_approval" },
    });

    expect(result).toEqual({ status: "completed", outcome: "pending_approval" });
    expect(requests).toEqual([
      {
        path: "/author",
        headers: {
          "content-type": "application/json",
          "x-request-id": "request-1",
        },
        body: JSON.stringify({ action: "submit_for_approval", builderDraftId: "brd-123" }),
      },
      {
        path: "/author",
        headers: {
          "content-type": "application/json",
          "x-request-id": "request-2",
        },
        body: JSON.stringify({ action: "submit_for_approval", builderDraftId: "brd-123" }),
      },
    ]);
    expect(controller.state()).toBe("completed");
  });

  it("waits briefly before replaying an unconfirmed create", async () => {
    let requestCount = 0;
    const operationOrder: string[] = [];
    const controller = createTestController({
      request: async () => {
        requestCount += 1;
        operationOrder.push(`request:${requestCount}`);
        return requestCount === 1
          ? { ok: true, payload: null }
          : { ok: true, payload: { outcome: "draft_saved" } };
      },
      waitBeforeReplay: async (delayMs) => {
        operationOrder.push(`wait:${delayMs}`);
      },
    });

    await expect(
      controller.execute({
        apiPath: "/author",
        delivery: { kind: "replay_safe_create", builderDraftId: "brd-123" },
        payload: { action: "save_draft" },
      }),
    ).resolves.toEqual({ status: "completed", outcome: "draft_saved" });
    expect(operationOrder).toEqual(["request:1", "wait:250", "request:2"]);
  });

  it("retries a replay-safe create when a successful response body is malformed", async () => {
    let requestCount = 0;
    const controller = createTestController({
      request: async () => {
        requestCount += 1;
        return requestCount === 1
          ? { ok: true, payload: null }
          : { ok: true, payload: { outcome: "draft_saved" } };
      },
      createRequestId: () => `request-${requestCount + 1}`,
    });

    const result = await controller.execute({
      apiPath: "/author",
      delivery: { kind: "replay_safe_create", builderDraftId: "brd-123" },
      payload: { action: "save_draft" },
    });

    expect(result).toEqual({ status: "completed", outcome: "draft_saved" });
    expect(requestCount).toBe(2);
    expect(controller.state()).toBe("completed");
  });

  it("retries a replay-safe create when parsing the first response fails", async () => {
    let parseCount = 0;
    let requestCount = 0;
    const controller = createTestController({
      request: async () => {
        requestCount += 1;
        return { ok: true, payload: { outcome: "draft_saved" } };
      },
      parseResponse: async (response) => {
        parseCount += 1;

        if (parseCount === 1) {
          throw new Error("response body unavailable");
        }

        return response.payload;
      },
      createRequestId: () => `request-${requestCount + 1}`,
    });

    const result = await controller.execute({
      apiPath: "/author",
      delivery: { kind: "replay_safe_create", builderDraftId: "brd-123" },
      payload: { action: "save_draft" },
    });

    expect(result).toEqual({ status: "completed", outcome: "draft_saved" });
    expect(requestCount).toBe(2);
    expect(parseCount).toBe(2);
  });

  it("retries an unrecognized gateway response for a replay-safe create", async () => {
    let requestCount = 0;
    const controller = createTestController({
      request: async () => {
        requestCount += 1;
        return requestCount === 1
          ? { ok: false, payload: null }
          : { ok: true, payload: { outcome: "draft_saved" } };
      },
      createRequestId: () => `request-${requestCount + 1}`,
    });

    const result = await controller.execute({
      apiPath: "/author",
      delivery: { kind: "replay_safe_create", builderDraftId: "brd-123" },
      payload: { action: "save_draft" },
    });

    expect(result).toEqual({ status: "completed", outcome: "draft_saved" });
    expect(requestCount).toBe(2);
  });

  it("does not retry a structured CredTrail server rejection", async () => {
    let requestCount = 0;
    const controller = createTestController({
      request: async () => {
        requestCount += 1;
        return {
          ok: false,
          payload: {
            error: "CredTrail could not check this badge's artwork right now.",
          },
        };
      },
    });

    const result = await controller.execute({
      apiPath: "/author",
      delivery: { kind: "replay_safe_create", builderDraftId: "brd-123" },
      payload: { action: "save_draft" },
    });

    expect(result).toEqual({
      status: "rejected",
      message: "CredTrail could not check this badge's artwork right now.",
    });
    expect(requestCount).toBe(1);
    expect(controller.state()).toBe("idle");
  });

  it("reports the terminal attempt after both replay-safe requests lose their responses", async () => {
    let requestCount = 0;
    const controller = createTestController({
      request: async () => {
        requestCount += 1;
        throw new Error("connection unavailable");
      },
      createRequestId: () => `request-${requestCount + 1}`,
    });

    const result = await controller.execute({
      apiPath: "/author",
      delivery: { kind: "replay_safe_create", builderDraftId: "brd-123" },
      payload: { action: "save_draft" },
    });

    expect(result).toEqual({
      status: "unknown",
      requestId: "request-2",
      attemptCount: 2,
    });
    expect(requestCount).toBe(2);
    expect(controller.state()).toBe("idle");
  });

  it("does not retry a command with the single-attempt delivery policy", async () => {
    let requestCount = 0;
    const controller = createTestController({
      request: async () => {
        requestCount += 1;
        throw new Error("connection unavailable");
      },
    });

    const result = await controller.execute({
      apiPath: "/author",
      delivery: singleAttempt,
      payload: { action: "save_draft", builderDraftId: "ignored-payload-convention" },
    });

    expect(result).toEqual({
      status: "unknown",
      requestId: "request-1",
      attemptCount: 1,
    });
    expect(requestCount).toBe(1);
    expect(controller.state()).toBe("idle");
  });

  it("returns to idle when response parsing cannot confirm the outcome", async () => {
    const controller = createTestController({
      request: async () => ({ ok: true, payload: null }),
      parseResponse: () => Promise.reject(new Error("response body unavailable")),
    });

    await expect(
      controller.execute({
        apiPath: "/author",
        delivery: singleAttempt,
        payload: { action: "save_draft" },
      }),
    ).resolves.toEqual({
      status: "unknown",
      requestId: "request-1",
      attemptCount: 1,
    });
    expect(controller.state()).toBe("idle");
  });

  it("returns to idle when an injected dependency violates its contract", async () => {
    const controller = createTestController({
      request: async () => ({ ok: true, payload: { outcome: "draft_saved" } }),
      createRequestId: () => {
        throw new Error("request ID generator defect");
      },
    });

    await expect(
      controller.execute({
        apiPath: "/author",
        delivery: singleAttempt,
        payload: { action: "save_draft" },
      }),
    ).rejects.toThrow("request ID generator defect");
    expect(controller.state()).toBe("idle");
  });
});
