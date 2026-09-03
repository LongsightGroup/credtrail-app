import { readFileSync } from "node:fs";
import { createContext, Script } from "node:vm";
import { describe, expect, it } from "vitest";

type AuthoringOutcome = "draft_saved" | "pending_approval" | "approved";
type AuthoringDelivery =
  | { readonly kind: "single_attempt" }
  | {
      readonly kind: "reconciled";
      readonly builderDraftId: string;
      readonly resultApiPath: string;
    };

interface BrowserResponse {
  readonly ok: boolean;
  readonly payload: unknown;
}

interface BrowserRequestInit {
  readonly method: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body?: string;
  readonly signal: AbortSignal;
}

type BrowserRequest = (path: string, init: BrowserRequestInit) => Promise<BrowserResponse>;

interface CompletedAuthoringResult {
  readonly status: "completed";
  readonly outcome: AuthoringOutcome;
  readonly ruleId: string;
  readonly versionId: string;
}

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
    | {
        readonly status: "unknown";
        readonly referenceId: string;
        readonly attemptCount: number;
      }
    | { readonly status: "rejected"; readonly message: string }
    | CompletedAuthoringResult
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
  readonly reconciliationRequestTimeoutMs: number | undefined;
  readonly waitBeforeReplay: (delayMs: number) => Promise<void>;
  readonly onReconciliationStarted: () => void;
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
const completedPayload = (outcome: AuthoringOutcome): unknown => ({
  outcome,
  rule: { id: "brl_saved" },
  version: { id: "brv_saved" },
});
const completedResult = (outcome: AuthoringOutcome): CompletedAuthoringResult => ({
  status: "completed",
  outcome,
  ruleId: "brl_saved",
  versionId: "brv_saved",
});

const createTestController = (input: {
  readonly request: BrowserRequest;
  readonly parseResponse?: (response: BrowserResponse) => Promise<unknown>;
  readonly createRequestId?: () => string;
  readonly reportUnexpectedError?: (error: unknown) => void;
  readonly requestTimeoutMs?: number;
  readonly reconciliationRequestTimeoutMs?: number;
  readonly waitBeforeReplay?: (delayMs: number) => Promise<void>;
  readonly onReconciliationStarted?: () => void;
}): AuthoringController => {
  return authoringModule.createController({
    request: input.request,
    parseResponse: input.parseResponse ?? createResponseParser,
    createRequestId: input.createRequestId ?? (() => "request-1"),
    reportUnexpectedError: input.reportUnexpectedError ?? (() => undefined),
    requestTimeoutMs: input.requestTimeoutMs,
    reconciliationRequestTimeoutMs: input.reconciliationRequestTimeoutMs,
    waitBeforeReplay: input.waitBeforeReplay ?? (() => Promise.resolve()),
    onReconciliationStarted: input.onReconciliationStarted ?? (() => undefined),
  });
};

const singleAttempt: AuthoringDelivery = { kind: "single_attempt" };
const reconciledDelivery: AuthoringDelivery = {
  kind: "reconciled",
  builderDraftId: "brd_123",
  resultApiPath: "/authoring-results/brd_123",
};

describe("rule builder browser authoring controller", () => {
  it.each<{
    readonly action: "save_draft" | "submit_for_approval";
    readonly outcome: AuthoringOutcome;
  }>([
    { action: "save_draft", outcome: "draft_saved" },
    { action: "submit_for_approval", outcome: "pending_approval" },
    { action: "submit_for_approval", outcome: "approved" },
  ])("returns the exact saved resource for $outcome", async ({ action, outcome }) => {
    const requests: Array<{
      readonly path: string;
      readonly headers: Readonly<Record<string, string>>;
      readonly body: string | undefined;
    }> = [];
    const controller = createTestController({
      request: async (path, init) => {
        requests.push({ path, headers: init.headers, body: init.body });
        return { ok: true, payload: completedPayload(outcome) };
      },
    });

    await expect(
      controller.execute({
        apiPath: "/v1/tenants/tenant_123/badge-rules",
        delivery: singleAttempt,
        payload: { name: "Rule", action },
      }),
    ).resolves.toEqual(completedResult(outcome));
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

  it("invokes the injected browser request without rebinding its receiver", async () => {
    const request = async function (
      this: unknown,
      _path: string,
      _init: BrowserRequestInit,
    ): Promise<BrowserResponse> {
      if (this !== undefined) {
        throw new TypeError("Illegal invocation");
      }

      return { ok: true, payload: completedPayload("draft_saved") };
    };
    const controller = createTestController({ request });

    await expect(
      controller.execute({
        apiPath: "/author",
        delivery: singleAttempt,
        payload: { action: "save_draft" },
      }),
    ).resolves.toEqual(completedResult("draft_saved"));
  });

  it("allows another submission if navigation does not follow a completed command", async () => {
    let requestCount = 0;
    const controller = createTestController({
      request: async () => {
        requestCount += 1;
        return { ok: true, payload: completedPayload("draft_saved") };
      },
    });
    const input = {
      apiPath: "/author",
      delivery: singleAttempt,
      payload: { action: "save_draft" },
    } as const;

    await controller.execute(input);
    controller.resetCompleted();
    await expect(controller.execute(input)).resolves.toEqual(completedResult("draft_saved"));
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

    resolveRequest?.({ ok: true, payload: completedPayload("pending_approval") });
    await first;
  });

  it("returns a rejected command to idle so the user can correct and retry", async () => {
    const controller = createTestController({
      request: async () => ({ ok: false, payload: { error: "Policy needs an approval step." } }),
    });

    const result = await controller.execute({
      apiPath: "/author",
      delivery: reconciledDelivery,
      payload: { action: "submit_for_approval" },
    });

    expect(result).toEqual({ status: "rejected", message: "Policy needs an approval step." });
    expect(controller.state()).toBe("idle");
  });

  it("reconciles a committed save after its response is lost", async () => {
    const requests: Array<{ readonly path: string; readonly method: string }> = [];
    let reconciliationStarted = 0;
    const controller = createTestController({
      request: async function (this: unknown, path, init) {
        if (this !== undefined) {
          throw new TypeError("Illegal invocation");
        }

        requests.push({ path, method: init.method });

        if (init.method === "POST") {
          throw new Error("connection lost after commit");
        }

        return {
          ok: true,
          payload: {
            status: "completed",
            outcome: "draft_saved",
            ruleId: "brl_saved",
            versionId: "brv_saved",
          },
        };
      },
      onReconciliationStarted: () => {
        reconciliationStarted += 1;
      },
    });

    await expect(
      controller.execute({
        apiPath: "/author",
        delivery: reconciledDelivery,
        payload: { action: "save_draft" },
      }),
    ).resolves.toEqual(completedResult("draft_saved"));
    expect(requests).toEqual([
      { path: "/author", method: "POST" },
      { path: "/authoring-results/brd_123", method: "GET" },
    ]);
    expect(reconciliationStarted).toBe(1);
    expect(controller.state()).toBe("completed");
  });

  it("checks twice before safely replaying one logical save identity", async () => {
    const requests: Array<{
      readonly path: string;
      readonly method: string;
      readonly body: string | undefined;
    }> = [];
    const delays: number[] = [];
    let postCount = 0;
    const controller = createTestController({
      request: async (path, init) => {
        requests.push({ path, method: init.method, body: init.body });

        if (init.method === "GET") {
          return { ok: true, payload: { status: "pending" } };
        }

        postCount += 1;
        return postCount === 1
          ? { ok: true, payload: null }
          : { ok: true, payload: completedPayload("pending_approval") };
      },
      waitBeforeReplay: async (delayMs) => {
        delays.push(delayMs);
      },
    });

    await expect(
      controller.execute({
        apiPath: "/author",
        delivery: reconciledDelivery,
        payload: { action: "submit_for_approval" },
      }),
    ).resolves.toEqual(completedResult("pending_approval"));
    expect(delays).toEqual([250, 750]);
    expect(requests.map(({ path, method }) => ({ path, method }))).toEqual([
      { path: "/author", method: "POST" },
      { path: "/authoring-results/brd_123", method: "GET" },
      { path: "/authoring-results/brd_123", method: "GET" },
      { path: "/author", method: "POST" },
    ]);
    expect(requests[0]?.body).toBe(
      JSON.stringify({ action: "submit_for_approval", builderDraftId: "brd_123" }),
    );
    expect(requests[3]?.body).toBe(requests[0]?.body);
  });

  it("finds the saved result after the safe replay also loses its response", async () => {
    let postCount = 0;
    let getCount = 0;
    const controller = createTestController({
      request: async (_path, init) => {
        if (init.method === "POST") {
          postCount += 1;
          throw new Error("response unavailable");
        }

        getCount += 1;
        return getCount < 3
          ? { ok: true, payload: { status: "pending" } }
          : {
              ok: true,
              payload: {
                status: "completed",
                outcome: "approved",
                ruleId: "brl_saved",
                versionId: "brv_saved",
              },
            };
      },
    });

    await expect(
      controller.execute({
        apiPath: "/author",
        delivery: reconciledDelivery,
        payload: { action: "submit_for_approval" },
      }),
    ).resolves.toEqual(completedResult("approved"));
    expect(postCount).toBe(2);
    expect(getCount).toBe(3);
  });

  it("returns the stable support reference only after bounded reconciliation fails", async () => {
    let requestCount = 0;
    const delays: number[] = [];
    const controller = createTestController({
      request: async (_path, init) => {
        requestCount += 1;
        return init.method === "GET"
          ? { ok: true, payload: { status: "pending" } }
          : { ok: true, payload: null };
      },
      waitBeforeReplay: async (delayMs) => {
        delays.push(delayMs);
      },
    });

    await expect(
      controller.execute({
        apiPath: "/author",
        delivery: reconciledDelivery,
        payload: { action: "save_draft" },
      }),
    ).resolves.toEqual({
      status: "unknown",
      referenceId: "brd_123",
      attemptCount: 2,
    });
    expect(delays).toEqual([250, 750, 500, 1_000, 2_000]);
    expect(requestCount).toBe(7);
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
    expect(requestCount).toBe(1);
    expect(controller.state()).toBe("idle");
  });

  it("times out a single request and makes the controller retryable", async () => {
    const controller = createTestController({
      request: (_path, init) =>
        new Promise<BrowserResponse>((_resolve, reject) => {
          init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true });
        }),
      requestTimeoutMs: 5,
    });

    await expect(
      controller.execute({
        apiPath: "/author",
        delivery: singleAttempt,
        payload: { action: "save_draft" },
      }),
    ).resolves.toMatchObject({ status: "unknown", attemptCount: 1 });
    expect(controller.state()).toBe("idle");
  });

  it("returns to idle when an injected dependency violates its contract", async () => {
    const controller = createTestController({
      request: async () => ({ ok: true, payload: completedPayload("draft_saved") }),
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
