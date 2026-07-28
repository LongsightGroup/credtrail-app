import { readFileSync } from "node:fs";
import { createContext, Script } from "node:vm";
import { describe, expect, it } from "vitest";

type AuthoringOutcome = "draft_saved" | "pending_approval" | "approved";

interface BrowserResponse {
  readonly ok: boolean;
  readonly payload: unknown;
}

interface AuthoringController {
  readonly execute: (input: {
    readonly apiPath: string;
    readonly payload: Readonly<Record<string, unknown>>;
    readonly prepareRequest?: () => Promise<boolean>;
  }) => Promise<
    | { readonly status: "ignored" | "precondition_failed" | "unknown" }
    | { readonly status: "rejected"; readonly message: string }
    | { readonly status: "completed"; readonly outcome: AuthoringOutcome }
  >;
  readonly state: () => "idle" | "submitting" | "completed" | "unknown";
}

type CreateAuthoringController = (dependencies: {
  readonly request: (
    path: string,
    init: { readonly method: string; readonly body: string },
  ) => Promise<BrowserResponse>;
  readonly parseResponse: (response: BrowserResponse) => Promise<unknown>;
  readonly errorMessage: (payload: unknown) => string;
}) => AuthoringController;

const loadCreateAuthoringController = (): CreateAuthoringController => {
  const source = readFileSync(
    new URL("./content/js/institution-admin-rule-builder-authoring.js", import.meta.url),
    "utf8",
  );
  const context = createContext({});
  new Script(
    `${source}\nthis.createController = createRuleBuilderAuthoringController;`,
  ).runInContext(context);
  const createController = (context as { createController?: unknown }).createController;

  if (typeof createController !== "function") {
    throw new Error("Rule builder authoring controller did not load");
  }

  // SAFETY: The VM source defines this function, and the runtime guard above verifies its callable boundary.
  return createController as CreateAuthoringController;
};

const createResponseParser = async (response: BrowserResponse): Promise<unknown> => {
  return response.payload;
};

describe("rule builder browser authoring controller", () => {
  it.each<{
    readonly action: "save_draft" | "submit_for_approval";
    readonly outcome: AuthoringOutcome;
  }>([
    { action: "save_draft", outcome: "draft_saved" },
    { action: "submit_for_approval", outcome: "pending_approval" },
    { action: "submit_for_approval", outcome: "approved" },
  ])("sends one $action command and returns $outcome", async ({ action, outcome }) => {
    const requests: Array<{ readonly path: string; readonly body: string }> = [];
    const controller = loadCreateAuthoringController()({
      request: async (path, init) => {
        requests.push({ path, body: init.body });
        return { ok: true, payload: { outcome } };
      },
      parseResponse: createResponseParser,
      errorMessage: () => "request rejected",
    });

    const result = await controller.execute({
      apiPath: "/v1/tenants/tenant_123/badge-rules",
      payload: { name: "Rule", action },
    });

    expect(result.status).toBe("completed");
    expect(result.status === "completed" ? result.outcome : null).toBe(outcome);
    expect(requests).toHaveLength(1);
    expect(requests[0]?.path).toBe("/v1/tenants/tenant_123/badge-rules");
    expect(JSON.parse(requests[0]?.body ?? "{}")).toMatchObject({ action });
    expect(controller.state()).toBe("completed");
  });

  it("ignores a concurrent submission while the first request is pending", async () => {
    let resolveRequest: ((response: BrowserResponse) => void) | undefined;
    let requestCount = 0;
    const controller = loadCreateAuthoringController()({
      request: () => {
        requestCount += 1;
        return new Promise<BrowserResponse>((resolve) => {
          resolveRequest = resolve;
        });
      },
      parseResponse: createResponseParser,
      errorMessage: () => "request rejected",
    });

    const first = controller.execute({
      apiPath: "/author",
      payload: { action: "submit_for_approval" },
    });
    const second = await controller.execute({
      apiPath: "/author",
      payload: { action: "submit_for_approval" },
    });

    expect(controller.state()).toBe("submitting");
    expect(second.status).toBe("ignored");
    expect(requestCount).toBe(1);

    resolveRequest?.({ ok: true, payload: { outcome: "pending_approval" } });
    await first;
  });

  it("returns a rejected command to idle so the user can correct and retry", async () => {
    const controller = loadCreateAuthoringController()({
      request: async () => ({ ok: false, payload: { error: "Policy needs an approval step." } }),
      parseResponse: createResponseParser,
      errorMessage: (payload) =>
        typeof payload === "object" &&
        payload !== null &&
        "error" in payload &&
        typeof payload.error === "string"
          ? payload.error
          : "request rejected",
    });

    const result = await controller.execute({
      apiPath: "/author",
      payload: { action: "submit_for_approval" },
    });

    expect(result.status).toBe("rejected");
    expect(result.status === "rejected" ? result.message : "").toContain("approval step");
    expect(controller.state()).toBe("idle");
  });

  it("does not send the command when unfinished-work persistence fails", async () => {
    let requestCount = 0;
    const controller = loadCreateAuthoringController()({
      request: async () => {
        requestCount += 1;
        return { ok: true, payload: { outcome: "draft_saved" } };
      },
      parseResponse: createResponseParser,
      errorMessage: () => "request rejected",
    });

    const result = await controller.execute({
      apiPath: "/author",
      payload: { action: "save_draft" },
      prepareRequest: async () => false,
    });

    expect(result.status).toBe("precondition_failed");
    expect(requestCount).toBe(0);
    expect(controller.state()).toBe("idle");
  });

  it("locks retries when the browser cannot determine the command outcome", async () => {
    const controller = loadCreateAuthoringController()({
      request: async () => {
        throw new Error("connection lost");
      },
      parseResponse: createResponseParser,
      errorMessage: () => "request rejected",
    });

    const result = await controller.execute({
      apiPath: "/author",
      payload: { action: "submit_for_approval" },
    });

    expect(result.status).toBe("unknown");
    expect(controller.state()).toBe("unknown");
  });
});
