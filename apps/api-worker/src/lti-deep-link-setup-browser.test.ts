import { readFileSync } from "node:fs";
import { createContext, Script } from "node:vm";
import { describe, expect, it } from "vitest";
import {
  FakeDocument,
  FakeElement,
  FakeInput,
  FakeSelect,
  FakeTimers,
  waitForBrowserCondition,
} from "./test-support/browser-page-asset-harness";

interface LtiPickerHarness {
  readonly document: FakeDocument;
  readonly itemQuery: FakeInput;
  readonly itemSelect: FakeSelect;
  readonly stateSelect: FakeSelect;
  readonly status: FakeElement;
  readonly statusMessage: FakeElement;
  readonly timers: FakeTimers;
}

const loadLtiPickerHarness = (fetchImpl: typeof fetch): LtiPickerHarness => {
  const payloadParsers = readFileSync(
    new URL("./ui/page-assets/content/js/lms-picker-payload-parsers.js", import.meta.url),
    "utf8",
  );
  const primitives = readFileSync(
    new URL("./ui/page-assets/content/js/lms-gradebook-picker-primitives.js", import.meta.url),
    "utf8",
  );
  const setup = readFileSync(
    new URL("./ui/page-assets/content/js/lti-deep-link-setup.js", import.meta.url),
    "utf8",
  );
  const document = new FakeDocument();
  const container = new FakeElement();
  container.dataset.ltiGradebookSetup = "true";
  container.dataset.ltiGradebookApiBase = "/v1/lti/deep-linking/sessions/session-123";
  const itemSelect = new FakeSelect();
  itemSelect.dataset.ltiGradebookItemSelect = "true";
  const itemQuery = new FakeInput();
  itemQuery.dataset.ltiGradebookItemQuery = "true";
  const stateSelect = new FakeSelect();
  stateSelect.dataset.ltiWorkflowStateSelect = "true";
  const status = new FakeElement();
  status.dataset.ltiGradebookStatus = "true";
  const statusMessage = new FakeElement();
  statusMessage.dataset.ltiGradebookStatusMessage = "true";
  status.append(statusMessage);
  container.append(itemSelect, itemQuery, stateSelect, status);
  document.append(container);
  const timers = new FakeTimers();
  const window = {
    clearTimeout: timers.clearTimeout,
    setTimeout: timers.setTimeout,
  };
  const context = createContext({
    AbortController,
    AbortSignal,
    console,
    document,
    fetch: fetchImpl,
    HTMLElement: FakeElement,
    HTMLInputElement: FakeInput,
    HTMLSelectElement: FakeSelect,
    Response,
    window,
  });

  new Script(`${payloadParsers}\n${primitives}\n${setup}`).runInContext(context);
  document.dispatch("DOMContentLoaded");

  return { document, itemQuery, itemSelect, stateSelect, status, statusMessage, timers };
};

describe("LTI Deep Linking gradebook picker", () => {
  it("hydrates items on load and workflow states after an assignment change", async () => {
    const requestedUrls: string[] = [];
    const fetchImpl = ((input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = input instanceof Request ? input.url : input instanceof URL ? input.href : input;
      requestedUrls.push(url);
      expect(init?.cache).toBe("no-store");

      if (url.endsWith("/gradebook-items")) {
        return Promise.resolve(
          Response.json({ items: [{ assignmentId: "assignment-1", title: "Assignment 1" }] }),
        );
      }

      if (url.endsWith("/gradebook-items/assignment-1/workflow-states")) {
        return Promise.resolve(
          Response.json({ states: [{ value: "graded", label: "Graded", preselected: true }] }),
        );
      }

      return Promise.reject(new Error(`Unexpected LTI picker request: ${url}`));
    }) as typeof fetch;
    const harness = loadLtiPickerHarness(fetchImpl);

    harness.timers.runAll();
    await waitForBrowserCondition(
      () => harness.itemSelect.options.some((option) => option.value === "assignment-1"),
      "LTI gradebook items did not load",
    );

    expect(harness.itemSelect.options.map((option) => option.value)).toEqual(["", "assignment-1"]);
    expect(harness.stateSelect.disabled).toBe(true);
    harness.itemSelect.value = "assignment-1";
    harness.itemSelect.dispatch("change");
    await waitForBrowserCondition(
      () => harness.stateSelect.options.some((option) => option.value === "graded"),
      "LTI workflow states did not load",
    );

    expect(harness.stateSelect.value).toBe("graded");
    expect(requestedUrls).toEqual([
      "/v1/lti/deep-linking/sessions/session-123/gradebook-items",
      "/v1/lti/deep-linking/sessions/session-123/gradebook-items/assignment-1/workflow-states",
    ]);
  });

  it("keeps the latest search and workflow-state responses", async () => {
    let initialItemsAborted = false;
    let oldWorkflowAborted = false;
    const fetchImpl = ((input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = input instanceof Request ? input.url : input instanceof URL ? input.href : input;

      if (url.endsWith("/gradebook-items")) {
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            initialItemsAborted = true;
            reject(new Error("aborted"));
          });
        });
      }

      if (url.endsWith("/gradebook-items?q=new")) {
        return Promise.resolve(
          Response.json({
            items: [
              { assignmentId: "old-item", title: "Old item" },
              { assignmentId: "new-item", title: "New item" },
            ],
          }),
        );
      }

      if (url.endsWith("/gradebook-items/old-item/workflow-states")) {
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            oldWorkflowAborted = true;
            reject(new Error("aborted"));
          });
        });
      }

      if (url.endsWith("/gradebook-items/new-item/workflow-states")) {
        return Promise.resolve(
          Response.json({ states: [{ value: "released", label: "Released" }] }),
        );
      }

      return Promise.reject(new Error(`Unexpected LTI picker request: ${url}`));
    }) as typeof fetch;
    const harness = loadLtiPickerHarness(fetchImpl);

    harness.timers.runAll();
    harness.itemQuery.value = "new";
    harness.itemQuery.dispatch("input");
    harness.timers.runAll();
    await waitForBrowserCondition(
      () => harness.itemSelect.options.some((option) => option.value === "new-item"),
      "Updated LTI gradebook items did not load",
    );

    expect(initialItemsAborted).toBe(true);
    harness.itemSelect.value = "old-item";
    harness.itemSelect.dispatch("change");
    harness.itemSelect.value = "new-item";
    harness.itemSelect.dispatch("change");
    await waitForBrowserCondition(
      () => harness.stateSelect.options.some((option) => option.value === "released"),
      "Updated LTI workflow states did not load",
    );

    expect(oldWorkflowAborted).toBe(true);
    expect(harness.stateSelect.options.map((option) => option.value)).toEqual(["", "released"]);
  });

  it("keeps loaded items and localizes a workflow-state failure", async () => {
    const fetchImpl = ((input: RequestInfo | URL): Promise<Response> => {
      const url = input instanceof Request ? input.url : input instanceof URL ? input.href : input;

      if (url.endsWith("/gradebook-items")) {
        return Promise.resolve(
          Response.json({ items: [{ assignmentId: "assignment-1", title: "Assignment 1" }] }),
        );
      }

      if (url.endsWith("/gradebook-items/assignment-1/workflow-states")) {
        return Promise.resolve(
          Response.json({ error: "Sakai workflow states denied." }, { status: 403 }),
        );
      }

      return Promise.reject(new Error(`Unexpected LTI picker request: ${url}`));
    }) as typeof fetch;
    const harness = loadLtiPickerHarness(fetchImpl);

    harness.timers.runAll();
    await waitForBrowserCondition(
      () => harness.itemSelect.options.some((option) => option.value === "assignment-1"),
      "LTI gradebook items did not load",
    );
    harness.itemSelect.value = "assignment-1";
    harness.itemSelect.dispatch("change");
    await waitForBrowserCondition(
      () => harness.statusMessage.textContent === "Sakai workflow states denied.",
      "LTI workflow-state failure was not reported",
    );

    expect(harness.itemSelect.options.map((option) => option.value)).toEqual(["", "assignment-1"]);
    expect(harness.stateSelect.options.map((option) => option.textContent)).toEqual([
      "Workflow states unavailable",
    ]);
    expect(harness.status.hidden).toBe(false);
    expect(harness.status.dataset.tone).toBe("error");
  });
});
