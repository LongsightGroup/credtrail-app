import { readFileSync } from "node:fs";
import { createContext, Script } from "node:vm";
import { describe, expect, it } from "vitest";

type BrowserListener = () => void;

class FakeElement {
  public readonly dataset: Record<string, string> = {};
  public hidden = false;
  public textContent: string | null = "";
  private readonly children: FakeElement[] = [];
  private readonly listeners = new Map<string, BrowserListener[]>();

  public append(...children: FakeElement[]): void {
    this.children.push(...children);
  }

  public addEventListener(type: string, listener: BrowserListener): void {
    const listeners = this.listeners.get(type) ?? [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }

  public dispatch(type: string): void {
    for (const listener of this.listeners.get(type) ?? []) {
      listener();
    }
  }

  public querySelector(selector: string): FakeElement | null {
    return this.querySelectorAll(selector)[0] ?? null;
  }

  public querySelectorAll(selector: string): readonly FakeElement[] {
    return this.children.flatMap((child) => [
      ...(child.matches(selector) ? [child] : []),
      ...child.querySelectorAll(selector),
    ]);
  }

  private matches(selector: string): boolean {
    const match = selector.match(/^\[data-([a-z-]+)\]$/);
    const attributeName = match?.[1];

    if (attributeName === undefined) {
      return false;
    }

    const datasetName = attributeName.replace(/-([a-z])/g, (_entry, letter: string) =>
      letter.toUpperCase(),
    );
    return datasetName in this.dataset;
  }
}

class FakeOption extends FakeElement {
  public disabled = false;
  public selected = false;
  public value = "";
}

class FakeInput extends FakeElement {
  public value = "";
}

class FakeSelect extends FakeElement {
  public disabled = false;
  public required = false;
  public options: FakeOption[] = [];

  public get selectedOptions(): readonly FakeOption[] {
    return this.options.filter((option) => option.selected);
  }

  public get value(): string {
    return this.selectedOptions[0]?.value ?? "";
  }

  public set value(value: string) {
    for (const option of this.options) {
      option.selected = option.value === value;
    }
  }

  public replaceChildren(...options: FakeOption[]): void {
    this.options = [...options];
  }
}

class FakeDocument extends FakeElement {
  public createElement(tagName: string): FakeElement {
    return tagName.toLowerCase() === "option" ? new FakeOption() : new FakeElement();
  }
}

class FakeTimers {
  private nextId = 1;
  private readonly callbacks = new Map<number, BrowserListener>();

  public readonly setTimeout = (callback: BrowserListener): number => {
    const id = this.nextId;
    this.nextId += 1;
    this.callbacks.set(id, callback);
    return id;
  };

  public readonly clearTimeout = (id: number): void => {
    this.callbacks.delete(id);
  };

  public runAll(): void {
    const callbacks = [...this.callbacks.values()];
    this.callbacks.clear();

    for (const callback of callbacks) {
      callback();
    }
  }
}

interface LtiPickerHarness {
  readonly document: FakeDocument;
  readonly itemQuery: FakeInput;
  readonly itemSelect: FakeSelect;
  readonly stateSelect: FakeSelect;
  readonly timers: FakeTimers;
}

const loadLtiPickerHarness = (fetchImpl: typeof fetch): LtiPickerHarness => {
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

  new Script(`${primitives}\n${setup}`).runInContext(context);
  document.dispatch("DOMContentLoaded");

  return { document, itemQuery, itemSelect, stateSelect, timers };
};

const waitFor = async (predicate: () => boolean): Promise<void> => {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (predicate()) {
      return;
    }

    await new Promise<void>((resolve) => setImmediate(resolve));
  }

  throw new Error("Browser picker did not reach the expected state");
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
    await waitFor(() =>
      harness.itemSelect.options.some((option) => option.value === "assignment-1"),
    );

    expect(harness.itemSelect.options.map((option) => option.value)).toEqual(["", "assignment-1"]);
    expect(harness.stateSelect.disabled).toBe(true);
    harness.itemSelect.value = "assignment-1";
    harness.itemSelect.dispatch("change");
    await waitFor(() => harness.stateSelect.options.some((option) => option.value === "graded"));

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
    await waitFor(() => harness.itemSelect.options.some((option) => option.value === "new-item"));

    expect(initialItemsAborted).toBe(true);
    harness.itemSelect.value = "old-item";
    harness.itemSelect.dispatch("change");
    harness.itemSelect.value = "new-item";
    harness.itemSelect.dispatch("change");
    await waitFor(() => harness.stateSelect.options.some((option) => option.value === "released"));

    expect(oldWorkflowAborted).toBe(true);
    expect(harness.stateSelect.options.map((option) => option.value)).toEqual(["", "released"]);
  });
});
