import { readFileSync } from "node:fs";
import { createContext, Script } from "node:vm";
import { describe, expect, it } from "vitest";
import {
  FakeBrowserEvent,
  FakeDocument,
  FakeElement,
  FakeOption,
  FakeSelect,
  waitForBrowserCondition,
} from "./test-support/browser-page-asset-harness";

interface RuleVersionHarness {
  readonly assignmentId: FakeElement;
  readonly assignmentLabel: FakeElement;
  readonly courseId: FakeElement;
  readonly courseLabel: FakeElement;
  readonly document: FakeDocument;
  readonly status: FakeElement;
}

const LABELS_URL =
  "/v1/tenants/tenant_123/badge-rules/brl_detail/versions/brv_detail/lms-reference-labels";

const ruleVersionAssetSource = (): string => {
  return readFileSync(
    new URL("./ui/page-assets/content/js/institution-admin-rule-version.js", import.meta.url),
    "utf8",
  );
};

const loadRuleVersionHarness = (fetchImpl: typeof fetch): RuleVersionHarness => {
  const document = new FakeDocument();
  const root = new FakeElement();
  root.dataset.ruleLmsLabels = "";
  root.dataset.lmsLabelsUrl = LABELS_URL;

  const courseReference = new FakeElement();
  courseReference.dataset.ruleLmsReference = "course";
  courseReference.dataset.courseId = "course_101";
  const courseLabel = new FakeElement();
  courseLabel.dataset.ruleLmsLabel = "";
  courseLabel.textContent = "Course";
  const courseId = new FakeElement();
  courseId.textContent = "ID: course_101";
  courseReference.append(courseLabel, courseId);

  const assignmentReference = new FakeElement();
  assignmentReference.dataset.ruleLmsReference = "assignment";
  assignmentReference.dataset.courseId = "course_101";
  assignmentReference.dataset.assignmentId = "assignment_7";
  const assignmentLabel = new FakeElement();
  assignmentLabel.dataset.ruleLmsLabel = "";
  assignmentLabel.textContent = "Assignment";
  const assignmentId = new FakeElement();
  assignmentId.textContent = "ID: assignment_7";
  assignmentReference.append(assignmentLabel, assignmentId);

  const status = new FakeElement();
  status.dataset.ruleLmsLabelStatus = "";
  status.hidden = true;
  status.textContent =
    "Course and assignment names could not be loaded. The saved LMS IDs remain visible.";
  root.append(courseReference, assignmentReference, status);
  document.append(root);

  const context = createContext({
    console,
    document,
    fetch: fetchImpl,
    HTMLElement: FakeElement,
    Response,
  });

  new Script(ruleVersionAssetSource()).runInContext(context);
  document.dispatch("DOMContentLoaded");

  return { assignmentId, assignmentLabel, courseId, courseLabel, document, status };
};

describe("institution admin rule-version navigation", () => {
  it("navigates directly to the selected same-origin version URL", () => {
    const document = new FakeDocument();
    const form = new FakeElement("FORM");
    form.dataset.ruleVersionNavigation = "";
    const select = new FakeSelect();
    select.dataset.ruleVersionSelect = "";
    const option = new FakeOption();
    option.dataset.versionUrl =
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_latest";
    option.selected = true;
    select.append(option);
    form.append(select);
    document.append(form);
    const assignedUrls: string[] = [];
    const window = {
      location: {
        href: "https://credtrail.example/tenants/tenant_123/admin/rules/brl_detail",
        origin: "https://credtrail.example",
        assign: (url: string): void => {
          assignedUrls.push(url);
        },
      },
    };
    const context = createContext({
      console,
      document,
      fetch,
      HTMLElement: FakeElement,
      HTMLFormElement: FakeElement,
      HTMLSelectElement: FakeSelect,
      Response,
      URL,
      window,
    });

    new Script(ruleVersionAssetSource()).runInContext(context);
    document.dispatch("DOMContentLoaded");
    const submitEvent = new FakeBrowserEvent();
    form.dispatch("submit", submitEvent);

    expect(submitEvent.defaultPrevented).toBe(true);
    expect(assignedUrls).toEqual([
      "https://credtrail.example/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_latest",
    ]);
  });
});

describe("institution admin rule-version LMS label hydration contract", () => {
  it("loads every saved reference through one version-scoped request", async () => {
    const requestedUrls: string[] = [];
    const fetchImpl = ((input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = input instanceof Request ? input.url : input instanceof URL ? input.href : input;
      requestedUrls.push(url);
      expect(init?.cache).toBe("no-store");
      expect((init as (RequestInit & { priority?: string }) | undefined)?.priority).toBe("low");

      return Promise.resolve(
        Response.json({
          courses: [{ courseId: "course_101", title: "Advanced TypeScript" }],
          assignments: [
            {
              courseId: "course_101",
              assignmentId: "assignment_7",
              title: "Final project",
            },
          ],
        }),
      );
    }) as typeof fetch;
    const harness = loadRuleVersionHarness(fetchImpl);

    expect(harness.courseLabel.textContent).toBe("Course");
    expect(harness.assignmentLabel.textContent).toBe("Assignment");
    await waitForBrowserCondition(
      () => harness.courseLabel.textContent === "Advanced TypeScript",
      "Rule-version labels did not load",
    );

    expect(harness.courseLabel.textContent).toBe("Advanced TypeScript");
    expect(harness.assignmentLabel.textContent).toBe("Final project");
    expect(harness.courseId.textContent).toBe("ID: course_101");
    expect(harness.assignmentId.textContent).toBe("ID: assignment_7");
    expect(harness.status.hidden).toBe(true);
    expect(requestedUrls).toEqual([LABELS_URL]);
  });

  it("keeps saved references visible when the endpoint denies access", async () => {
    const fetchImpl = (() =>
      Promise.resolve(
        Response.json({ error: "Course access denied" }, { status: 403 }),
      )) as typeof fetch;
    const harness = loadRuleVersionHarness(fetchImpl);

    await waitForBrowserCondition(
      () => harness.status.dataset.tone === "warning",
      "Rule-version label warning did not render",
    );

    expect(harness.courseLabel.textContent).toBe("Course");
    expect(harness.assignmentLabel.textContent).toBe("Assignment");
    expect(harness.courseId.textContent).toBe("ID: course_101");
    expect(harness.assignmentId.textContent).toBe("ID: assignment_7");
    expect(harness.status.hidden).toBe(false);
    expect(harness.status.textContent).toBe(
      "Course access denied. The saved LMS IDs remain visible.",
    );
  });

  it("uses a safe message when a failed endpoint does not return JSON", async () => {
    const fetchImpl = (() =>
      Promise.resolve(
        new Response("<html>upstream failure</html>", {
          status: 502,
          headers: { "content-type": "text/html" },
        }),
      )) as typeof fetch;
    const harness = loadRuleVersionHarness(fetchImpl);

    await waitForBrowserCondition(
      () => harness.status.dataset.tone === "warning",
      "Rule-version label warning did not render",
    );

    expect(harness.status.textContent).toBe(
      "Course and assignment names could not be loaded. The saved LMS IDs remain visible.",
    );
    expect(harness.status.hidden).toBe(false);
    expect(harness.status.textContent).not.toContain("upstream failure");
  });

  it("reports partial results when the endpoint omits a saved assignment", async () => {
    const fetchImpl = (() =>
      Promise.resolve(
        Response.json({
          courses: [{ courseId: "course_101", title: "Advanced TypeScript" }],
          assignments: [],
        }),
      )) as typeof fetch;
    const harness = loadRuleVersionHarness(fetchImpl);

    await waitForBrowserCondition(
      () => harness.status.dataset.tone === "warning",
      "Partial rule-version label warning did not render",
    );

    expect(harness.courseLabel.textContent).toBe("Advanced TypeScript");
    expect(harness.assignmentLabel.textContent).toBe("Assignment");
    expect(harness.status.hidden).toBe(false);
    expect(harness.status.textContent).toBe(
      "Some LMS names could not be loaded. Their saved IDs remain visible.",
    );
  });
});
