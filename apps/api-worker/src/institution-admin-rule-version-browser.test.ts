import { readFileSync } from "node:fs";
import { createContext, Script } from "node:vm";
import { describe, expect, it } from "vitest";
import {
  FakeDocument,
  FakeElement,
  waitForBrowserCondition,
} from "./test-support/browser-page-asset-harness";

interface RuleVersionHarness {
  readonly assignmentLabel: FakeElement;
  readonly courseLabel: FakeElement;
  readonly document: FakeDocument;
  readonly status: FakeElement;
}

const LABELS_URL =
  "/v1/tenants/tenant_123/badge-rules/brl_detail/versions/brv_detail/lms-reference-labels";

const loadRuleVersionHarness = (fetchImpl: typeof fetch): RuleVersionHarness => {
  const source = readFileSync(
    new URL("./ui/page-assets/content/js/institution-admin-rule-version.js", import.meta.url),
    "utf8",
  );
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
  courseReference.append(courseLabel);

  const assignmentReference = new FakeElement();
  assignmentReference.dataset.ruleLmsReference = "assignment";
  assignmentReference.dataset.courseId = "course_101";
  assignmentReference.dataset.assignmentId = "assignment_7";
  const assignmentLabel = new FakeElement();
  assignmentLabel.dataset.ruleLmsLabel = "";
  assignmentLabel.textContent = "Assignment";
  assignmentReference.append(assignmentLabel);

  const status = new FakeElement();
  status.dataset.ruleLmsLabelStatus = "";
  status.textContent = "Loading course and assignment names…";
  root.append(courseReference, assignmentReference, status);
  document.append(root);

  const context = createContext({
    console,
    document,
    fetch: fetchImpl,
    HTMLElement: FakeElement,
    Response,
  });

  new Script(source).runInContext(context);
  document.dispatch("DOMContentLoaded");

  return { assignmentLabel, courseLabel, document, status };
};

describe("institution admin rule-version LMS labels", () => {
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
      () => harness.status.dataset.tone === "success",
      "Rule-version labels did not load",
    );

    expect(harness.courseLabel.textContent).toBe("Advanced TypeScript");
    expect(harness.assignmentLabel.textContent).toBe("Final project");
    expect(harness.status.textContent).toBe("Course and assignment names loaded from the LMS.");
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
    expect(harness.status.textContent).toBe(
      "Some LMS names could not be loaded. Their saved IDs remain visible.",
    );
  });
});
