import { readFileSync } from "node:fs";
import { createContext, Script } from "node:vm";
import { describe, expect, it } from "vitest";
import { FakeDocument, FakeElement, FakeInput } from "./test-support/browser-page-asset-harness";

interface ReviewDecisionHarness {
  readonly approve: FakeInput;
  readonly changesRequested: FakeInput;
  readonly comment: FakeInput;
  readonly hint: FakeElement;
  readonly rejected: FakeInput;
}

const ruleApprovalReviewAssetSource = (): string => {
  return readFileSync(
    new URL(
      "./ui/page-assets/content/js/institution-admin-rule-approval-review.js",
      import.meta.url,
    ),
    "utf8",
  );
};

const reviewDecisionChoice = (value: string): FakeInput => {
  const choice = new FakeInput();
  choice.type = "radio";
  choice.value = value;
  choice.dataset.ruleReviewDecision = "";
  return choice;
};

const loadReviewDecisionHarness = (): ReviewDecisionHarness => {
  const document = new FakeDocument();
  const form = new FakeElement("FORM");
  form.dataset.ruleReviewDecisionForm = "";
  form.dataset.ruleReviewCommentRequiredDecisions = "rejected changes_requested";
  const approve = reviewDecisionChoice("approved");
  const changesRequested = reviewDecisionChoice("changes_requested");
  const rejected = reviewDecisionChoice("rejected");
  const comment = new FakeInput();
  comment.dataset.ruleReviewComment = "";
  const hint = new FakeElement();
  hint.dataset.ruleReviewCommentHint = "";
  hint.textContent = "Optional when approving. Required when returning for changes or rejecting.";
  form.append(approve, changesRequested, rejected, comment, hint);
  document.append(form);
  const context = createContext({
    console,
    document,
    HTMLElement: FakeElement,
    HTMLFormElement: FakeElement,
    HTMLInputElement: FakeInput,
    HTMLTextAreaElement: FakeInput,
  });

  new Script(ruleApprovalReviewAssetSource()).runInContext(context);
  document.dispatch("DOMContentLoaded");

  return { approve, changesRequested, comment, hint, rejected };
};

describe("institution admin rule approval-review decisions", () => {
  it("requires an explanation for return and rejection decisions", () => {
    const harness = loadReviewDecisionHarness();

    expect(harness.comment.required).toBe(false);

    harness.changesRequested.checked = true;
    harness.changesRequested.dispatch("change");
    expect(harness.comment.required).toBe(true);
    expect(harness.hint.textContent).toBe(
      "Required. Describe what the author must change before resubmitting.",
    );

    harness.changesRequested.checked = false;
    harness.rejected.checked = true;
    harness.rejected.dispatch("change");
    expect(harness.comment.required).toBe(true);
    expect(harness.hint.textContent).toBe(
      "Required. Explain why this submission should not continue.",
    );

    harness.rejected.checked = false;
    harness.approve.checked = true;
    harness.approve.dispatch("change");
    expect(harness.comment.required).toBe(false);
    expect(harness.hint.textContent).toBe(
      "Optional when approving. Required when returning for changes or rejecting.",
    );
  });
});
