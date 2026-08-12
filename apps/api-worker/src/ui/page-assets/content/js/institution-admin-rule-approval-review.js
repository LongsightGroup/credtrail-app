const ruleApprovalReviewSelectedDecision = (form) => {
  for (const choice of form.querySelectorAll("[data-rule-review-decision]")) {
    if (choice instanceof HTMLInputElement && choice.checked) {
      return choice.value;
    }
  }

  return "";
};

const ruleApprovalReviewUpdateCommentRequirement = (form) => {
  const comment = form.querySelector("[data-rule-review-comment]");
  const hint = form.querySelector("[data-rule-review-comment-hint]");
  const selectedDecision = ruleApprovalReviewSelectedDecision(form);
  const decisionsRequiringComment = new Set(
    (form.dataset.ruleReviewCommentRequiredDecisions ?? "").split(" ").filter(Boolean),
  );

  if (!(comment instanceof HTMLTextAreaElement)) {
    return;
  }

  comment.required = decisionsRequiringComment.has(selectedDecision);

  if (!(hint instanceof HTMLElement)) {
    return;
  }

  if (selectedDecision === "changes_requested") {
    hint.textContent = "Required. Describe what the author must change before resubmitting.";
    return;
  }

  if (selectedDecision === "rejected") {
    hint.textContent = "Required. Explain why this submission should not continue.";
    return;
  }

  hint.textContent = "Optional when approving. Required when returning for changes or rejecting.";
};

const ruleApprovalReviewEnableDecisionForm = (form) => {
  if (!(form instanceof HTMLFormElement)) {
    return;
  }

  for (const choice of form.querySelectorAll("[data-rule-review-decision]")) {
    choice.addEventListener("change", () => {
      ruleApprovalReviewUpdateCommentRequirement(form);
    });
  }

  ruleApprovalReviewUpdateCommentRequirement(form);
};

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-rule-review-decision-form]").forEach((form) => {
    ruleApprovalReviewEnableDecisionForm(form);
  });
});
