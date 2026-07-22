const parsedContext = readAdminContext();

if (!parsedContext) {
  return;
}

const badgeRuleApiPath =
  parsedContext && typeof parsedContext.badgeRuleApiPath === "string"
    ? parsedContext.badgeRuleApiPath
    : "";
const assertionsApiPathPrefix =
  parsedContext && typeof parsedContext.assertionsApiPathPrefix === "string"
    ? parsedContext.assertionsApiPathPrefix
    : "";

const reportingFiltersForm = document.getElementById("reporting-filters-form");
const reportingFiltersStatus = document.getElementById("reporting-filters-status");
const assertionLifecycleViewForm = document.getElementById("assertion-lifecycle-view-form");
const assertionLifecycleViewStatus = document.getElementById("assertion-lifecycle-view-status");
const assertionLifecycleOutput = document.getElementById("assertion-lifecycle-output");
const assertionLifecycleTransitionForm = document.getElementById(
  "assertion-lifecycle-transition-form",
);
const assertionLifecycleTransitionStatus = document.getElementById(
  "assertion-lifecycle-transition-status",
);
const ruleGovernanceForm = document.getElementById("rule-governance-form");
const ruleGovernanceStatus = document.getElementById("rule-governance-status");
const ruleGovernanceOutput = document.getElementById("rule-governance-output");

const fillLifecycleAssertionIdInputs = (assertionId) => {
  if (typeof assertionId !== "string" || assertionId.length === 0) {
    return;
  }

  if (assertionLifecycleViewForm instanceof HTMLFormElement) {
    const lifecycleInput = assertionLifecycleViewForm.elements.namedItem("assertionId");

    if (lifecycleInput instanceof HTMLInputElement) {
      lifecycleInput.value = assertionId;
    }
  }

  if (assertionLifecycleTransitionForm instanceof HTMLFormElement) {
    const transitionInput = assertionLifecycleTransitionForm.elements.namedItem("assertionId");

    if (transitionInput instanceof HTMLInputElement) {
      transitionInput.value = assertionId;
    }
  }
};
