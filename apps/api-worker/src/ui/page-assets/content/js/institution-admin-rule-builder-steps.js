const ruleBuilderStepPanels = Array.from(
  ruleCreateForm.querySelectorAll("[data-rule-step]"),
).filter((candidate) => candidate instanceof HTMLElement);
const ruleBuilderStepOrder = ruleBuilderStepPanels
  .map((candidate) => candidate.dataset.ruleStep ?? "")
  .filter((stepName) => stepName.length > 0);
const ruleBuilderStepLabels = {
  metadata: "Awarding pattern",
  conditions: "Requirements",
  test: "Test and submit",
};
const ruleBuilderStepCallouts = {
  metadata: "Choose an awarding pattern, badge, and LMS connection, then select Continue.",
  conditions:
    "Confirm the requirements learners must meet, then select Continue. To revise setup, select step 1 above.",
  test: "Test the rule, then submit it for approval or save it as a rule draft. To revise earlier steps, select a step label above.",
};
const ruleBuilderStepGateMessages = {
  metadata: "Choose a badge template and LMS connection before continuing.",
  conditions: "Add at least one requirement before continuing.",
  test: "Run a learner test before submitting the rule.",
};
let activeRuleBuilderStepIndex = 0;

const prefersReducedMotion = () => {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
};

const isRuleBuilderMobileLayout = () => {
  return window.matchMedia("(max-width: 979px)").matches;
};

const shouldScrollToActiveBuilderPanel = (panel) => {
  if (!(panel instanceof HTMLElement)) {
    return false;
  }

  if (isRuleBuilderMobileLayout()) {
    return true;
  }

  const margin = 16;
  const rect = panel.getBoundingClientRect();

  return rect.top < margin || rect.bottom > window.innerHeight - margin;
};

const scrollActiveBuilderPanelIntoView = (panel) => {
  if (!shouldScrollToActiveBuilderPanel(panel)) {
    return;
  }

  const stepRow = panel.closest("[data-rule-step-row], .ct-admin__stepper-step");
  const scrollTarget = stepRow instanceof HTMLElement ? stepRow : panel;

  scrollTarget.scrollIntoView({
    block: "nearest",
    behavior: prefersReducedMotion() ? "auto" : "smooth",
  });
};

const focusActiveBuilderPanelHeading = (panel) => {
  if (!(panel instanceof HTMLElement)) {
    return;
  }

  const heading = panel.querySelector("h3");

  if (!(heading instanceof HTMLElement)) {
    return;
  }

  heading.tabIndex = -1;
  heading.focus({ preventScroll: true });
};

const isMetadataStepComplete = () => {
  return (
    getTextFieldValue("name").length > 0 &&
    getTextFieldValue("badgeTemplateId").length > 0 &&
    getTextFieldValue("lmsConnectionId").length > 0
  );
};

const isConditionsStepComplete = () => {
  const cardCount = getConditionCards().length;

  if (cardCount === 0) {
    return false;
  }

  const validationErrors = validateConditionCards(false);

  if (validationErrors.length > 0) {
    return false;
  }

  try {
    const definition = readDefinitionFromBuilder(true);
    const rootConditions =
      definition &&
      typeof definition === "object" &&
      definition.conditions &&
      typeof definition.conditions === "object"
        ? definition.conditions
        : null;
    const childCount =
      rootConditions !== null && Array.isArray(rootConditions.all)
        ? rootConditions.all.length
        : rootConditions !== null && Array.isArray(rootConditions.any)
          ? rootConditions.any.length
          : cardCount;

    return childCount > 0;
  } catch {
    return false;
  }
};

const isTestStepComplete = () => {
  const testReady =
    ruleBuilderLastTestSummary.startsWith("Matched") ||
    ruleBuilderLastTestSummary.startsWith("No match") ||
    ruleBuilderLastTestSummary.startsWith("Review required");
  const reviewReady = getTextFieldValue("issuanceTiming").length > 0;

  return testReady && reviewReady;
};

const getRuleBuilderCompletionState = () => {
  return {
    metadata: isMetadataStepComplete(),
    conditions: isConditionsStepComplete(),
    test: isTestStepComplete(),
  };
};

const isStepComplete = (stepName) => {
  const completion = getRuleBuilderCompletionState();
  return completion[stepName] === true;
};

const getStepGateMessage = (stepName) => {
  if (stepName === "metadata") {
    const missingLabels = [];

    if (getTextFieldValue("badgeTemplateId").length === 0) {
      missingLabels.push("badge template");
    }

    if (getTextFieldValue("lmsConnectionId").length === 0) {
      missingLabels.push("LMS connection");
    }

    if (missingLabels.length > 0) {
      if (missingLabels.length === 1) {
        const article = missingLabels[0] === "LMS connection" ? "an " : "a ";

        return "Choose " + article + missingLabels[0] + " before continuing.";
      }

      return "Choose a " + missingLabels[0] + " and an " + missingLabels[1] + " before continuing.";
    }
  }

  if (stepName === "conditions") {
    const cardCount = getConditionCards().length;

    if (cardCount === 0) {
      return "Add at least one requirement before continuing. Go back to Step 1 to choose a pattern.";
    }

    const validationErrors = validateConditionCards(false);

    if (validationErrors.length > 0) {
      return validationErrors[0];
    }

    try {
      readDefinitionFromBuilder(true);
    } catch (error) {
      return error instanceof Error ? error.message : "Fix the requirements before continuing.";
    }
  }

  if (stepName === "test") {
    const testReady =
      ruleBuilderLastTestSummary.startsWith("Matched") ||
      ruleBuilderLastTestSummary.startsWith("No match") ||
      ruleBuilderLastTestSummary.startsWith("Review required");

    if (!testReady) {
      return "Run a learner test before submitting the rule.";
    }

    if (getTextFieldValue("issuanceTiming").length === 0) {
      return "Choose when the badge should be issued before submitting the rule.";
    }

  }

  return ruleBuilderStepGateMessages[stepName] ?? "Complete this step before continuing.";
};

const canNavigateToStep = (targetIndex) => {
  if (targetIndex < 0 || targetIndex >= ruleBuilderStepOrder.length) {
    return false;
  }

  return targetIndex < activeRuleBuilderStepIndex;
};

const showStepGateMessage = (stepName) => {
  if (!(ruleBuilderStepCallout instanceof HTMLElement)) {
    return;
  }

  ruleBuilderStepCallout.textContent = getStepGateMessage(stepName);
  ruleBuilderStepCallout.dataset.tone = "warning";
};

const updateStepNavigationState = () => {
  const completion = getRuleBuilderCompletionState();
  const currentStep = ruleBuilderStepOrder[activeRuleBuilderStepIndex] ?? "";
  const currentComplete = completion[currentStep] === true;
  const submissionInProgress = ruleBuilderAuthoringController.state() !== "idle";

  ruleBuilderStepButtons.forEach((candidate) => {
    if (!(candidate instanceof HTMLButtonElement)) {
      return;
    }

    const targetStep = candidate.dataset.ruleStepTarget ?? "";
    const targetIndex = ruleBuilderStepOrder.indexOf(targetStep);
    const isCurrent = targetIndex === activeRuleBuilderStepIndex;
    const isFuture = targetIndex > activeRuleBuilderStepIndex;
    const canGoBack = canNavigateToStep(targetIndex);

    candidate.disabled = isFuture;
    candidate.classList.toggle("is-locked", isFuture);
    candidate.classList.toggle("is-current-only", isCurrent);

    if (canGoBack) {
      candidate.removeAttribute("aria-disabled");
    } else if (isFuture) {
      candidate.setAttribute("aria-disabled", "true");
    } else {
      candidate.removeAttribute("aria-disabled");
    }
  });

  const isLastStep = activeRuleBuilderStepIndex >= ruleBuilderStepOrder.length - 1;

  if (ruleBuilderStepNextButton instanceof HTMLButtonElement) {
    const nextStep = ruleBuilderStepOrder[activeRuleBuilderStepIndex + 1] ?? "";
    const nextStepLabel = ruleBuilderStepLabels[nextStep] ?? "";

    ruleBuilderStepNextButton.hidden = isLastStep;
    ruleBuilderStepNextButton.textContent =
      nextStepLabel.length > 0 ? "Continue to " + nextStepLabel : "Continue";
    ruleBuilderStepNextButton.disabled = !currentComplete;
  }

  if (ruleBuilderSubmitButton instanceof HTMLButtonElement) {
    ruleBuilderSubmitButton.hidden = !isLastStep;
    ruleBuilderSubmitButton.disabled = submissionInProgress || !completion.test;
  }

  if (ruleBuilderSaveFormalDraftButton instanceof HTMLButtonElement) {
    ruleBuilderSaveFormalDraftButton.hidden = !isLastStep;
    ruleBuilderSaveFormalDraftButton.disabled = submissionInProgress || !completion.test;
  }

  if (ruleBuilderStepCallout instanceof HTMLElement) {
    if (!currentComplete) {
      ruleBuilderStepCallout.textContent = getStepGateMessage(currentStep);
      ruleBuilderStepCallout.dataset.tone = "warning";
    } else {
      ruleBuilderStepCallout.textContent =
        ruleBuilderStepCallouts[currentStep] ?? "Complete this step, then continue.";
      delete ruleBuilderStepCallout.dataset.tone;
    }
  }
};

const setBuilderStepState = (requestedIndex) => {
  if (ruleBuilderStepOrder.length === 0) {
    return;
  }

  const previousIndex = activeRuleBuilderStepIndex;
  const nextIndex = Math.min(Math.max(requestedIndex, 0), ruleBuilderStepOrder.length - 1);
  const stepChanged = previousIndex !== nextIndex;
  activeRuleBuilderStepIndex = nextIndex;
  const activeStep = ruleBuilderStepOrder[nextIndex] ?? "";

  ruleBuilderStepPanels.forEach((panel) => {
    if (!(panel instanceof HTMLElement)) {
      return;
    }

    const isActive = (panel.dataset.ruleStep ?? "") === activeStep;
    panel.hidden = !isActive;
  });

  document.querySelectorAll("[data-rule-step-row]").forEach((candidate) => {
    if (!(candidate instanceof HTMLElement)) {
      return;
    }

    const isActive = (candidate.dataset.ruleStepRow ?? "") === activeStep;
    candidate.classList.toggle("is-active", isActive);
  });

  ruleBuilderStepButtons.forEach((candidate) => {
    if (!(candidate instanceof HTMLButtonElement)) {
      return;
    }

    const isActive = (candidate.dataset.ruleStepTarget ?? "") === activeStep;
    candidate.classList.toggle("is-active", isActive);

    if (isActive) {
      candidate.setAttribute("aria-current", "step");
    } else {
      candidate.removeAttribute("aria-current");
    }
  });

  syncRuleBuilderStepCompletion();

  const activePanel = ruleBuilderStepPanels.find(
    (panel) => panel instanceof HTMLElement && (panel.dataset.ruleStep ?? "") === activeStep,
  );

  if (stepChanged && activePanel instanceof HTMLElement) {
    scrollActiveBuilderPanelIntoView(activePanel);
    focusActiveBuilderPanelHeading(activePanel);
  }

  if (stepChanged && typeof persistRuleBuilderDraftOnStepChange === "function") {
    persistRuleBuilderDraftOnStepChange();
  }

  if (activeStep === "test") {
    syncRuleBuilderTestDataSource();
    syncRuleBuilderTestRecipientFields();

    if (getRuleBuilderTestDataSource() === "example") {
      void runRuleBuilderTest({ auto: true });
    } else {
      void loadRuleBuilderLearners();
    }
  }
};

const tryNavigateToStep = (targetIndex) => {
  if (targetIndex === activeRuleBuilderStepIndex) {
    return true;
  }

  if (targetIndex > activeRuleBuilderStepIndex) {
    const currentStep = ruleBuilderStepOrder[activeRuleBuilderStepIndex] ?? "";

    if (!isStepComplete(currentStep)) {
      showStepGateMessage(currentStep);
    } else if (ruleBuilderStepCallout instanceof HTMLElement) {
      ruleBuilderStepCallout.textContent =
        "Use the Continue button at the bottom of the current step before opening this step.";
      ruleBuilderStepCallout.dataset.tone = "warning";
    }

    return false;
  }

  if (!canNavigateToStep(targetIndex)) {
    return false;
  }

  setBuilderStepState(targetIndex);
  return true;
};
