export const INSTITUTION_ADMIN_RULE_BUILDER_STEPS_JS = `
    const ruleBuilderStepPanels = Array.from(
      ruleCreateForm.querySelectorAll('[data-rule-step]'),
    ).filter((candidate) => candidate instanceof HTMLElement);
    const ruleBuilderStepOrder = ruleBuilderStepPanels
      .map((candidate) => candidate.dataset.ruleStep ?? '')
      .filter((stepName) => stepName.length > 0);
    const ruleBuilderStepLabels = {
      metadata: 'Awarding pattern',
      conditions: 'Requirements',
      test: 'Test and submit',
    };
    const ruleBuilderStepCallouts = {
      metadata: 'Choose an awarding pattern, badge, and LMS source, then select Continue.',
      conditions: 'Confirm the requirements learners must meet, then select Continue.',
      test: 'Test with a sample learner. When results look right, create the draft.',
    };
    const ruleBuilderStepGateMessages = {
      metadata: 'Choose a badge template and LMS provider before continuing.',
      conditions: 'Add at least one requirement before continuing.',
      test: 'Run a test with a sample learner before creating the draft.',
    };
    let activeRuleBuilderStepIndex = 0;

    const isMetadataStepComplete = () => {
      return (
        getTextFieldValue('name').length > 0 &&
        getTextFieldValue('badgeTemplateId').length > 0 &&
        getTextFieldValue('lmsProviderKind').length > 0
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
          typeof definition === 'object' &&
          definition.conditions &&
          typeof definition.conditions === 'object'
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
        ruleBuilderLastTestSummary.startsWith('Matched') ||
        ruleBuilderLastTestSummary.startsWith('No match') ||
        ruleBuilderLastTestSummary.startsWith('Review required');
      let reviewReady = getTextFieldValue('issuanceTiming').length > 0;

      try {
        buildApprovalChain(getTextFieldValue('approvalRoles'));
      } catch {
        reviewReady = false;
      }

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
      if (stepName === 'metadata') {
        const missingLabels = [];

        if (getTextFieldValue('badgeTemplateId').length === 0) {
          missingLabels.push('badge template');
        }

        if (getTextFieldValue('lmsProviderKind').length === 0) {
          missingLabels.push('LMS provider');
        }

        if (missingLabels.length > 0) {
          return 'Choose a ' + missingLabels.join(' and ') + ' before continuing.';
        }
      }

      if (stepName === 'conditions') {
        const cardCount = getConditionCards().length;

        if (cardCount === 0) {
          return 'Add at least one requirement before continuing. Go back to Step 1 to choose a pattern.';
        }

        const validationErrors = validateConditionCards(false);

        if (validationErrors.length > 0) {
          return validationErrors[0];
        }

        try {
          readDefinitionFromBuilder(true);
        } catch (error) {
          return error instanceof Error ? error.message : 'Fix the requirements before continuing.';
        }
      }

      if (stepName === 'test') {
        const testReady =
          ruleBuilderLastTestSummary.startsWith('Matched') ||
          ruleBuilderLastTestSummary.startsWith('No match') ||
          ruleBuilderLastTestSummary.startsWith('Review required');

        if (!testReady) {
          return 'Run a test with a sample learner before creating the draft.';
        }

        if (getTextFieldValue('issuanceTiming').length === 0) {
          return 'Choose when the badge should be issued before creating the draft.';
        }

        try {
          buildApprovalChain(getTextFieldValue('approvalRoles'));
        } catch (error) {
          return error instanceof Error ? error.message : 'Fix approval roles before creating the draft.';
        }
      }

      return ruleBuilderStepGateMessages[stepName] ?? 'Complete this step before continuing.';
    };

    const canNavigateToStep = (targetIndex) => {
      if (targetIndex < 0 || targetIndex >= ruleBuilderStepOrder.length) {
        return false;
      }

      if (targetIndex <= activeRuleBuilderStepIndex) {
        return true;
      }

      const completion = getRuleBuilderCompletionState();

      for (let index = 0; index < targetIndex; index += 1) {
        const stepName = ruleBuilderStepOrder[index] ?? '';

        if (completion[stepName] !== true) {
          return false;
        }
      }

      return true;
    };

    const showStepGateMessage = (stepName) => {
      if (!(ruleBuilderStepCallout instanceof HTMLElement)) {
        return;
      }

      ruleBuilderStepCallout.textContent = getStepGateMessage(stepName);
      ruleBuilderStepCallout.dataset.tone = 'warning';
    };

    const updateStepNavigationState = () => {
      const completion = getRuleBuilderCompletionState();
      const currentStep = ruleBuilderStepOrder[activeRuleBuilderStepIndex] ?? '';
      const currentComplete = completion[currentStep] === true;

      ruleBuilderStepButtons.forEach((candidate) => {
        if (!(candidate instanceof HTMLButtonElement)) {
          return;
        }

        const targetStep = candidate.dataset.ruleStepTarget ?? '';
        const targetIndex = ruleBuilderStepOrder.indexOf(targetStep);
        const reachable = canNavigateToStep(targetIndex);

        candidate.disabled = !reachable;
        candidate.classList.toggle('is-locked', !reachable);
        candidate.setAttribute('aria-disabled', reachable ? 'false' : 'true');
      });

      if (ruleBuilderStepPrevButton instanceof HTMLButtonElement) {
        ruleBuilderStepPrevButton.disabled = activeRuleBuilderStepIndex === 0;
      }

      if (ruleBuilderStepNextButton instanceof HTMLButtonElement) {
        const nextStep = ruleBuilderStepOrder[activeRuleBuilderStepIndex + 1] ?? '';
        const nextStepLabel = ruleBuilderStepLabels[nextStep] ?? '';

        ruleBuilderStepNextButton.textContent =
          nextStepLabel.length > 0 ? 'Continue to ' + nextStepLabel : 'Continue';
        ruleBuilderStepNextButton.disabled =
          activeRuleBuilderStepIndex >= ruleBuilderStepOrder.length - 1 || !currentComplete;
      }

      if (ruleBuilderSubmitButton instanceof HTMLButtonElement) {
        ruleBuilderSubmitButton.disabled =
          activeRuleBuilderStepIndex < ruleBuilderStepOrder.length - 1 || !completion.test;
      }

      if (ruleBuilderStepCallout instanceof HTMLElement) {
        if (!currentComplete) {
          ruleBuilderStepCallout.textContent = getStepGateMessage(currentStep);
          ruleBuilderStepCallout.dataset.tone = 'warning';
        } else {
          ruleBuilderStepCallout.textContent =
            ruleBuilderStepCallouts[currentStep] ?? 'Complete this step, then continue.';
          delete ruleBuilderStepCallout.dataset.tone;
        }
      }
    };

    const setBuilderStepState = (requestedIndex) => {
      if (ruleBuilderStepOrder.length === 0) {
        return;
      }

      const nextIndex = Math.min(
        Math.max(requestedIndex, 0),
        ruleBuilderStepOrder.length - 1,
      );
      activeRuleBuilderStepIndex = nextIndex;
      const activeStep = ruleBuilderStepOrder[nextIndex] ?? '';
      const activeStepLabel = ruleBuilderStepLabels[activeStep] ?? 'Step';

      ruleBuilderStepPanels.forEach((panel) => {
        if (!(panel instanceof HTMLElement)) {
          return;
        }

        const isActive = (panel.dataset.ruleStep ?? '') === activeStep;
        panel.hidden = !isActive;
      });

      ruleBuilderStepButtons.forEach((candidate) => {
        if (!(candidate instanceof HTMLButtonElement)) {
          return;
        }

        const isActive = (candidate.dataset.ruleStepTarget ?? '') === activeStep;
        candidate.classList.toggle('is-active', isActive);

        if (isActive) {
          candidate.setAttribute('aria-current', 'step');
        } else {
          candidate.removeAttribute('aria-current');
        }
      });

      syncRuleBuilderStepCompletion();

      if (activeStep === 'test') {
        applyTestFactPreset();
        void runRuleBuilderTest({ auto: true });
      }
    };

    const tryNavigateToStep = (targetIndex) => {
      if (!canNavigateToStep(targetIndex)) {
        for (let index = 0; index < targetIndex; index += 1) {
          const stepName = ruleBuilderStepOrder[index] ?? '';

          if (!isStepComplete(stepName)) {
            showStepGateMessage(stepName);
            break;
          }
        }

        return false;
      }

      setBuilderStepState(targetIndex);
      return true;
    };
`;
