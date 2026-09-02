runRuleBuilderTest = async (options) => {
  const autoRun = options && options.auto === true;
  const runningMessage = autoRun
    ? "Running automatic test with sample learner..."
    : getRuleBuilderTestDataSource() === "lms"
      ? "Checking current LMS data..."
      : "Evaluating generated example data...";

  setStatus(ruleCreateStatus, runningMessage, false);
  setCodeOutput(ruleBuilderTestOutput, "");

  if (ruleBuilderTestResult instanceof HTMLElement) {
    setStatus(ruleBuilderTestResult, runningMessage, false);
  }

  resetConditionEvaluationResults();
  ruleBuilderLastTestSummary = "Running...";
  syncRuleBuilderSummary(runningMessage);

  let definition;

  try {
    definition = parseDefinitionJson();
  } catch (error) {
    const message = error instanceof Error ? error.message : "Rule definition is invalid.";
    setStatus(ruleCreateStatus, message, true);
    if (ruleBuilderTestResult instanceof HTMLElement) {
      setStatus(ruleBuilderTestResult, message, true);
    }
    ruleBuilderLastTestSummary = "Definition invalid";
    syncRuleBuilderSummary(message);
    return;
  }

  const lmsConnectionId = getTextFieldValue("lmsConnectionId");
  const lmsProviderKind = getSelectedLmsProviderKind();
  const testDataSource = getRuleBuilderTestDataSource();
  const learnerId =
    testDataSource === "example" ? "example-learner" : getTextFieldValue("testLearnerId");
  const recipientIdentity = getTextFieldValue("testRecipientIdentity").toLowerCase();
  const requiresRecipientIdentity =
    testDataSource === "lms" && ruleBuilderTestRequiresRecipientIdentity();
  const testFactsJson = getTextFieldValue("testFactsJson");

  if (learnerId.length === 0) {
    const message = "Choose an LMS learner.";
    setStatus(ruleCreateStatus, message, true);
    if (ruleBuilderTestResult instanceof HTMLElement) {
      setStatus(ruleBuilderTestResult, message, true);
    }
    ruleBuilderLastTestSummary = "Missing test identifiers";
    syncRuleBuilderSummary(message);
    return;
  }

  if (testDataSource === "lms" && ruleBuilderLearnerSelect instanceof HTMLSelectElement) {
    const selectedCourseIds = ruleBuilderLearnerSelect.dataset.courseIds ?? "";
    const currentCourseIds = ruleBuilderLearnerCourseIds().join(",");

    if (selectedCourseIds !== currentCourseIds) {
      const message = "The rule courses changed. Choose the learner again.";
      setStatus(ruleCreateStatus, message, true);
      if (ruleBuilderTestResult instanceof HTMLElement) {
        setStatus(ruleBuilderTestResult, message, true);
      }
      ruleBuilderLastTestSummary = "Learner selection outdated";
      syncRuleBuilderSummary(message);
      return;
    }
  }

  if (requiresRecipientIdentity && recipientIdentity.length === 0) {
    const message = "Enter the learner credential email required by the prerequisite badge check.";
    setStatus(ruleCreateStatus, message, true);
    if (ruleBuilderTestResult instanceof HTMLElement) {
      setStatus(ruleBuilderTestResult, message, true);
    }
    ruleBuilderLastTestSummary = "Missing credential email";
    syncRuleBuilderSummary(message);
    return;
  }

  if (lmsConnectionId.length === 0) {
    const message = "Select an LMS connection before testing the rule.";
    setStatus(ruleCreateStatus, message, true);
    if (ruleBuilderTestResult instanceof HTMLElement) {
      setStatus(ruleBuilderTestResult, message, true);
    }
    ruleBuilderLastTestSummary = "Missing LMS connection";
    syncRuleBuilderSummary(message);
    return;
  }

  let facts = undefined;

  if (testDataSource === "lms") {
    facts = undefined;
  } else if (testFactsJson.length > 0) {
    try {
      facts = JSON.parse(testFactsJson);
    } catch {
      const message = "Advanced facts JSON is invalid.";
      setStatus(ruleCreateStatus, message, true);
      if (ruleBuilderTestResult instanceof HTMLElement) {
        setStatus(ruleBuilderTestResult, message, true);
      }
      ruleBuilderLastTestSummary = "Facts JSON invalid";
      syncRuleBuilderSummary(message);
      return;
    }
  } else {
    const exampleValueError = ruleBuilderExampleTestController.validate();

    if (exampleValueError !== null) {
      const message = exampleValueError;
      setStatus(ruleCreateStatus, message, true);
      if (ruleBuilderTestResult instanceof HTMLElement) {
        setStatus(ruleBuilderTestResult, message, true);
      }
      ruleBuilderLastTestSummary = "Example value invalid";
      syncRuleBuilderSummary(message);
      return;
    }

    facts = buildSampleFactsFromConditions(readConditionsForPreview(), learnerId);
  }

  try {
    const response = await fetch(badgeRulePreviewApiPath, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        definition,
        lmsConnectionId,
        lmsProviderKind,
        learnerId,
        ...(requiresRecipientIdentity
          ? {
              recipient: {
                identity: recipientIdentity,
                identityType: "email",
              },
            }
          : {}),
        ...(facts === undefined ? {} : { facts }),
      }),
    });
    const payload = await parseJsonBody(response);

    if (!response.ok) {
      const message = errorDetailFromPayload(payload);
      setStatus(ruleCreateStatus, message, true);
      if (ruleBuilderTestResult instanceof HTMLElement) {
        setStatus(ruleBuilderTestResult, message, true);
      }
      ruleBuilderLastTestSummary = "Failed";
      syncRuleBuilderSummary(message);
      return;
    }

    const matched = payload && payload.evaluation && payload.evaluation.matched === true;
    let outcome = "no_match";

    if (payload && typeof payload.outcome === "string") {
      outcome = payload.outcome;
    } else if (matched) {
      outcome = "matched";
    }
    const evaluationSummary =
      payload && payload.evaluationSummary && typeof payload.evaluationSummary === "object"
        ? payload.evaluationSummary
        : null;
    const missingDataCount =
      evaluationSummary && typeof evaluationSummary.missingDataCount === "number"
        ? evaluationSummary.missingDataCount
        : 0;
    const conditionSummary = applyConditionEvaluationResults(
      payload && payload.evaluation ? payload.evaluation : null,
    );
    const conditionSummaryText =
      conditionSummary.total === 0
        ? ""
        : " Requirements passed: " +
          String(conditionSummary.matched) +
          "/" +
          String(conditionSummary.total) +
          ".";
    let resultMessage = "";

    if (outcome === "review_required") {
      resultMessage =
        "Review required: " +
        String(conditionSummary.matched) +
        " of " +
        String(conditionSummary.total) +
        " requirements matched, with missing data for " +
        String(missingDataCount) +
        " check(s).";
    } else if (matched) {
      resultMessage =
        (testDataSource === "lms" ? "This learner" : "The example learner") +
        " qualifies for this badge (" +
        String(conditionSummary.matched) +
        " of " +
        String(conditionSummary.total) +
        " requirements matched).";
    } else if (missingDataCount > 0) {
      resultMessage =
        "CredTrail could not find all data needed to evaluate this learner. Review the requirement results for the missing LMS data, then confirm the learner ID and course records.";
    } else {
      resultMessage =
        (testDataSource === "lms" ? "This learner" : "The example learner") +
        " does not qualify yet (" +
        String(conditionSummary.matched) +
        " of " +
        String(conditionSummary.total) +
        (testDataSource === "lms"
          ? " requirements matched). Confirm the learner records or adjust the requirements and run again."
          : " requirements matched). Adjust the requirements or example data and run again.");
    }

    const testStatusMessage =
      outcome === "matched"
        ? "Test passed." + conditionSummaryText
        : outcome === "review_required"
          ? "Test needs review. Data was unavailable for " +
            String(missingDataCount) +
            " requirement(s)." +
            conditionSummaryText
          : missingDataCount > 0
            ? "Test could not confirm eligibility because data was unavailable for " +
              String(missingDataCount) +
              " requirement(s)." +
              conditionSummaryText
            : "Test complete." + conditionSummaryText;

    setStatus(
      ruleCreateStatus,
      testStatusMessage,
      false,
      outcome === "matched" ? "success" : "warning",
    );

    if (ruleBuilderTestResult instanceof HTMLElement) {
      setStatus(
        ruleBuilderTestResult,
        resultMessage,
        false,
        outcome === "matched" ? "success" : "warning",
      );
    }

    if (outcome === "review_required") {
      ruleBuilderLastTestSummary =
        "Review required (" +
        String(missingDataCount) +
        " missing, " +
        String(conditionSummary.matched) +
        "/" +
        String(conditionSummary.total) +
        " requirements matched)";
    } else {
      ruleBuilderLastTestSummary =
        (matched ? "Matched" : "No match") +
        " (" +
        String(conditionSummary.matched) +
        "/" +
        String(conditionSummary.total) +
        " requirements)";
    }

    syncRuleBuilderSummary(testStatusMessage);
    setCodeOutput(ruleBuilderTestOutput, JSON.stringify(payload, null, 2));
  } catch {
    const message = "Unable to run rule test from this browser session.";
    setStatus(ruleCreateStatus, message, true);
    if (ruleBuilderTestResult instanceof HTMLElement) {
      setStatus(ruleBuilderTestResult, message, true);
    }
    ruleBuilderLastTestSummary = "Failed";
    syncRuleBuilderSummary(message);
  }
};

if (ruleBuilderTestButton instanceof HTMLButtonElement) {
  ruleBuilderTestButton.addEventListener("click", () => {
    void runRuleBuilderTest({ auto: false });
  });
}

ruleCreateForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  if (ruleBuilderAuthoringController.state() !== "idle") {
    const message = "CredTrail is already saving this rule. Wait for that attempt to finish.";
    setStatus(ruleCreateStatus, message, false);
    syncRuleBuilderSummary(message);
    return;
  }

  const action = event.submitter instanceof HTMLButtonElement ? event.submitter.value : "";

  if (action !== "save_draft" && action !== "submit_for_approval") {
    const message = "Choose whether to submit this rule or save it as a draft.";
    setStatus(ruleCreateStatus, message, true);
    syncRuleBuilderSummary(message);
    return;
  }

  const name = getTextFieldValue("name");
  const description = getTextFieldValue("description");
  const badgeTemplateId = getTextFieldValue("badgeTemplateId");
  const lmsConnectionId = getTextFieldValue("lmsConnectionId");
  const changeSummaryInput = getTextFieldValue("changeSummary");

  if (name.length === 0 || badgeTemplateId.length === 0 || lmsConnectionId.length === 0) {
    setStatus(
      ruleCreateStatus,
      "Rule name, badge template, and LMS connection are required.",
      true,
    );
    syncRuleBuilderSummary("Rule name, badge template, and LMS connection are required.");
    return;
  }

  if (!ruleBuilderBadgeTemplatePicker.isComplete()) {
    const message =
      "Confirm that reusing this badge represents another valid way to earn the same achievement.";
    setStatus(ruleCreateStatus, message, true);
    syncRuleBuilderSummary(message);
    return;
  }

  let definition;

  try {
    definition = parseDefinitionJson();
  } catch (error) {
    setStatus(
      ruleCreateStatus,
      error instanceof Error ? error.message : "Rule payload is invalid.",
      true,
    );
    syncRuleBuilderSummary(error instanceof Error ? error.message : "Rule payload is invalid.");
    return;
  }

  let changeSummary = changeSummaryInput;
  const issuanceLabel = definition.options.issuanceTiming.replaceAll("_", " ");

  if (changeSummary.length === 0) {
    changeSummary =
      (isRuleBuilderEditMode
        ? "New draft version saved via visual builder; issuance timing: "
        : "Rule created via visual builder; issuance timing: ") +
      issuanceLabel +
      ".";
  } else if (!changeSummary.toLowerCase().includes("issuance timing")) {
    changeSummary = changeSummary + " Issuance timing: " + issuanceLabel + ".";
  }

  const builderDraftId =
    !isRuleBuilderEditMode &&
    ruleBuilderContext &&
    typeof ruleBuilderContext.builderDraftId === "string"
      ? ruleBuilderContext.builderDraftId
      : "";
  const delivery =
    builderDraftId.length > 0
      ? { kind: "replay_safe_create", builderDraftId }
      : { kind: "single_attempt" };
  const authoringPromise = ruleBuilderAuthoringController.execute({
    apiPath: ruleBuilderSubmitApiPath,
    delivery,
    payload: {
      name,
      ...(description.length > 0 ? { description } : {}),
      badgeTemplateId,
      badgeTemplateReuseAcknowledged: ruleBuilderBadgeTemplatePicker.isReuseAcknowledged(),
      lmsConnectionId,
      definition,
      ...(changeSummary.length > 0 ? { changeSummary } : {}),
      action,
    },
  });
  updateStepNavigationState();
  const savingMessage =
    action === "submit_for_approval"
      ? "Saving and submitting the rule..."
      : isRuleBuilderEditMode
        ? "Saving a new draft version..."
        : "Creating rule draft...";
  setStatus(ruleCreateStatus, savingMessage, false);
  setCodeOutput(ruleBuilderTestOutput, "");
  syncRuleBuilderSummary(savingMessage);
  const result = await authoringPromise;
  updateStepNavigationState();

  if (result.status === "ignored") {
    const message = "CredTrail is already saving this rule. Wait for that attempt to finish.";
    setStatus(ruleCreateStatus, message, false);
    syncRuleBuilderSummary(message);
    return;
  }

  if (result.status === "rejected") {
    setStatus(ruleCreateStatus, result.message, true);
    syncRuleBuilderSummary(result.message);
    return;
  }

  if (result.status === "unknown") {
    const operation = ruleBuilderAuthoringOperationForSubmit({
      isEditMode: isRuleBuilderEditMode,
      action,
    });
    const message = ruleBuilderUnconfirmedAuthoringMessage({
      operation,
      ruleName: name,
      attemptCount: result.attemptCount,
      requestId: result.requestId,
    });
    setStatus(ruleCreateStatus, message, true);
    syncRuleBuilderSummary(message);
    return;
  }

  const successMessage =
    result.outcome === "approved"
      ? "Rule saved and approved by institution policy."
      : result.outcome === "pending_approval"
        ? "Rule submitted for approval."
        : isRuleBuilderEditMode
          ? "New draft version saved."
          : "Rule draft created.";
  setStatus(ruleCreateStatus, successMessage, false, "success");
  syncRuleBuilderSummary(successMessage);
  setTimeout(() => {
    ruleBuilderAuthoringController.resetCompleted();
    updateStepNavigationState();
    window.location.assign(rulesListPath);
  }, 900);
});

const badgeTemplateField = getRuleCreateField("badgeTemplateId");

if (badgeTemplateField instanceof HTMLSelectElement) {
  badgeTemplateField.addEventListener("change", () => {
    syncSuggestedRuleName();
    syncRuleBuilderSummary();

    if (ruleBuilderTemplatePreset instanceof HTMLSelectElement) {
      applyTemplatePreset();
    }
  });
}

if (ruleBuilderLmsConnectionSelect instanceof HTMLSelectElement) {
  ruleBuilderLmsConnectionSelect.addEventListener("change", () => {
    cancelRuleBuilderGradebookItemLookups();
    resetRuleBuilderLearnerPicker(
      "Learners load when this step opens",
      "CredTrail loads learners from the courses configured in this rule.",
    );
    syncSelectedLmsProviderKind();
    refreshConditionCardValueListOptions();
    syncRuleBuilderSummary();
  });
  syncSelectedLmsProviderKind();
}

if (ruleBuilderTemplatePreset instanceof HTMLSelectElement) {
  ruleBuilderTemplatePreset.addEventListener("change", () => {
    applyTemplatePreset();
    syncSuggestedRuleName();
    syncRuleBuilderSummary();
  });
}

setBuilderStepState(0);

if (isRuleBuilderEditMode) {
  if (typeof editRuleContext.name === "string") {
    setRuleCreateFieldValue("name", editRuleContext.name);
  }

  if (typeof editRuleContext.description === "string") {
    setRuleCreateFieldValue("description", editRuleContext.description);
  }

  if (typeof editRuleContext.badgeTemplateId === "string") {
    setRuleCreateFieldValue("badgeTemplateId", editRuleContext.badgeTemplateId);
    ruleBuilderBadgeTemplatePicker.sync();
  }

  if (typeof editRuleContext.lmsConnectionId === "string") {
    setRuleCreateFieldValue("lmsConnectionId", editRuleContext.lmsConnectionId);
    syncSelectedLmsProviderKind();
  }

  if (editRuleContext.definition && typeof editRuleContext.definition === "object") {
    ruleBuilderDefinitionJson.value = JSON.stringify(editRuleContext.definition, null, 2);
    applyDefinitionToBuilder(editRuleContext.definition, "Saved rule settings");
  } else {
    setStatus(ruleCreateStatus, "Saved rule JSON could not be loaded into the builder.", true);
    syncRuleBuilderSummary("Saved rule JSON could not be loaded into the builder.");
  }
} else if (copySourceContext !== null) {
  applyRuleBuilderPayload(
    {
      payload: copySourceContext.payload,
      currentStep: "metadata",
    },
    "Copied rule settings",
  );
  const sourceDisplayName =
    typeof copySourceContext.sourceDisplayName === "string"
      ? copySourceContext.sourceDisplayName
      : "the source rule";
  setStatus(
    ruleCreateStatus,
    "Creating a separate rule from " + sourceDisplayName + ". Review every setting before saving.",
    false,
    "success",
  );
  syncRuleBuilderSummary("Copied settings are ready to review.");
} else {
  syncSuggestedRuleName();
  applyTemplatePreset();
}

restoreBuilderDraftIfApplicable();
ruleBuilderBadgeTemplatePicker.sync();

refreshConditionCardValueListOptions();
syncRuleBuilderSummary();
