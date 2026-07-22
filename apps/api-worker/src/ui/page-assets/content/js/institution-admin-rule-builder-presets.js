const applyTemplatePreset = () => {
  const presetKey =
    ruleBuilderTemplatePreset instanceof HTMLSelectElement
      ? ruleBuilderTemplatePreset.value.trim()
      : "course_and_grade";

  if (presetKey === "blank") {
    clearConditionCanvas();
    setRuleBuilderRootLogic("all");
    ruleBuilderDefinitionJson.value = "";
    ruleBuilderLastTestSummary = "Not run";
    syncConditionCanvasMeta();
    renderRuleFlowPreview();
    renderSourceReadiness();
    validateConditionCards(true);
    setStatus(ruleCreateStatus, "Blank requirements started.", false, "success");
    syncSuggestedRuleName();
    syncRuleBuilderSummary("Blank requirements started.");
    return;
  }

  const selectedTemplate =
    buildDefaultTemplateDefinitions(getDefaultCourseId())[presetKey] ??
    buildDefaultTemplateDefinitions(getDefaultCourseId()).course_and_grade;
  ruleBuilderDefinitionJson.value = JSON.stringify(selectedTemplate, null, 2);
  applyDefinitionToBuilder(selectedTemplate, "Template");
  syncSuggestedRuleName();
};

const applyTestFactPreset = () => {
  const learnerId = getTextFieldValue("testLearnerId") || "canvas:12345";
  const recipientIdentity = getTextFieldValue("testRecipientIdentity") || "learner@example.edu";

  setRuleCreateFieldValue("testLearnerId", learnerId);
  setRuleCreateFieldValue("testRecipientIdentity", recipientIdentity);

  if (getTextFieldValue("testFinalScore").length === 0) {
    setRuleCreateFieldValue("testFinalScore", "92");
  }

  if (getTextFieldValue("testCompletionPercent").length === 0) {
    setRuleCreateFieldValue("testCompletionPercent", "100");
  }

  ruleBuilderLastTestSummary = "Not run";
  renderSourceReadiness();
  validateConditionCards(true);
  setStatus(ruleCreateStatus, "Applied test facts preset.", false);
  syncRuleBuilderSummary("Applied test facts preset.");
};
