const applyTemplatePreset = () => {
  const presetKey =
    ruleBuilderTemplatePreset instanceof HTMLSelectElement
      ? ruleBuilderTemplatePreset.value.trim()
      : "course_and_grade";

  if (presetKey === "blank") {
    ruleBuilderJsonOnlyDefinitionActive = false;
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

  if (presetKey === "custom") {
    setStatus(ruleCreateStatus, "Current custom requirements kept.", false, "success");
    syncSuggestedRuleName();
    syncRuleBuilderSummary("Current custom requirements kept.");
    return;
  }

  const selectedTemplate =
    buildDefaultTemplateDefinitions(getDefaultCourseId())[presetKey] ??
    buildDefaultTemplateDefinitions(getDefaultCourseId()).course_and_grade;
  ruleBuilderDefinitionJson.value = JSON.stringify(selectedTemplate, null, 2);
  applyDefinitionToBuilder(selectedTemplate, "Template");
  syncSuggestedRuleName();
};
