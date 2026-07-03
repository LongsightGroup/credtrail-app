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
  const presetKey =
    ruleBuilderTemplatePreset instanceof HTMLSelectElement
      ? ruleBuilderTemplatePreset.value.trim()
      : ruleBuilderTestPresetSelect instanceof HTMLSelectElement
        ? ruleBuilderTestPresetSelect.value.trim()
        : "canvas_course_grade";
  const learnerId = getTextFieldValue("testLearnerId") || "canvas:12345";
  const recipientIdentity = getTextFieldValue("testRecipientIdentity") || "learner@example.edu";
  const courseId = getDefaultCourseId() || getCoursePlaceholder();
  const programCourseIds = deriveRelatedCourseIds(courseId, 3);
  const surveyId = courseId + "_EXIT_SURVEY";

  setRuleCreateFieldValue("testLearnerId", learnerId);
  setRuleCreateFieldValue("testRecipientIdentity", recipientIdentity);

  if (presetKey === "program_completion") {
    setRuleCreateFieldValue("testFinalScore", "92");
    setRuleCreateFieldValue(
      "testFactsJson",
      JSON.stringify(
        {
          completions: programCourseIds.map((entry) => {
            return {
              courseId: entry,
              learnerId,
              completed: true,
              completionPercent: 100,
            };
          }),
        },
        null,
        2,
      ),
    );
  } else if (presetKey === "assignment_submission") {
    setRuleCreateFieldValue("testFinalScore", "88");
    setRuleCreateFieldValue(
      "testFactsJson",
      JSON.stringify(
        {
          submissions: [
            {
              courseId,
              assignmentId: "assignment_1",
              learnerId,
              score: 88,
              workflowState: "submitted",
              submittedAt: new Date().toISOString(),
            },
          ],
        },
        null,
        2,
      ),
    );
  } else if (presetKey === "prerequisite_chain" || presetKey === "prerequisite_badge") {
    setRuleCreateFieldValue("testFinalScore", "95");
    setRuleCreateFieldValue(
      "testFactsJson",
      JSON.stringify(
        {
          earnedBadgeTemplateIds: ["badge_template_foundations"],
        },
        null,
        2,
      ),
    );
  } else if (presetKey === "survey_completion") {
    setRuleCreateFieldValue("testFinalScore", "92");
    setRuleCreateFieldValue(
      "testFactsJson",
      JSON.stringify(
        {
          surveyCompletions: [
            {
              surveyId,
              learnerId,
              source: "qualtrics",
              completed: true,
              completedAt: new Date().toISOString(),
            },
          ],
        },
        null,
        2,
      ),
    );
  } else if (presetKey === "custom_field") {
    setRuleCreateFieldValue("testFinalScore", "92");
    setRuleCreateFieldValue(
      "testFactsJson",
      JSON.stringify(
        {
          customFields: [
            {
              learnerId,
              fieldName: "programStanding",
              value: "eligible",
            },
          ],
        },
        null,
        2,
      ),
    );
  } else {
    setRuleCreateFieldValue("testFinalScore", "92");
    setRuleCreateFieldValue("testCompletionPercent", "100");
    setRuleCreateFieldValue("testFactsJson", "");
  }

  ruleBuilderLastTestSummary = "Not run";
  renderSourceReadiness();
  validateConditionCards(true);
  setStatus(ruleCreateStatus, "Applied test facts preset.", false);
  syncRuleBuilderSummary("Applied test facts preset.");
};
