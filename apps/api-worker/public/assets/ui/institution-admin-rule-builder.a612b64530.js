(() => {
const readAdminContext = () => {
  const contextElement = document.getElementById("ct-admin-context");

  if (!(contextElement instanceof HTMLElement)) {
    return null;
  }

  const contextJson =
    contextElement.dataset.contextJson ??
    (contextElement instanceof HTMLScriptElement ? contextElement.textContent : null) ??
    "{}";

  try {
    const parsedContext = JSON.parse(contextJson);

    return parsedContext && typeof parsedContext === "object" ? parsedContext : null;
  } catch {
    return null;
  }
};

const setStatus = (el, text, isError, tone = "info") => {
  if (!(el instanceof HTMLElement)) {
    return;
  }

  el.textContent = text;
  el.dataset.tone = isError ? "error" : tone;
};

const parseJsonBody = async (response) => {
  try {
    return await response.json();
  } catch {
    return null;
  }
};

const errorDetailFromPayload = (payload) => {
  return payload && typeof payload.error === "string" ? payload.error : "Request failed";
};

const setCodeOutput = (el, value) => {
  if (!(el instanceof HTMLElement)) {
    return;
  }

  if (typeof value !== "string" || value.length === 0) {
    el.hidden = true;
    el.textContent = "";
    return;
  }

  el.hidden = false;
  el.textContent = value;
};

const createRuleBuilderAuthoringController = (dependencies) => {
  let state = "idle";

  const execute = async (input) => {
    if (state !== "idle") {
      return { status: "ignored" };
    }

    state = "submitting";

    try {
      const response = await dependencies.request(input.apiPath, {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify(input.payload),
      });
      const payload = await dependencies.parseResponse(response);

      if (!response.ok) {
        state = "idle";
        return {
          status: "rejected",
          message: dependencies.errorMessage(payload),
        };
      }

      const outcome =
        payload && typeof payload === "object" && typeof payload.outcome === "string"
          ? payload.outcome
          : "";

      if (
        outcome !== "draft_saved" &&
        outcome !== "pending_approval" &&
        outcome !== "approved"
      ) {
        state = "idle";
        return {
          status: "rejected",
          message: "CredTrail returned an invalid rule authoring outcome.",
        };
      }

      state = "completed";
      return {
        status: "completed",
        outcome,
      };
    } catch {
      state = "idle";
      return { status: "unknown" };
    }
  };

  return {
    execute,
    state: () => state,
  };
};

const parsedContext = readAdminContext();

if (!parsedContext) {
  return;
}

const tenantAdminPath =
  typeof parsedContext.tenantAdminPath === "string" ? parsedContext.tenantAdminPath : "";
const rulesListPath =
  typeof parsedContext.rulesListPath === "string" ? parsedContext.rulesListPath : "";
const badgeRuleApiPath =
  typeof parsedContext.badgeRuleApiPath === "string" ? parsedContext.badgeRuleApiPath : "";
const lmsConnectionsApiPath =
  typeof parsedContext.lmsConnectionsApiPath === "string"
    ? parsedContext.lmsConnectionsApiPath
    : "";

if (
  tenantAdminPath.length === 0 ||
  rulesListPath.length === 0 ||
  badgeRuleApiPath.length === 0 ||
  lmsConnectionsApiPath.length === 0
) {
  return;
}

const ruleCreateForm = document.getElementById("rule-create-form");
const ruleCreateStatus = document.getElementById("rule-create-status");
const ruleBuilderConditionList = document.getElementById("rule-builder-condition-list");
const ruleBuilderConditionCardTemplate = document.getElementById(
  "rule-builder-condition-card-template",
);
const ruleBuilderRootLogic = document.getElementById("rule-builder-root-logic");
const ruleBuilderDefinitionJson = document.getElementById("rule-builder-definition-json");
const ruleBuilderTemplatePreset = document.getElementById("rule-builder-template-preset");
const ruleBuilderLmsConnectionSelect = document.getElementById("rule-builder-lms-connection");
const ruleBuilderLmsStatus = document.getElementById("rule-builder-lms-status");
const ruleBuilderLmsProviderKindInput = document.getElementById("rule-builder-lms-provider-kind");
const ruleBuilderApplyTemplateButton = document.getElementById("rule-builder-apply-template");
const ruleBuilderAddConditionButton = document.getElementById("rule-builder-add-condition");
const ruleBuilderAddAlternativePathButton = document.getElementById(
  "rule-builder-add-alternative-path",
);
const ruleBuilderRequireEveryRequirementButton = document.getElementById(
  "rule-builder-require-every-requirement",
);
const ruleBuilderExportJsonButton = document.getElementById("rule-builder-export-json");
const ruleBuilderImportJsonButton = document.getElementById("rule-builder-import-json");
const ruleBuilderImportFileInput = document.getElementById("rule-builder-import-file");
const ruleBuilderApplyJsonButton = document.getElementById("rule-builder-apply-json");
const ruleBuilderCloneRuleSelect = document.getElementById("rule-builder-clone-rule");
const ruleBuilderCloneLoadButton = document.getElementById("rule-builder-clone-load");
const ruleBuilderTestButton = document.getElementById("rule-builder-test");
const ruleBuilderTestOutput = document.getElementById("rule-builder-test-output");
const ruleBuilderTestResult = document.getElementById("rule-builder-test-result");
const ruleBuilderLiveTestFields = document.getElementById("rule-builder-live-test-fields");
const ruleBuilderExampleTestFields = document.getElementById("rule-builder-example-test-fields");
const ruleBuilderLearnerSelect = document.getElementById("rule-builder-learner-select");
const ruleBuilderLearnerFilter = document.getElementById("rule-builder-learner-filter");
const ruleBuilderLearnerFilterQuery = document.getElementById(
  "rule-builder-learner-filter-query",
);
const ruleBuilderLearnerStatus = document.getElementById("rule-builder-learner-status");
const ruleBuilderTestRecipientFields = document.getElementById(
  "rule-builder-test-recipient-fields",
);
const ruleBuilderExampleTestAdvanced = document.getElementById(
  "rule-builder-example-test-advanced",
);
const ruleBuilderTestDataSourceInputs = Array.from(
  document.querySelectorAll('input[name="testDataSource"]'),
).filter((candidate) => candidate instanceof HTMLInputElement);
const ruleBuilderStepNextButton = document.getElementById("rule-builder-step-next");
const ruleBuilderStepProgress = document.getElementById("rule-builder-step-progress");
const ruleBuilderStepCallout = document.getElementById("rule-builder-step-callout");
const ruleBuilderSubmitButton = document.getElementById("rule-builder-submit");
const ruleBuilderSaveFormalDraftButton = document.getElementById(
  "rule-builder-save-formal-draft",
);
const ruleBuilderAuthoringController = createRuleBuilderAuthoringController({
  request: fetch,
  parseResponse: parseJsonBody,
  errorMessage: errorDetailFromPayload,
});
const ruleBuilderSaveDraftButton = document.getElementById("rule-builder-save-draft");
const ruleBuilderDraftStatus = document.getElementById("rule-builder-draft-status");
const ruleBuilderCanvasCount = document.getElementById("rule-builder-canvas-count");
const ruleBuilderCanvasLogic = document.getElementById("rule-builder-canvas-logic");
const ruleBuilderFlowMode = document.getElementById("rule-builder-flow-mode");
const ruleBuilderFlowEmpty = document.getElementById("rule-builder-flow-empty");
const ruleBuilderFlowList = document.getElementById("rule-builder-flow-list");
const ruleBuilderSummaryMessage = document.getElementById("rule-builder-summary-message");
const ruleBuilderSummaryRuleName = document.getElementById("rule-builder-summary-rule-name");
const ruleBuilderSummaryConditionCount = document.getElementById(
  "rule-builder-summary-condition-count",
);
const ruleBuilderSummaryRootLogic = document.getElementById("rule-builder-summary-root-logic");
const ruleBuilderSummaryValidity = document.getElementById("rule-builder-summary-validity");
const ruleBuilderSummaryLastTest = document.getElementById("rule-builder-summary-last-test");
const ruleBuilderSourceList = document.getElementById("rule-builder-source-list");
const ruleBuilderSourceSample = document.getElementById("rule-builder-source-sample");
const ruleBuilderStepButtons = Array.from(
  document.querySelectorAll("[data-rule-step-target]"),
).filter((candidate) => candidate instanceof HTMLButtonElement);
const ruleBuilderContext =
  parsedContext &&
  parsedContext.ruleBuilderContext &&
  typeof parsedContext.ruleBuilderContext === "object"
    ? parsedContext.ruleBuilderContext
    : {};
const initialRuleValueLists =
  ruleBuilderContext && Array.isArray(ruleBuilderContext.valueLists)
    ? ruleBuilderContext.valueLists
    : [];
let ruleValueLists = initialRuleValueLists;

/* admin-status-pill-class-helper.js */
var adminStatusPillClass = function adminStatusPillClass(tone) {
  const normalizedTone = typeof tone === "string" ? tone.trim() : "";
  return normalizedTone.length === 0
    ? "ct-admin__status-pill"
    : "ct-admin__status-pill ct-admin__status-pill--" + normalizedTone;
};


  if (
    ruleCreateForm instanceof HTMLFormElement &&
    ruleCreateStatus instanceof HTMLElement &&
    ruleBuilderConditionList instanceof HTMLElement &&
    ruleBuilderRootLogic instanceof HTMLInputElement &&
    ruleBuilderDefinitionJson instanceof HTMLTextAreaElement
  ) {
    const badgeRulePreviewApiPath = badgeRuleApiPath + '/preview-evaluate';
    const ruleBuilderContext =
      parsedContext &&
      parsedContext.ruleBuilderContext &&
      typeof parsedContext.ruleBuilderContext === 'object'
        ? parsedContext.ruleBuilderContext
        : null;
    const editRuleContext =
      ruleBuilderContext &&
      ruleBuilderContext.editRule &&
      typeof ruleBuilderContext.editRule === 'object' &&
      !Array.isArray(ruleBuilderContext.editRule) &&
      typeof ruleBuilderContext.editRule.id === 'string'
        ? ruleBuilderContext.editRule
        : null;
    const builderDraftContext =
      ruleBuilderContext &&
      ruleBuilderContext.builderDraft &&
      typeof ruleBuilderContext.builderDraft === 'object' &&
      !Array.isArray(ruleBuilderContext.builderDraft)
        ? ruleBuilderContext.builderDraft
        : null;
    const isRuleBuilderEditMode = editRuleContext !== null;
    const ruleBuilderSubmitApiPath = isRuleBuilderEditMode
      ? badgeRuleApiPath + '/' + encodeURIComponent(editRuleContext.id) + '/draft'
      : badgeRuleApiPath;
    const ruleBuilderDraftApiPath =
      ruleBuilderContext && typeof ruleBuilderContext.badgeRuleBuilderDraftApiPath === "string"
        ? ruleBuilderContext.badgeRuleBuilderDraftApiPath
        : "";
    const badgeTemplateCourseMap = new Map();
    const badgeTemplatesContext =
      ruleBuilderContext && Array.isArray(ruleBuilderContext.badgeTemplates)
        ? ruleBuilderContext.badgeTemplates
        : [];
    const lmsConnectionsContext =
      ruleBuilderContext && Array.isArray(ruleBuilderContext.lmsConnections)
        ? ruleBuilderContext.lmsConnections
        : [];
    const lmsConnectionsById = new Map();

    badgeTemplatesContext.forEach((entry) => {
      if (entry && typeof entry.id === 'string') {
        badgeTemplateCourseMap.set(
          entry.id,
          typeof entry.defaultCourseId === 'string' && entry.defaultCourseId.length > 0
            ? entry.defaultCourseId
            : null,
        );
      }
    });

    lmsConnectionsContext.forEach((entry) => {
      if (entry && typeof entry.id === 'string') {
        lmsConnectionsById.set(entry.id, entry);
      }
    });

    const getSelectedLmsConnectionId = () => {
      return getTextFieldValue('lmsConnectionId');
    };

    const getSelectedLmsConnection = () => {
      const connectionId = getSelectedLmsConnectionId();
      return connectionId.length > 0 ? lmsConnectionsById.get(connectionId) ?? null : null;
    };

    const getSelectedLmsProviderKind = () => {
      const connection = getSelectedLmsConnection();
      return connection && typeof connection.providerKind === 'string'
        ? connection.providerKind
        : getTextFieldValue('lmsProviderKind');
    };

    const syncSelectedLmsProviderKind = () => {
      const connection = getSelectedLmsConnection();
      const providerKind =
        connection && typeof connection.providerKind === 'string' ? connection.providerKind : '';

      if (ruleBuilderLmsProviderKindInput instanceof HTMLInputElement) {
        ruleBuilderLmsProviderKindInput.value = providerKind;
      }
    };

    const fallbackCourseId =
      ruleBuilderContext &&
      typeof ruleBuilderContext.fallbackCourseId === 'string' &&
      ruleBuilderContext.fallbackCourseId.length > 0
        ? ruleBuilderContext.fallbackCourseId
        : '';

    const getSelectedBadgeTemplateId = () => {
      return getTextFieldValue('badgeTemplateId');
    };

    const deriveRelatedCourseIds = (courseId, count) => {
      const ids = [courseId];
      const match = courseId.match(/^(.+?)(\d+)([A-Z]?)$/i);

      if (match) {
        const prefix = match[1];
        const number = Number(match[2]);
        const suffix = match[3] ?? '';

        for (let index = 1; index < count; index += 1) {
          ids.push(prefix + String(number + index) + suffix);
        }

        return ids;
      }

      for (let index = 1; index < count; index += 1) {
        ids.push(courseId + '-' + String(index + 1));
      }

      return ids;
    };

    const getDefaultCourseId = () => {
      const templateId = getSelectedBadgeTemplateId();
      const fromTemplate =
        templateId.length > 0 ? badgeTemplateCourseMap.get(templateId) : null;

      if (typeof fromTemplate === 'string' && fromTemplate.length > 0) {
        return fromTemplate;
      }

      if (fallbackCourseId.length > 0) {
        return fallbackCourseId;
      }

      return '';
    };

    const getCoursePlaceholder = () => {
      const courseId = getDefaultCourseId();

      return courseId.length > 0 ? courseId : 'COURSE_ID';
    };

    const buildDefaultTemplateDefinitions = (courseId) => {
      const primaryCourseId = courseId.length > 0 ? courseId : 'COURSE_ID';
      const programCourseIds = deriveRelatedCourseIds(primaryCourseId, 3);
      const nextCourseId = programCourseIds[1] ?? primaryCourseId + '-2';
      const surveyId = primaryCourseId + '_EXIT_SURVEY';

      return {
        blank: {
          conditions: {
            all: [
              {
                type: 'course_completion',
                courseId: primaryCourseId,
                minCompletionPercent: 100,
              },
            ],
          },
        },
        course_completion: {
          conditions: {
            all: [
              {
                type: 'course_completion',
                courseId: primaryCourseId,
                minCompletionPercent: 100,
              },
            ],
          },
        },
        course_and_grade: {
          conditions: {
            all: [
              {
                type: 'course_completion',
                courseId: primaryCourseId,
                minCompletionPercent: 100,
              },
              {
                type: 'grade_threshold',
                courseId: primaryCourseId,
                scoreField: 'final_score',
                minScore: 80,
              },
            ],
          },
        },
        program_completion: {
          conditions: {
            all: [
              {
                type: 'program_completion',
                courseIds: programCourseIds,
                minimumCompleted: 3,
              },
            ],
          },
        },
        assignment_submission: {
          conditions: {
            all: [
              {
                type: 'assignment_submission',
                courseId: primaryCourseId,
                assignmentId: '',
                requireSubmitted: true,
              },
            ],
          },
        },
        survey_completion: {
          conditions: {
            all: [
              {
                type: 'survey_completion',
                source: 'qualtrics',
                surveyId,
                requireCompleted: true,
              },
            ],
          },
        },
        time_limited: {
          conditions: {
            all: [
              {
                type: 'course_completion',
                courseId: primaryCourseId,
                minCompletionPercent: 100,
              },
              {
                type: 'time_window',
                notBefore: new Date().toISOString(),
              },
            ],
          },
        },
        custom_field: {
          conditions: {
            all: [
              {
                type: 'custom_field',
                fieldName: 'programStanding',
                operator: 'equals',
                expectedValue: 'eligible',
              },
            ],
          },
        },
        prerequisite_chain: {
          conditions: {
            all: [
              {
                type: 'prerequisite_badge',
                badgeTemplateId: 'badge_template_foundations',
              },
              {
                type: 'course_completion',
                courseId: nextCourseId,
                minCompletionPercent: 100,
              },
            ],
          },
        },
      };
    };
    let runRuleBuilderTest = async () => {};
    const conditionTypeLabels = {
      course_completion: 'Course completion',
      grade_threshold: 'Grade threshold',
      program_completion: 'Course pathway completion',
      assignment_submission: 'Gradebook item submitted',
      survey_completion: 'Survey completion',
      time_window: 'Time window',
      prerequisite_badge: 'Prerequisite badge',
      custom_field: 'Custom field',
    };
    const getRuleBuilderRootLogic = () => {
      return ruleBuilderRootLogic.value === 'any' ? 'any' : 'all';
    };
    const setRuleBuilderRootLogic = (value) => {
      const normalizedValue = value === 'any' ? 'any' : 'all';

      ruleBuilderRootLogic.value = normalizedValue;
      syncRootLogicToolbarVisibility();
    };
    const conditionTypeHelpText = {
      course_completion:
        'Learner must complete all gradebook items, or a configured percentage of them.',
      grade_threshold:
        'Learner score must meet the configured minimum and/or maximum threshold.',
      program_completion:
        'Learner must complete the required number of selected courses. A course is complete when all of its gradebook items are complete.',
      assignment_submission:
        'Learner must submit an assignment, assessment, or gradebook item, with optional score constraints.',
      survey_completion:
        'Learner must complete a required survey, such as an exit survey or attestation.',
      time_window:
        'Badge can only be earned inside the configured date-time window.',
      prerequisite_badge:
        'Learner must already hold a specific prerequisite badge.',
      custom_field:
        'Learner must match an institution-specific field from imported or connected data.',
    };

    function syncExclusiveFieldPair(card, valueFieldName, listFieldName) {
      const valueField = card.querySelector('[data-field="' + valueFieldName + '"]');
      const listField = card.querySelector('[data-field="' + listFieldName + '"]');
      const readExclusiveValue = (field) => {
        if (field instanceof HTMLSelectElement && field.multiple) {
          return Array.from(field.selectedOptions)
            .map((option) => option.value.trim())
            .filter((value) => value.length > 0)
            .join(',');
        }

        if (
          field instanceof HTMLInputElement ||
          field instanceof HTMLTextAreaElement ||
          field instanceof HTMLSelectElement
        ) {
          return field.value.trim();
        }

        return '';
      };
      const valueFieldText =
        valueField instanceof HTMLInputElement ||
        valueField instanceof HTMLTextAreaElement ||
        valueField instanceof HTMLSelectElement
          ? readExclusiveValue(valueField)
          : '';
      const listFieldText = listField instanceof HTMLSelectElement ? listField.value.trim() : '';

      if (
        !(
          valueField instanceof HTMLInputElement ||
          valueField instanceof HTMLTextAreaElement ||
          valueField instanceof HTMLSelectElement
        ) ||
        !(listField instanceof HTMLSelectElement)
      ) {
        return;
      }

      if (valueFieldText.length > 0 && listFieldText.length > 0) {
        valueField.disabled = false;
        listField.disabled = false;
        return;
      }

      valueField.disabled = listFieldText.length > 0;
      listField.disabled = valueFieldText.length > 0;
    }

    function bindExclusiveFieldPair(card, valueFieldName, listFieldName) {
      const valueField = card.querySelector('[data-field="' + valueFieldName + '"]');
      const listField = card.querySelector('[data-field="' + listFieldName + '"]');

      if (
        !(
          valueField instanceof HTMLInputElement ||
          valueField instanceof HTMLTextAreaElement ||
          valueField instanceof HTMLSelectElement
        ) ||
        !(listField instanceof HTMLSelectElement)
      ) {
        return;
      }

      const syncPair = () => {
        syncExclusiveFieldPair(card, valueFieldName, listFieldName);
      };

      valueField.addEventListener('input', syncPair);
      valueField.addEventListener('change', syncPair);
      listField.addEventListener('change', syncPair);
      syncPair();
    }


    const getRuleCreateField = (fieldName) => {
      return ruleCreateForm.elements.namedItem(fieldName);
    };

    const getTextFieldValue = (fieldName) => {
      const field = getRuleCreateField(fieldName);

      if (field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement) {
        return field.value.trim();
      }

      if (field instanceof HTMLSelectElement) {
        return field.value.trim();
      }

      return '';
    };

    const getCheckboxFieldValue = (fieldName) => {
      const field = getRuleCreateField(fieldName);
      return field instanceof HTMLInputElement ? field.checked : false;
    };

    const setRuleCreateFieldValue = (fieldName, value) => {
      const field = getRuleCreateField(fieldName);

      if (field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement) {
        field.value = value;
      }

      if (field instanceof HTMLSelectElement) {
        field.value = value;
      }
    };

    const getRuleBuilderTestDataSource = () => {
      const checkedInput = ruleBuilderTestDataSourceInputs.find((candidate) => candidate.checked);

      return checkedInput instanceof HTMLInputElement && checkedInput.value === 'example'
        ? 'example'
        : 'lms';
    };

    const syncRuleBuilderTestDataSource = () => {
      const useExampleData = getRuleBuilderTestDataSource() === 'example';

      if (ruleBuilderLiveTestFields instanceof HTMLElement) {
        ruleBuilderLiveTestFields.hidden = useExampleData;
      }

      if (ruleBuilderExampleTestFields instanceof HTMLElement) {
        ruleBuilderExampleTestFields.hidden = !useExampleData;
      }

      if (ruleBuilderExampleTestAdvanced instanceof HTMLElement) {
        ruleBuilderExampleTestAdvanced.hidden = !useExampleData;
      }

      if (ruleBuilderTestButton instanceof HTMLButtonElement) {
        ruleBuilderTestButton.textContent = useExampleData ? 'Test example data' : 'Test learner';
      }
    };

    const invalidateRuleBuilderTest = () => {
      ruleBuilderLastTestSummary = 'Not run';
      resetConditionEvaluationResults();
      syncRuleBuilderSummary('Test data changed. Run the test again.');
    };

    [
      'testLearnerId',
      'testRecipientIdentity',
      'testFinalScore',
      'testCompletionPercent',
      'testFactsJson',
    ].forEach((fieldName) => {
      const field = getRuleCreateField(fieldName);

      if (
        field instanceof HTMLInputElement ||
        field instanceof HTMLTextAreaElement ||
        field instanceof HTMLSelectElement
      ) {
        field.addEventListener('input', invalidateRuleBuilderTest);
      }
    });

    ruleBuilderTestDataSourceInputs.forEach((candidate) => {
      candidate.addEventListener('change', () => {
        syncRuleBuilderTestDataSource();
        syncRuleBuilderTestRecipientFields();
        invalidateRuleBuilderTest();
        setStatus(
          ruleBuilderTestResult,
          getRuleBuilderTestDataSource() === 'example'
            ? 'Run the test to check the rule with generated example data.'
            : 'Choose an LMS learner, then run the test.',
          false,
        );
      });
    });

    syncRuleBuilderTestDataSource();

    const getSelectedOptionLabel = (field) => {
      if (!(field instanceof HTMLSelectElement)) {
        return '';
      }

      const selectedOption = field.selectedOptions[0];

      if (!(selectedOption instanceof HTMLOptionElement)) {
        return '';
      }

      const optionText = selectedOption.textContent?.trim() ?? '';

      if (optionText.length === 0) {
        return '';
      }

      const templateIdSuffixIndex = optionText.lastIndexOf(' (');

      if (templateIdSuffixIndex > 0) {
        return optionText.slice(0, templateIdSuffixIndex).trim();
      }

      return optionText;
    };

    const buildSuggestedRuleName = () => {
      const badgeTitle = getSelectedOptionLabel(getRuleCreateField('badgeTemplateId'));
      const patternLabel = getSelectedOptionLabel(ruleBuilderTemplatePreset);
      const badgeLabel = badgeTitle.length > 0 ? badgeTitle : 'Badge rule';
      const patternName = patternLabel.length > 0 ? patternLabel : 'Awarding rule';

      return badgeLabel + ' – ' + patternName;
    };

    const syncSuggestedRuleName = () => {
      const ruleNameField = getRuleCreateField('name');

      if (
        ruleNameField instanceof HTMLInputElement &&
        ruleNameField.dataset.ruleBuilderPreserveName === 'true' &&
        ruleNameField.value.trim().length > 0
      ) {
        return;
      }

      const suggestedName = buildSuggestedRuleName();
      setRuleCreateFieldValue('name', suggestedName);
    };

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

const getConditionCards = () => {
  return Array.from(ruleBuilderConditionList.querySelectorAll(".ct-admin__condition-card")).filter(
    (candidate) => candidate instanceof HTMLElement,
  );
};

const readFieldFromCard = (card, fieldName) => {
  const field = card.querySelector('[data-field="' + fieldName + '"]');

  if (field instanceof HTMLSelectElement && field.multiple) {
    return Array.from(field.selectedOptions)
      .map((option) => option.value.trim())
      .filter((value) => value.length > 0)
      .join(",");
  }

  if (
    field instanceof HTMLInputElement ||
    field instanceof HTMLTextAreaElement ||
    field instanceof HTMLSelectElement
  ) {
    return field.value.trim();
  }

  return "";
};

const readCheckboxFromCard = (card, fieldName) => {
  const field = card.querySelector('[data-field="' + fieldName + '"]');
  return field instanceof HTMLInputElement ? field.checked : false;
};

const setFieldOnCard = (card, fieldName, value) => {
  const field = card.querySelector('[data-field="' + fieldName + '"]');

  if (field instanceof HTMLSelectElement && field.multiple) {
    const values = new Set(parseCsv(String(value)));
    Array.from(field.options).forEach((option) => {
      option.selected = values.has(option.value);
    });
    return;
  }

  if (
    field instanceof HTMLInputElement ||
    field instanceof HTMLTextAreaElement ||
    field instanceof HTMLSelectElement
  ) {
    field.value = value;
  }
};

const setCheckboxOnCard = (card, fieldName, checked) => {
  const field = card.querySelector('[data-field="' + fieldName + '"]');

  if (field instanceof HTMLInputElement) {
    field.checked = checked;
  }
};

const parseNumberInput = (value) => {
  if (value.trim().length === 0) {
    return null;
  }

  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
};

const parseCsv = (value) => {
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
};

const parseCustomExpectedValue = (value, valueType) => {
  if (valueType === "number") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  if (valueType === "boolean") {
    const normalized = value.trim().toLowerCase();

    if (normalized === "true" || normalized === "yes" || normalized === "1") {
      return true;
    }

    if (normalized === "false" || normalized === "no" || normalized === "0") {
      return false;
    }

    return null;
  }

  return value.trim().length > 0 ? value.trim() : null;
};

const toDateTimeLocalInput = (isoValue) => {
  if (typeof isoValue !== "string" || isoValue.length < 16) {
    return "";
  }

  return isoValue.slice(0, 16);
};

const toIsoTimestamp = (value) => {
  if (value.length === 0) {
    return undefined;
  }

  const parsed = Date.parse(value);

  if (!Number.isFinite(parsed)) {
    return null;
  }

  return new Date(parsed).toISOString();
};

const cloneRuleBuilderConditionCard = () => {
  if (!(ruleBuilderConditionCardTemplate instanceof HTMLTemplateElement)) {
    return null;
  }

  const firstElement = ruleBuilderConditionCardTemplate.content.firstElementChild;

  if (!(firstElement instanceof HTMLElement)) {
    return null;
  }

  const clone = firstElement.cloneNode(true);

  return clone instanceof HTMLElement ? clone : null;
};

const updateConditionCardClass = (card, conditionType) => {
  card.classList.remove(
    "ct-admin__condition-card--course_completion",
    "ct-admin__condition-card--grade_threshold",
    "ct-admin__condition-card--program_completion",
    "ct-admin__condition-card--assignment_submission",
    "ct-admin__condition-card--survey_completion",
    "ct-admin__condition-card--time_window",
    "ct-admin__condition-card--prerequisite_badge",
    "ct-admin__condition-card--custom_field",
  );
  card.classList.add("ct-admin__condition-card--" + conditionType);
};

const updateConditionPlainSummary = (card) => {
  const summaryElement = card.querySelector(".ct-admin__condition-summary");

  if (!(summaryElement instanceof HTMLElement)) {
    return;
  }

  const typeSelect = card.querySelector(".ct-admin__condition-type");
  const conditionType =
    typeSelect instanceof HTMLSelectElement ? typeSelect.value : "course_completion";
  const negatePrefix = readCheckboxFromCard(card, "negate") ? "Must not: " : "";

  try {
    const condition = readConditionFromCard(card, false);
    summaryElement.textContent = negatePrefix + formatConditionPlainSummary(condition);
    return;
  } catch {
    summaryElement.textContent =
      negatePrefix + (conditionTypeLabels[conditionType] ?? "Requirement");
  }
};

const formatConditionPlainSummary = (condition) => {
  if (!condition || typeof condition !== "object" || typeof condition.type !== "string") {
    return "Requirement";
  }

  if (condition.type === "course_completion") {
    const courseLabel =
      typeof condition.courseListId === "string" && condition.courseListId.length > 0
        ? "courses from list " + condition.courseListId
        : typeof condition.courseId === "string" && condition.courseId.length > 0
          ? condition.courseId
          : "the course";
    const completionPercent =
      typeof condition.minCompletionPercent === "number" ? condition.minCompletionPercent : 100;

    return (
      "Learner has completed at least " +
      String(completionPercent) +
      "% of gradebook items in " +
      courseLabel
    );
  }

  if (condition.type === "grade_threshold") {
    const courseLabel =
      typeof condition.courseListId === "string" && condition.courseListId.length > 0
        ? "courses from list " + condition.courseListId
        : typeof condition.courseId === "string" && condition.courseId.length > 0
          ? condition.courseId
          : "the course";
    const scoreField = condition.scoreField === "current_score" ? "current score" : "final score";
    const minScore =
      typeof condition.minScore === "number" ? " at least " + String(condition.minScore) : "";
    const maxScore =
      typeof condition.maxScore === "number" ? " no more than " + String(condition.maxScore) : "";

    return "Learner " + scoreField + " in " + courseLabel + " is" + minScore + maxScore;
  }

  if (condition.type === "program_completion") {
    const courseCount = Array.isArray(condition.courseIds) ? condition.courseIds.length : 0;
    const minimumCompleted =
      typeof condition.minimumCompleted === "number" ? condition.minimumCompleted : courseCount;

    if (typeof condition.courseListId === "string" && condition.courseListId.length > 0) {
      return (
        "Learner completes at least " +
        String(minimumCompleted) +
        " courses from list " +
        condition.courseListId
      );
    }

    const courseLabel = courseCount > 0 ? condition.courseIds.join(", ") : "required courses";

    return "Learner completes at least " + String(minimumCompleted) + " of: " + courseLabel;
  }

  if (condition.type === "assignment_submission") {
    const courseLabel =
      typeof condition.courseId === "string" && condition.courseId.length > 0
        ? condition.courseId
        : "the course";
    const assignmentLabel =
      typeof condition.assignmentId === "string" && condition.assignmentId.length > 0
        ? condition.assignmentId
        : "the assignment";
    const minScore =
      typeof condition.minScore === "number"
        ? " with score at least " + String(condition.minScore)
        : "";

    return "Learner submits gradebook item " + assignmentLabel + " in " + courseLabel + minScore;
  }

  if (condition.type === "survey_completion") {
    const surveyLabel =
      typeof condition.surveyId === "string" && condition.surveyId.length > 0
        ? condition.surveyId
        : "the required survey";

    return "Learner completes survey " + surveyLabel;
  }

  if (condition.type === "time_window") {
    const notBefore =
      typeof condition.notBefore === "string" && condition.notBefore.length > 0
        ? " after " + condition.notBefore
        : "";
    const notAfter =
      typeof condition.notAfter === "string" && condition.notAfter.length > 0
        ? " before " + condition.notAfter
        : "";

    return "Badge can only be earned" + notBefore + notAfter;
  }

  if (condition.type === "prerequisite_badge") {
    const badgeLabel =
      typeof condition.badgeTemplateListId === "string" && condition.badgeTemplateListId.length > 0
        ? "badges from list " + condition.badgeTemplateListId
        : typeof condition.badgeTemplateId === "string" && condition.badgeTemplateId.length > 0
          ? condition.badgeTemplateId
          : "a prerequisite badge";

    return "Learner already holds " + badgeLabel;
  }

  if (condition.type === "custom_field") {
    const fieldName =
      typeof condition.fieldName === "string" && condition.fieldName.length > 0
        ? condition.fieldName
        : "custom field";
    const expectedValue =
      typeof condition.expectedValue === "string" && condition.expectedValue.length > 0
        ? condition.expectedValue
        : "expected value";

    return (
      "Learner " +
      fieldName +
      " " +
      (typeof condition.operator === "string" ? condition.operator : "matches") +
      " " +
      expectedValue
    );
  }

  return conditionTypeLabels[condition.type] ?? "Requirement";
};

const setConditionResultState = (card, state, detail) => {
  card.classList.remove(
    "ct-admin__condition-card--result-pass",
    "ct-admin__condition-card--result-fail",
    "ct-admin__condition-card--result-review",
    "ct-admin__condition-card--result-idle",
  );
  card.classList.add("ct-admin__condition-card--result-" + state);

  const resultElement = card.querySelector(".ct-admin__condition-result");

  if (resultElement instanceof HTMLElement) {
    resultElement.dataset.state = state;
    resultElement.textContent = detail;
  }
};

const createConditionInput = (type, attributes) => {
  const input = document.createElement("input");
  input.type = type;

  Object.entries(attributes).forEach(([name, value]) => {
    if (value === true) {
      input.setAttribute(name, "");
      return;
    }

    if (value !== false && value !== null && value !== undefined) {
      input.setAttribute(name, String(value));
    }
  });

  return input;
};

const createConditionOption = (value, label, selected) => {
  const option = document.createElement("option");
  option.value = value;
  option.textContent = label;
  option.selected = selected;
  return option;
};

const createConditionSelect = (attributes, options) => {
  const select = document.createElement("select");

  Object.entries(attributes).forEach(([name, value]) => {
    if (value === true) {
      select.setAttribute(name, "");
      return;
    }

    if (value !== false && value !== null && value !== undefined) {
      select.setAttribute(name, String(value));
    }
  });

  select.append(...options);
  return select;
};

const createConditionField = (labelText, control, styled) => {
  const field = document.createElement("label");
  field.className = styled === false ? "" : "ct-field ct-admin__field ct-admin__condition-field";
  const fieldLabel = document.createElement("span");
  fieldLabel.className = "ct-field__label";
  fieldLabel.textContent = labelText;
  if (control.tagName === "INPUT" && control.type !== "checkbox" && control.type !== "radio") {
    control.classList.add("ct-input", "ct-field__control");
  }
  if (control.tagName === "SELECT") {
    control.classList.add("ct-select", "ct-field__control");
  }
  if (control.tagName === "TEXTAREA") {
    control.classList.add("ct-textarea", "ct-field__control");
  }
  field.append(fieldLabel, control);
  return field;
};

const createConditionCheckbox = (fieldName, labelText, checked) => {
  const field = document.createElement("label");
  const checkbox = createConditionInput("checkbox", { "data-field": fieldName });
  checkbox.className = "ct-checkbox-field__control";
  checkbox.checked = checked;
  const fieldLabel = document.createElement("span");
  fieldLabel.className = "ct-checkbox-field__label";
  fieldLabel.textContent = labelText;
  field.className = "ct-checkbox-field ct-admin__checkbox-row";
  field.append(checkbox, fieldLabel);
  return field;
};

const replaceConditionFields = (fieldsContainer, fields) => {
  fieldsContainer.replaceChildren(...fields);
};

const createCourseSearchField = (targetFieldName) => {
  return createConditionField(
    "Course search",
    createConditionInput("search", {
      "data-lms-course-query": targetFieldName,
      placeholder: "Search by title, code, or ID",
    }),
  );
};

const createCourseSelectField = (labelText, fieldName, selectedValue, multiple) => {
  const selectedCourseIds = parseCsv(selectedValue);
  const attributes = {
    "data-field": fieldName,
    "data-lms-course-select": true,
    multiple,
    required: multiple ? false : true,
    size: multiple ? "6" : null,
  };

  if (multiple) {
    attributes["data-selected-values"] = selectedValue;
  } else {
    attributes["data-selected-value"] = selectedValue;
  }

  return createConditionField(
    labelText,
    createConditionSelect(attributes, [
      createConditionOption("", "Loading courses...", selectedCourseIds.length === 0),
      ...selectedCourseIds.map((courseId) => createConditionOption(courseId, courseId, true)),
    ]),
  );
};

const createListSelectField = (labelText, fieldName, kind, selectedValue, emptyLabel) => {
  const options = [
    createConditionOption("", emptyLabel, selectedValue.length === 0),
    ...ruleValueLists
      .filter((valueList) => valueList.kind === kind)
      .map((valueList) => {
        const label =
          typeof valueList.label === "string" && valueList.label.length > 0
            ? valueList.label
            : valueList.id;
        return createConditionOption(
          valueList.id,
          label +
            " · " +
            String(Array.isArray(valueList.values) ? valueList.values.length : 0) +
            " values",
          valueList.id === selectedValue,
        );
      }),
  ];

  return createConditionField(
    labelText,
    createConditionSelect({ "data-field": fieldName }, options),
    false,
  );
};

const renderCourseCompletionFields = (card, fieldsContainer, seed) => {
  const selectedCourseId = typeof seed.courseId === "string" ? seed.courseId : "";
  replaceConditionFields(fieldsContainer, [
    createCourseSearchField("courseId"),
    createCourseSelectField("LMS course", "courseId", selectedCourseId, false),
    createConditionField(
      "Gradebook completion at least %",
      createConditionInput("number", {
        "data-field": "minCompletionPercent",
        min: "0",
        max: "100",
        step: "0.01",
      }),
    ),
  ]);

  setFieldOnCard(
    card,
    "courseListId",
    typeof seed.courseListId === "string" ? seed.courseListId : "",
  );
  setFieldOnCard(
    card,
    "minCompletionPercent",
    typeof seed.minCompletionPercent === "number" ? String(seed.minCompletionPercent) : "100",
  );
  bindExclusiveFieldPair(card, "courseId", "courseListId");
  bindSearchableCourseSelect(card, "courseId");
  updateConditionPlainSummary(card);
};

const renderGradeThresholdFields = (card, fieldsContainer, seed) => {
  const selectedCourseId = typeof seed.courseId === "string" ? seed.courseId : "";
  replaceConditionFields(fieldsContainer, [
    createCourseSearchField("courseId"),
    createCourseSelectField("LMS course", "courseId", selectedCourseId, false),
    createConditionField(
      "Gradebook score field",
      createConditionSelect({ "data-field": "scoreField" }, [
        createConditionOption("final_score", "Final score", false),
        createConditionOption("current_score", "Current score", false),
      ]),
    ),
    createConditionField(
      "Minimum score (optional)",
      createConditionInput("number", {
        "data-field": "minScore",
        min: "0",
        max: "100",
        step: "0.01",
      }),
    ),
    createConditionField(
      "Maximum score (optional)",
      createConditionInput("number", {
        "data-field": "maxScore",
        min: "0",
        max: "100",
        step: "0.01",
      }),
    ),
  ]);

  setFieldOnCard(
    card,
    "courseListId",
    typeof seed.courseListId === "string" ? seed.courseListId : "",
  );
  setFieldOnCard(
    card,
    "scoreField",
    seed.scoreField === "current_score" ? "current_score" : "final_score",
  );
  setFieldOnCard(card, "minScore", typeof seed.minScore === "number" ? String(seed.minScore) : "");
  setFieldOnCard(card, "maxScore", typeof seed.maxScore === "number" ? String(seed.maxScore) : "");
  bindExclusiveFieldPair(card, "courseId", "courseListId");
  bindSearchableCourseSelect(card, "courseId");
  updateConditionPlainSummary(card);
};

const renderProgramCompletionFields = (card, fieldsContainer, seed) => {
  const selectedCourseIds = Array.isArray(seed.courseIds) ? seed.courseIds.join(",") : "";
  replaceConditionFields(fieldsContainer, [
    createCourseSearchField("courseIds"),
    createCourseSelectField("Courses", "courseIds", selectedCourseIds, true),
    createConditionField(
      "Minimum completed (optional)",
      createConditionInput("number", {
        "data-field": "minimumCompleted",
        min: "1",
        max: "200",
        step: "1",
      }),
    ),
  ]);

  setFieldOnCard(
    card,
    "courseListId",
    typeof seed.courseListId === "string" ? seed.courseListId : "",
  );
  setFieldOnCard(
    card,
    "minimumCompleted",
    typeof seed.minimumCompleted === "number" ? String(seed.minimumCompleted) : "",
  );
  bindExclusiveFieldPair(card, "courseIds", "courseListId");
  bindSearchableCourseSelect(card, "courseIds");
  updateConditionPlainSummary(card);
};

const renderAssignmentSubmissionFields = (card, fieldsContainer, seed) => {
  const selectedCourseId = typeof seed.courseId === "string" ? seed.courseId : "";
  const selectedAssignmentId = typeof seed.assignmentId === "string" ? seed.assignmentId : "";
  const selectedWorkflowStates = Array.isArray(seed.workflowStates)
    ? seed.workflowStates.join(",")
    : "";
  replaceConditionFields(fieldsContainer, [
    createCourseSearchField("courseId"),
    createCourseSelectField("Course", "courseId", selectedCourseId, false),
    createConditionField(
      "Gradebook item search",
      createConditionInput("search", {
        "data-lms-gradebook-item-query": true,
        placeholder: "Search by title or ID",
      }),
    ),
    createConditionField(
      "Gradebook item",
      createConditionSelect(
        {
          "data-field": "assignmentId",
          "data-lms-gradebook-item-select": true,
          "data-selected-value": selectedAssignmentId,
          required: true,
        },
        [createConditionOption("", "Select course first", false)],
      ),
    ),
    createConditionField(
      "Minimum score (optional)",
      createConditionInput("number", {
        "data-field": "minScore",
        min: "0",
        max: "100",
        step: "0.01",
      }),
    ),
    createConditionField(
      "Workflow states",
      createConditionSelect(
        {
          "data-field": "workflowStates",
          "data-lms-workflow-state-select": true,
          "data-selected-values": selectedWorkflowStates,
          multiple: true,
          size: "5",
        },
        [createConditionOption("", "Select gradebook item first", false)],
      ),
    ),
    createConditionCheckbox("requireSubmitted", "Gradebook item must be submitted", true),
  ]);

  setFieldOnCard(card, "minScore", typeof seed.minScore === "number" ? String(seed.minScore) : "");
  setCheckboxOnCard(
    card,
    "requireSubmitted",
    seed.requireSubmitted === undefined ? true : Boolean(seed.requireSubmitted),
  );
  bindSearchableCourseSelect(card, "courseId");
  bindSearchableGradebookItemSelect(card);
  updateConditionPlainSummary(card);
};

const renderSurveyCompletionFields = (card, fieldsContainer, seed) => {
  const surveyPlaceholder = getCoursePlaceholder() + "_EXIT_SURVEY";
  replaceConditionFields(fieldsContainer, [
    createConditionField(
      "Survey ID",
      createConditionInput("text", {
        "data-field": "surveyId",
        placeholder: surveyPlaceholder,
      }),
    ),
    createConditionField(
      "Source (optional)",
      createConditionInput("text", {
        "data-field": "source",
        placeholder: "qualtrics",
      }),
    ),
    createConditionCheckbox("requireCompleted", "Survey must be completed", true),
  ]);

  setFieldOnCard(card, "surveyId", typeof seed.surveyId === "string" ? seed.surveyId : "");
  setFieldOnCard(card, "source", typeof seed.source === "string" ? seed.source : "");
  setCheckboxOnCard(
    card,
    "requireCompleted",
    seed.requireCompleted === undefined ? true : Boolean(seed.requireCompleted),
  );
  updateConditionPlainSummary(card);
};

const renderTimeWindowFields = (card, fieldsContainer, seed) => {
  replaceConditionFields(fieldsContainer, [
    createConditionField(
      "Not before (optional)",
      createConditionInput("datetime-local", { "data-field": "notBefore" }),
      false,
    ),
    createConditionField(
      "Not after (optional)",
      createConditionInput("datetime-local", { "data-field": "notAfter" }),
      false,
    ),
  ]);

  setFieldOnCard(card, "notBefore", toDateTimeLocalInput(seed.notBefore));
  setFieldOnCard(card, "notAfter", toDateTimeLocalInput(seed.notAfter));
  updateConditionPlainSummary(card);
};

const renderCustomFieldFields = (card, fieldsContainer, seed) => {
  const valueType =
    typeof seed.expectedValue === "number"
      ? "number"
      : typeof seed.expectedValue === "boolean"
        ? "boolean"
        : "string";
  replaceConditionFields(fieldsContainer, [
    createConditionField(
      "Field name",
      createConditionInput("text", {
        "data-field": "fieldName",
        placeholder: "programStanding",
      }),
      false,
    ),
    createConditionField(
      "Operator",
      createConditionSelect({ "data-field": "operator" }, [
        createConditionOption("equals", "Equals", false),
        createConditionOption("not_equals", "Does not equal", false),
        createConditionOption("contains", "Contains", false),
        createConditionOption("greater_than_or_equal", "Greater than or equal", false),
        createConditionOption("less_than_or_equal", "Less than or equal", false),
      ]),
      false,
    ),
    createConditionField(
      "Value type",
      createConditionSelect({ "data-field": "expectedValueType" }, [
        createConditionOption("string", "Text", false),
        createConditionOption("number", "Number", false),
        createConditionOption("boolean", "True/false", false),
      ]),
      false,
    ),
    createConditionField(
      "Expected value",
      createConditionInput("text", {
        "data-field": "expectedValue",
        placeholder: "eligible",
      }),
      false,
    ),
  ]);

  setFieldOnCard(card, "fieldName", typeof seed.fieldName === "string" ? seed.fieldName : "");
  setFieldOnCard(card, "operator", typeof seed.operator === "string" ? seed.operator : "equals");
  setFieldOnCard(card, "expectedValueType", valueType);
  setFieldOnCard(
    card,
    "expectedValue",
    seed.expectedValue === undefined ? "" : String(seed.expectedValue),
  );
  updateConditionPlainSummary(card);
};

const renderPrerequisiteBadgeFields = (card, fieldsContainer, seed) => {
  replaceConditionFields(fieldsContainer, [
    createConditionField(
      "Required badge template ID",
      createConditionInput("text", {
        "data-field": "badgeTemplateId",
        placeholder: "badge_template_foundations",
      }),
      false,
    ),
    createListSelectField(
      "Reusable badge-template list",
      "badgeTemplateListId",
      "badge_template_ids",
      typeof seed.badgeTemplateListId === "string" ? seed.badgeTemplateListId : "",
      "Use single badge template",
    ),
  ]);
  setFieldOnCard(
    card,
    "badgeTemplateId",
    typeof seed.badgeTemplateId === "string" ? seed.badgeTemplateId : "",
  );
  setFieldOnCard(
    card,
    "badgeTemplateListId",
    typeof seed.badgeTemplateListId === "string" ? seed.badgeTemplateListId : "",
  );
  bindExclusiveFieldPair(card, "badgeTemplateId", "badgeTemplateListId");
  updateConditionPlainSummary(card);
};

const conditionFieldRenderers = {
  course_completion: renderCourseCompletionFields,
  grade_threshold: renderGradeThresholdFields,
  program_completion: renderProgramCompletionFields,
  assignment_submission: renderAssignmentSubmissionFields,
  survey_completion: renderSurveyCompletionFields,
  time_window: renderTimeWindowFields,
  custom_field: renderCustomFieldFields,
  prerequisite_badge: renderPrerequisiteBadgeFields,
};

const renderConditionFields = (card, seed) => {
  const typeSelect = card.querySelector(".ct-admin__condition-type");
  const fieldsContainer = card.querySelector(".ct-admin__condition-fields");

  if (!(typeSelect instanceof HTMLSelectElement) || !(fieldsContainer instanceof HTMLElement)) {
    return;
  }

  const conditionType = typeSelect.value;
  updateConditionCardClass(card, conditionType);
  const renderer = conditionFieldRenderers[conditionType] ?? renderPrerequisiteBadgeFields;

  renderer(card, fieldsContainer, seed);
};

const lmsGradebookItemLabel = (item) => {
  if (!item || typeof item !== "object") {
    return "Untitled gradebook item";
  }

  const title =
    typeof item.title === "string" && item.title.length > 0
      ? item.title
      : "Untitled gradebook item";
  const itemId = typeof item.assignmentId === "string" ? item.assignmentId : "";
  const points =
    typeof item.pointsPossible === "number" ? " · " + String(item.pointsPossible) + " pts" : "";
  return title + points + (itemId.length > 0 ? " (" + itemId + ")" : "");
};

const lmsParseJsonBody = async (response) => {
  try {
    return await response.json();
  } catch {
    return null;
  }
};

const lmsErrorDetailFromPayload = (payload, fallbackMessage) => {
  if (payload && typeof payload === "object" && typeof payload.error === "string") {
    return payload.error;
  }

  return fallbackMessage;
};

const lmsFetchJson = async (url, fallbackMessage, options) => {
  const response = await fetch(url, {
    cache: "no-store",
    signal: options && options.signal instanceof AbortSignal ? options.signal : undefined,
  });
  const payload = await lmsParseJsonBody(response);

  if (!response.ok) {
    throw new Error(lmsErrorDetailFromPayload(payload, fallbackMessage));
  }

  return payload;
};

const lmsRequestControllerBySelect = new WeakMap();

const lmsCancelSelectRequest = (select) => {
  lmsRequestControllerBySelect.get(select)?.abort();
  lmsRequestControllerBySelect.delete(select);
};

const lmsFetchLatestSelectJson = async (select, url, fallbackMessage) => {
  lmsCancelSelectRequest(select);
  const controller = new AbortController();
  lmsRequestControllerBySelect.set(select, controller);

  try {
    const payload = await lmsFetchJson(url, fallbackMessage, {
      signal: controller.signal,
    });

    if (lmsRequestControllerBySelect.get(select) !== controller) {
      return { status: "superseded" };
    }

    lmsRequestControllerBySelect.delete(select);
    return { status: "complete", payload };
  } catch (error) {
    if (controller.signal.aborted) {
      return { status: "superseded" };
    }

    lmsRequestControllerBySelect.delete(select);
    throw error;
  }
};

const lmsSelectedValuesFromSelect = (select) => {
  return Array.from(select.selectedOptions)
    .map((option) => option.value)
    .filter((value) => value.length > 0);
};

const lmsSelectedValuesFromDataset = (select) => {
  const rawValues = select.dataset.selectedValues ?? select.dataset.selectedValue ?? "";
  return rawValues
    .split(",")
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
};

const lmsSelectedValuesForSelect = (select) => {
  const fromDataset = lmsSelectedValuesFromDataset(select);
  return fromDataset.length > 0 ? fromDataset : lmsSelectedValuesFromSelect(select);
};

const lmsSetSelectOptions = (
  select,
  entries,
  emptyLabel,
  selectedValues,
  labelForEntry,
  valueForEntry,
) => {
  const selectedSet = new Set(selectedValues);
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = emptyLabel;
  placeholder.disabled = select.required;
  placeholder.selected = selectedSet.size === 0;
  const options = [placeholder];

  entries.forEach((entry) => {
    const option = document.createElement("option");
    option.value = valueForEntry(entry);
    option.textContent = labelForEntry(entry);
    option.selected = selectedSet.has(option.value);
    options.push(option);
  });

  select.replaceChildren(...options);
};

const lmsPreselectedWorkflowValues = (states, selectedValues) => {
  if (selectedValues.length > 0) {
    return selectedValues;
  }

  return states
    .filter((state) => state && state.preselected === true && typeof state.value === "string")
    .map((state) => state.value);
};

const lmsHydrateWorkflowStateSelect = async (input) => {
  const { stateSelect, workflowStatesUrl, fallbackMessage } = input;

  if (!(stateSelect instanceof HTMLSelectElement)) {
    return false;
  }

  if (workflowStatesUrl.length === 0) {
    lmsCancelSelectRequest(stateSelect);
    lmsSetSelectOptions(
      stateSelect,
      [],
      "Select gradebook item first",
      [],
      (state) => state.label,
      (state) => state.value,
    );
    stateSelect.disabled = true;
    return true;
  }

  stateSelect.disabled = true;
  const preserved = lmsSelectedValuesForSelect(stateSelect);
  lmsSetSelectOptions(
    stateSelect,
    [],
    "Loading workflow states...",
    preserved,
    (state) => state.label,
    (state) => state.value,
  );
  const result = await lmsFetchLatestSelectJson(
    stateSelect,
    workflowStatesUrl,
    fallbackMessage ?? "Unable to load workflow states.",
  );
  if (result.status === "superseded") {
    return false;
  }

  const payload = result.payload;
  const states = payload && Array.isArray(payload.states) ? payload.states : [];
  const defaults = lmsPreselectedWorkflowValues(states, preserved);
  lmsSetSelectOptions(
    stateSelect,
    states,
    states.length === 0 ? "No workflow states available" : "Select workflow states",
    defaults,
    (state) => state.label,
    (state) => state.value,
  );
  stateSelect.disabled = false;
  return true;
};

const lmsHydrateGradebookItemSelect = async (input) => {
  const { itemSelect, itemsUrl, query, fallbackMessage } = input;

  if (!(itemSelect instanceof HTMLSelectElement)) {
    return false;
  }

  if (itemsUrl.length === 0) {
    lmsCancelSelectRequest(itemSelect);
    lmsSetSelectOptions(
      itemSelect,
      [],
      "Select course first",
      [],
      lmsGradebookItemLabel,
      (item) => item.assignmentId,
    );
    itemSelect.disabled = true;
    return true;
  }

  const selected = lmsSelectedValuesForSelect(itemSelect);
  itemSelect.disabled = true;
  lmsSetSelectOptions(
    itemSelect,
    [],
    "Loading gradebook items...",
    selected,
    lmsGradebookItemLabel,
    (item) => item.assignmentId,
  );
  const url = query.length === 0 ? itemsUrl : itemsUrl + "?q=" + encodeURIComponent(query);
  const result = await lmsFetchLatestSelectJson(
    itemSelect,
    url,
    fallbackMessage ?? "Unable to load gradebook items.",
  );
  if (result.status === "superseded") {
    return false;
  }

  const payload = result.payload;
  const items = payload && Array.isArray(payload.items) ? payload.items : [];
  lmsSetSelectOptions(
    itemSelect,
    items,
    items.length === 0 ? "No matching gradebook items" : "Select gradebook item",
    selected,
    lmsGradebookItemLabel,
    (item) => item.assignmentId,
  );
  itemSelect.disabled = false;
  itemSelect.dataset.selectedValue = itemSelect.value;
  itemSelect.dataset.selectedValues = lmsSelectedValuesFromSelect(itemSelect).join(",");

  return true;
};

const lmsHydrateGradebookItemWorkflowSelects = async (input) => {
  const {
    itemSelect,
    stateSelect,
    itemsUrl,
    query,
    itemFallbackMessage,
    workflowFallbackMessage,
    workflowStatesUrlForAssignment,
  } = input;
  const itemHydration = lmsHydrateGradebookItemSelect({
    itemSelect,
    itemsUrl,
    query,
    fallbackMessage: itemFallbackMessage,
  });

  await lmsHydrateWorkflowStateSelect({
    stateSelect,
    workflowStatesUrl: "",
    fallbackMessage: workflowFallbackMessage,
  });

  const didHydrateItems = await itemHydration;

  if (!didHydrateItems || itemsUrl.length === 0) {
    return didHydrateItems;
  }

  return lmsHydrateWorkflowStateSelect({
    stateSelect,
    workflowStatesUrl: workflowStatesUrlForAssignment(itemSelect.value),
    fallbackMessage: workflowFallbackMessage,
  });
};

const lmsBindDebouncedSearch = (input) => {
  const { onInput, searchInput, debounceMs } = input;
  let timer = 0;

  const schedule = () => {
    window.clearTimeout(timer);
    timer = window.setTimeout(() => {
      void onInput();
    }, debounceMs ?? 180);
  };

  if (searchInput instanceof HTMLInputElement) {
    searchInput.addEventListener("input", schedule);
  }

  return schedule;
};

const lmsCourseLabel = (course) => {
  if (!course || typeof course !== "object") {
    return "Untitled course";
  }

  const title =
    typeof course.title === "string" && course.title.length > 0 ? course.title : "Untitled course";
  const courseCode =
    typeof course.courseCode === "string" && course.courseCode.length > 0 ? course.courseCode : "";
  const courseId = typeof course.courseId === "string" ? course.courseId : "";
  return (
    title +
    (courseCode.length > 0 ? " · " + courseCode : "") +
    (courseId.length > 0 ? " (" + courseId + ")" : "")
  );
};

const lmsLookupErrorMessage = (error, fallback) => {
  return error instanceof Error ? error.message : fallback;
};

const setLmsLookupStatus = (message, isError) => {
  if (!(ruleBuilderLmsStatus instanceof HTMLElement)) {
    return;
  }

  const messageElement = ruleBuilderLmsStatus.querySelector(
    "[data-rule-builder-lms-status-message]",
  );

  ruleBuilderLmsStatus.hidden = message.length === 0;
  ruleBuilderLmsStatus.dataset.tone = isError ? "error" : "info";

  if (messageElement instanceof HTMLElement) {
    messageElement.textContent = message;
  }
};

const courseLookupAbortControllerByCard = new WeakMap();

const selectedCourseOptionSnapshots = (select, selectedValues) => {
  const snapshotsByValue = new Map();

  Array.from(select.selectedOptions).forEach((option) => {
    if (option.value.length > 0) {
      snapshotsByValue.set(option.value, option.textContent ?? option.value);
    }
  });

  selectedValues.forEach((value) => {
    if (!snapshotsByValue.has(value)) {
      snapshotsByValue.set(value, value);
    }
  });

  return snapshotsByValue;
};

const setCourseSelectOptions = (
  select,
  courses,
  emptyLabel,
  selectedValues,
  selectedOptionSnapshots,
) => {
  lmsSetSelectOptions(
    select,
    courses,
    emptyLabel,
    selectedValues,
    lmsCourseLabel,
    (course) => course.courseId,
  );

  const availableValues = new Set(Array.from(select.options).map((option) => option.value));
  const firstCourseOption = select.options.item(1);

  selectedOptionSnapshots.forEach((label, value) => {
    if (availableValues.has(value)) {
      return;
    }

    const option = document.createElement("option");
    option.value = value;
    option.textContent = label;
    option.selected = true;

    if (firstCourseOption === null) {
      select.append(option);
    } else {
      select.insertBefore(option, firstCourseOption);
    }
  });
};

const coursesPath = (query) => {
  const connectionId = getSelectedLmsConnectionId();

  if (connectionId.length === 0) {
    return "";
  }

  const queryString = query.trim();
  const suffix = queryString.length === 0 ? "" : "?q=" + encodeURIComponent(queryString);
  return lmsConnectionsApiPath + "/" + encodeURIComponent(connectionId) + "/courses" + suffix;
};

const gradebookItemsPath = (courseId, query) => {
  const connectionId = getSelectedLmsConnectionId();

  if (connectionId.length === 0 || courseId.length === 0) {
    return "";
  }

  const queryString = query.trim();
  const suffix = queryString.length === 0 ? "" : "?q=" + encodeURIComponent(queryString);
  return (
    lmsConnectionsApiPath +
    "/" +
    encodeURIComponent(connectionId) +
    "/courses/" +
    encodeURIComponent(courseId) +
    "/gradebook-items" +
    suffix
  );
};

const workflowStatesPath = (courseId, assignmentId) => {
  const connectionId = getSelectedLmsConnectionId();

  if (connectionId.length === 0 || courseId.length === 0 || assignmentId.length === 0) {
    return "";
  }

  return (
    lmsConnectionsApiPath +
    "/" +
    encodeURIComponent(connectionId) +
    "/courses/" +
    encodeURIComponent(courseId) +
    "/gradebook-items/" +
    encodeURIComponent(assignmentId) +
    "/workflow-states"
  );
};

const hydrateCourseSelect = async (card, select, query) => {
  courseLookupAbortControllerByCard.get(card)?.abort();
  const path = coursesPath(query);
  const selectedValues = lmsSelectedValuesForSelect(select);
  const selectedOptionSnapshots = selectedCourseOptionSnapshots(select, selectedValues);

  if (path.length === 0) {
    courseLookupAbortControllerByCard.delete(card);
    setCourseSelectOptions(
      select,
      [],
      "Select an LMS connection first",
      selectedValues,
      selectedOptionSnapshots,
    );
    select.disabled = true;
    return true;
  }

  const abortController = new AbortController();
  courseLookupAbortControllerByCard.set(card, abortController);
  setLmsLookupStatus("Loading courses...", false);
  select.disabled = true;
  setCourseSelectOptions(select, [], "Loading courses...", selectedValues, selectedOptionSnapshots);
  let payload;

  try {
    payload = await lmsFetchJson(path, "Unable to load LMS courses.", {
      signal: abortController.signal,
    });
  } catch (error) {
    if (abortController.signal.aborted) {
      return false;
    }

    courseLookupAbortControllerByCard.delete(card);
    setCourseSelectOptions(
      select,
      [],
      "Courses unavailable",
      selectedValues,
      selectedOptionSnapshots,
    );
    select.disabled = false;
    throw error;
  }

  if (courseLookupAbortControllerByCard.get(card) !== abortController) {
    return false;
  }

  courseLookupAbortControllerByCard.delete(card);
  const courses = payload && Array.isArray(payload.courses) ? payload.courses : [];
  const hasMore = payload && payload.hasMore === true;
  setCourseSelectOptions(
    select,
    courses,
    courses.length === 0 ? "No matching courses" : "Select course",
    selectedValues,
    selectedOptionSnapshots,
  );
  select.disabled = false;
  const normalizedQuery = query.trim();

  if (courses.length === 0) {
    setLmsLookupStatus(
      normalizedQuery.length === 0
        ? "No courses are available to the saved LMS account."
        : "No courses matched your search.",
      false,
    );
  } else if (hasMore) {
    setLmsLookupStatus(
      normalizedQuery.length === 0
        ? "Showing the first 100 courses. Search to narrow the list."
        : "Showing the first 100 matches. Refine your search to narrow the list.",
      false,
    );
  } else {
    setLmsLookupStatus("", false);
  }

  return true;
};

const hydrateWorkflowStateSelect = async (card) => {
  const courseId = readFieldFromCard(card, "courseId");
  const assignmentId = readFieldFromCard(card, "assignmentId");
  const stateSelect = card.querySelector("[data-lms-workflow-state-select]");

  await lmsHydrateWorkflowStateSelect({
    stateSelect,
    workflowStatesUrl: workflowStatesPath(courseId, assignmentId),
    fallbackMessage: "Unable to load workflow states.",
  });
};

const hydrateGradebookItemSelect = async (card, query) => {
  const courseId = readFieldFromCard(card, "courseId");
  const itemSelect = card.querySelector("[data-lms-gradebook-item-select]");
  const stateSelect = card.querySelector("[data-lms-workflow-state-select]");

  if (!(itemSelect instanceof HTMLSelectElement)) {
    return;
  }

  const path = gradebookItemsPath(courseId, query);

  setLmsLookupStatus("", false);
  await lmsHydrateGradebookItemWorkflowSelects({
    itemSelect,
    stateSelect,
    itemsUrl: path,
    query: "",
    itemFallbackMessage: "Unable to load gradebook items.",
    workflowFallbackMessage: "Unable to load workflow states.",
    workflowStatesUrlForAssignment: (assignmentId) =>
      workflowStatesPath(courseId, assignmentId),
  });
};

const bindSearchableCourseSelect = (card, fieldName) => {
  const courseSelect = card.querySelector(
    '[data-field="' + fieldName + '"][data-lms-course-select]',
  );
  const courseSearch = card.querySelector('[data-lms-course-query="' + fieldName + '"]');

  if (!(courseSelect instanceof HTMLSelectElement)) {
    return;
  }

  const refresh = lmsBindDebouncedSearch({
    searchInput: courseSearch,
    onInput: () =>
      hydrateCourseSelect(
        card,
        courseSelect,
        courseSearch instanceof HTMLInputElement ? courseSearch.value : "",
      )
        .then((didHydrate) => {
          if (!didHydrate) {
            return;
          }

          syncDefinitionJsonFromBuilder();
          if (fieldName === "courseId") {
            void hydrateGradebookItemSelect(card, "");
          }
        })
        .catch((error) => {
          const message = lmsLookupErrorMessage(error, "Unable to load LMS courses.");
          setLmsLookupStatus(message, true);
          setStatus(ruleCreateStatus, message, true);
        }),
  });

  courseSelect.addEventListener("change", () => {
    courseSelect.dataset.selectedValue = courseSelect.value;
    courseSelect.dataset.selectedValues = Array.from(courseSelect.selectedOptions)
      .map((option) => option.value)
      .join(",");
    if (fieldName === "courseId") {
      void hydrateGradebookItemSelect(card, "");
    }
  });

  refresh();
};

const bindSearchableGradebookItemSelect = (card) => {
  const itemSelect = card.querySelector("[data-lms-gradebook-item-select]");
  const itemSearch = card.querySelector("[data-lms-gradebook-item-query]");

  if (!(itemSelect instanceof HTMLSelectElement)) {
    return;
  }

  lmsBindDebouncedSearch({
    searchInput: itemSearch,
    onInput: () =>
      hydrateGradebookItemSelect(
        card,
        itemSearch instanceof HTMLInputElement ? itemSearch.value : "",
      )
        .then(() => {
          syncDefinitionJsonFromBuilder();
        })
        .catch((error) => {
          const message = lmsLookupErrorMessage(error, "Unable to load gradebook items.");
          setLmsLookupStatus(message, true);
          setStatus(ruleCreateStatus, message, true);
        }),
  });

  itemSelect.addEventListener("change", () => {
    itemSelect.dataset.selectedValue = itemSelect.value;
    void hydrateWorkflowStateSelect(card).then(() => {
      syncDefinitionJsonFromBuilder();
    });
  });
};

const readConditionFromCard = (card, strict) => {
  const typeSelect = card.querySelector(".ct-admin__condition-type");
  const negate = readCheckboxFromCard(card, "negate");

  if (!(typeSelect instanceof HTMLSelectElement)) {
    throw new Error("Requirement row is missing a type selection.");
  }

  const conditionType = typeSelect.value;
  let condition = null;

  if (conditionType === "course_completion") {
    const courseId = readFieldFromCard(card, "courseId");
    const courseListId = readFieldFromCard(card, "courseListId");
    const minCompletionPercent = parseNumberInput(readFieldFromCard(card, "minCompletionPercent"));

    if (strict && courseId.length === 0 && courseListId.length === 0) {
      throw new Error("Course completion requirement needs a course ID or reusable course list.");
    }

    if (strict && courseId.length > 0 && courseListId.length > 0) {
      throw new Error(
        "Course completion requirement can use course ID or reusable course list, not both.",
      );
    }

    condition = {
      type: "course_completion",
      minCompletionPercent: minCompletionPercent ?? 100,
      ...(courseListId.length > 0
        ? { courseListId }
        : {
            courseId: courseId.length > 0 ? courseId : "COURSE_ID",
          }),
    };
  } else if (conditionType === "grade_threshold") {
    const courseId = readFieldFromCard(card, "courseId");
    const courseListId = readFieldFromCard(card, "courseListId");
    const minScore = parseNumberInput(readFieldFromCard(card, "minScore"));
    const maxScore = parseNumberInput(readFieldFromCard(card, "maxScore"));

    if (strict && courseId.length === 0 && courseListId.length === 0) {
      throw new Error("Grade threshold requirement needs a course ID or reusable course list.");
    }

    if (strict && courseId.length > 0 && courseListId.length > 0) {
      throw new Error(
        "Grade threshold requirement can use course ID or reusable course list, not both.",
      );
    }

    if (strict && minScore === null && maxScore === null) {
      throw new Error("Grade threshold requires min score or max score.");
    }

    condition = {
      type: "grade_threshold",
      scoreField:
        readFieldFromCard(card, "scoreField") === "current_score" ? "current_score" : "final_score",
      ...(courseListId.length > 0
        ? { courseListId }
        : {
            courseId: courseId.length > 0 ? courseId : "COURSE_ID",
          }),
    };

    if (minScore !== null) {
      condition.minScore = minScore;
    }

    if (maxScore !== null) {
      condition.maxScore = maxScore;
    }
  } else if (conditionType === "program_completion") {
    const courseIds = parseCsv(readFieldFromCard(card, "courseIds"));
    const courseListId = readFieldFromCard(card, "courseListId");
    const minimumCompleted = parseNumberInput(readFieldFromCard(card, "minimumCompleted"));

    if (strict && courseIds.length === 0 && courseListId.length === 0) {
      throw new Error(
        "Course pathway completion requires selected courses or a reusable course list.",
      );
    }

    if (strict && courseIds.length > 0 && courseListId.length > 0) {
      throw new Error(
        "Course pathway completion can use selected courses or a reusable course list, not both.",
      );
    }

    condition = {
      type: "program_completion",
      ...(courseListId.length > 0
        ? { courseListId }
        : {
            courseIds: courseIds.length > 0 ? courseIds : ["COURSE_ID"],
          }),
    };

    if (minimumCompleted !== null) {
      condition.minimumCompleted = Math.trunc(minimumCompleted);
    }
  } else if (conditionType === "assignment_submission") {
    const courseId = readFieldFromCard(card, "courseId");
    const assignmentId = readFieldFromCard(card, "assignmentId");
    const minScore = parseNumberInput(readFieldFromCard(card, "minScore"));
    const workflowStates = parseCsv(readFieldFromCard(card, "workflowStates"));

    if (strict && courseId.length === 0) {
      throw new Error("Gradebook item requirement needs a course.");
    }

    if (strict && assignmentId.length === 0) {
      throw new Error("Gradebook item requirement needs a gradebook item.");
    }

    condition = {
      type: "assignment_submission",
      courseId: courseId.length > 0 ? courseId : "COURSE_ID",
      assignmentId: assignmentId.length > 0 ? assignmentId : "ASSIGNMENT_ID",
      requireSubmitted: readCheckboxFromCard(card, "requireSubmitted"),
    };

    if (minScore !== null) {
      condition.minScore = minScore;
    }

    if (workflowStates.length > 0) {
      condition.workflowStates = workflowStates;
    }
  } else if (conditionType === "survey_completion") {
    const surveyId = readFieldFromCard(card, "surveyId");
    const source = readFieldFromCard(card, "source");

    if (strict && surveyId.length === 0) {
      throw new Error("Survey completion requirement needs a survey ID.");
    }

    condition = {
      type: "survey_completion",
      surveyId: surveyId.length > 0 ? surveyId : "SURVEY_ID",
      requireCompleted: readCheckboxFromCard(card, "requireCompleted"),
    };

    if (source.length > 0) {
      condition.source = source;
    }
  } else if (conditionType === "time_window") {
    const notBeforeIso = toIsoTimestamp(readFieldFromCard(card, "notBefore"));
    const notAfterIso = toIsoTimestamp(readFieldFromCard(card, "notAfter"));

    if (notBeforeIso === null || notAfterIso === null) {
      throw new Error("Time window condition has an invalid timestamp.");
    }

    if (strict && notBeforeIso === undefined && notAfterIso === undefined) {
      throw new Error("Time window condition requires not before or not after.");
    }

    condition = {
      type: "time_window",
    };

    if (notBeforeIso !== undefined) {
      condition.notBefore = notBeforeIso;
    }

    if (notAfterIso !== undefined) {
      condition.notAfter = notAfterIso;
    }
  } else if (conditionType === "custom_field") {
    const fieldName = readFieldFromCard(card, "fieldName");
    const operator = readFieldFromCard(card, "operator");
    const expectedValueType = readFieldFromCard(card, "expectedValueType");
    const expectedValue = parseCustomExpectedValue(
      readFieldFromCard(card, "expectedValue"),
      expectedValueType,
    );

    if (strict && fieldName.length === 0) {
      throw new Error("Custom field requirement needs a field name.");
    }

    if (strict && expectedValue === null) {
      throw new Error("Custom field requirement needs a valid expected value.");
    }

    condition = {
      type: "custom_field",
      fieldName: fieldName.length > 0 ? fieldName : "fieldName",
      operator:
        operator === "not_equals" ||
        operator === "contains" ||
        operator === "greater_than_or_equal" ||
        operator === "less_than_or_equal"
          ? operator
          : "equals",
      expectedValue: expectedValue === null ? "VALUE" : expectedValue,
    };
  } else {
    const badgeTemplateId = readFieldFromCard(card, "badgeTemplateId");
    const badgeTemplateListId = readFieldFromCard(card, "badgeTemplateListId");

    if (strict && badgeTemplateId.length === 0 && badgeTemplateListId.length === 0) {
      throw new Error(
        "Prerequisite badge requirement needs a badge template ID or reusable badge list.",
      );
    }

    if (strict && badgeTemplateId.length > 0 && badgeTemplateListId.length > 0) {
      throw new Error(
        "Prerequisite badge requirement can use badge template ID or reusable badge list, not both.",
      );
    }

    condition = {
      type: "prerequisite_badge",
      ...(badgeTemplateListId.length > 0
        ? { badgeTemplateListId }
        : {
            badgeTemplateId:
              badgeTemplateId.length > 0 ? badgeTemplateId : "badge_template_required",
          }),
    };
  }

  return negate ? { not: condition } : condition;
};

const readDefinitionFromBuilder = (strict) => {
  const cards = getConditionCards();

  if (cards.length === 0) {
    throw new Error("Add at least one requirement before creating a draft.");
  }

  const conditions = cards.map((card) => readConditionFromCard(card, strict));
  const rootLogic = getRuleBuilderRootLogic();

  const definition = {
    conditions: rootLogic === "any" ? { any: conditions } : { all: conditions },
  };

  if (getCheckboxFieldValue("reviewOnMissingFacts")) {
    definition.options = {
      reviewOnMissingFacts: true,
    };
  }

  return definition;
};

const leafConditionFromCondition = (condition) => {
  if (condition && typeof condition === "object" && "not" in condition) {
    const nested = condition.not;
    return nested && typeof nested === "object" ? nested : condition;
  }

  return condition;
};

const conditionLabel = (condition) => {
  const leaf = leafConditionFromCondition(condition);
  const type = leaf && typeof leaf === "object" && typeof leaf.type === "string" ? leaf.type : "";
  return conditionTypeLabels[type] ?? "Requirement";
};

const conditionDetail = (condition) => {
  const leaf = leafConditionFromCondition(condition);

  if (leaf === null || typeof leaf !== "object") {
    return "Configure requirement details.";
  }

  if (leaf.type === "course_completion") {
    return (
      "At least " +
      String(leaf.minCompletionPercent ?? 100) +
      "% of gradebook items in " +
      (leaf.courseId ?? leaf.courseListId ?? "selected course") +
      " must be complete."
    );
  }

  if (leaf.type === "grade_threshold") {
    const parts = [];

    if (leaf.minScore !== undefined) {
      parts.push("min " + String(leaf.minScore));
    }

    if (leaf.maxScore !== undefined) {
      parts.push("max " + String(leaf.maxScore));
    }

    return (
      "Course " +
      (leaf.courseId ?? leaf.courseListId ?? "selected") +
      " score " +
      (parts.join(", ") || "threshold")
    );
  }

  if (leaf.type === "program_completion") {
    return "Complete " + String(leaf.minimumCompleted ?? "all") + " required courses.";
  }

  if (leaf.type === "assignment_submission") {
    return (
      "Gradebook item " +
      leaf.assignmentId +
      " in " +
      leaf.courseId +
      " must satisfy submission rules."
    );
  }

  if (leaf.type === "survey_completion") {
    return "Survey " + leaf.surveyId + " must be completed.";
  }

  if (leaf.type === "time_window") {
    return "Qualifying activity must fall inside the configured time window.";
  }

  if (leaf.type === "prerequisite_badge") {
    return (
      "Requires badge " + (leaf.badgeTemplateId ?? leaf.badgeTemplateListId ?? "selected") + "."
    );
  }

  if (leaf.type === "custom_field") {
    return (
      leaf.fieldName + " " + (leaf.operator ?? "equals") + " " + String(leaf.expectedValue) + "."
    );
  }

  return "Configure requirement details.";
};

const readConditionsForPreview = () => {
  return getConditionCards()
    .map((card) => {
      try {
        return readConditionFromCard(card, false);
      } catch {
        return null;
      }
    })
    .filter((condition) => condition !== null);
};

const selectedBadgeTemplateLabel = () => {
  const field = getRuleCreateField("badgeTemplateId");

  if (!(field instanceof HTMLSelectElement)) {
    return "selected badge";
  }

  const option = field.selectedOptions.item(0);
  return option === null ? "selected badge" : option.textContent?.trim() || "selected badge";
};

const createRuleFlowItem = (modifier, connector, kicker, title, detail) => {
  const item = document.createElement("li");
  item.className = "ct-admin__builder-flow-item ct-admin__builder-flow-item--" + modifier;

  if (connector.length > 0) {
    const connectorElement = document.createElement("span");
    connectorElement.className = "ct-admin__builder-flow-connector";
    connectorElement.textContent = connector;
    item.appendChild(connectorElement);
  }

  const node = document.createElement("div");
  node.className = "ct-admin__builder-flow-node";

  const kickerElement = document.createElement("span");
  kickerElement.className = "ct-admin__builder-flow-kicker";
  kickerElement.textContent = kicker;

  const titleElement = document.createElement("strong");
  titleElement.textContent = title;

  const detailElement = document.createElement("p");
  detailElement.textContent = detail;

  node.append(kickerElement, titleElement, detailElement);
  item.appendChild(node);

  return item;
};

const renderRuleFlowPreview = () => {
  if (
    !(ruleBuilderFlowList instanceof HTMLOListElement) ||
    !(ruleBuilderFlowEmpty instanceof HTMLElement)
  ) {
    return;
  }

  const conditions = readConditionsForPreview();
  const rootLogic = getRuleBuilderRootLogic();
  const connectorLabel = rootLogic === "any" ? "OR" : "AND";

  ruleBuilderFlowEmpty.hidden = conditions.length > 0;

  if (ruleBuilderFlowMode instanceof HTMLElement) {
    ruleBuilderFlowMode.textContent =
      conditions.length === 0
        ? "Waiting for requirements."
        : rootLogic === "any"
          ? "Any path can qualify."
          : "Learner must meet every requirement.";
  }

  if (conditions.length === 0) {
    ruleBuilderFlowList.replaceChildren();
    return;
  }

  const conditionItems = conditions.map((condition, index) => {
    const leaf = leafConditionFromCondition(condition);
    const type =
      leaf && typeof leaf === "object" && typeof leaf.type === "string" ? leaf.type : "unknown";
    const isNegated = condition && typeof condition === "object" && "not" in condition;
    return createRuleFlowItem(
      type,
      index === 0 ? "" : connectorLabel,
      "Requirement " + String(index + 1),
      (isNegated ? "Exclude: " : "") + conditionLabel(condition),
      conditionDetail(condition),
    );
  });
  const badgeLabel = selectedBadgeTemplateLabel();

  ruleBuilderFlowList.replaceChildren(
    ...conditionItems,
    createRuleFlowItem("issue", "THEN", "Outcome", "Issue badge draft", badgeLabel),
  );
};

const addSourceEntry = (entries, key, label, state, detail) => {
  if (!entries.has(key)) {
    entries.set(key, {
      label,
      state,
      details: [],
    });
  }

  const entry = entries.get(key);

  if (entry && !entry.details.includes(detail)) {
    entry.details.push(detail);
  }
};

const sourceEntriesForConditions = (conditions) => {
  const entries = new Map();
  const lmsLabel = getSelectedLmsProviderKind() || "selected LMS";

  conditions.forEach((condition) => {
    const leaf = leafConditionFromCondition(condition);

    if (leaf === null || typeof leaf !== "object") {
      return;
    }

    if (
      leaf.type === "course_completion" ||
      leaf.type === "grade_threshold" ||
      leaf.type === "program_completion"
    ) {
      addSourceEntry(
        entries,
        "lms-gradebook",
        lmsLabel + " gradebook connection",
        "Connected or sample",
        conditionDetail(condition),
      );
      return;
    }

    if (leaf.type === "assignment_submission") {
      addSourceEntry(
        entries,
        "lms-assignments",
        lmsLabel + " gradebook items",
        "Connected or sample",
        conditionDetail(condition),
      );
      return;
    }

    if (leaf.type === "survey_completion") {
      addSourceEntry(
        entries,
        "survey",
        leaf.source === "qualtrics" ? "Qualtrics surveys" : "Survey facts",
        "Sample or connector facts",
        conditionDetail(condition),
      );
      return;
    }

    if (leaf.type === "prerequisite_badge") {
      addSourceEntry(
        entries,
        "credtrail",
        "CredTrail issued badges",
        "Available",
        conditionDetail(condition),
      );
      return;
    }

    if (leaf.type === "custom_field") {
      addSourceEntry(
        entries,
        "custom",
        "Institutional fields",
        "Sample or import facts",
        conditionDetail(condition),
      );
      return;
    }

    if (leaf.type === "time_window") {
      addSourceEntry(entries, "clock", "System clock", "Available", conditionDetail(condition));
    }
  });

  return Array.from(entries.values());
};

const buildSampleFactsFromConditions = (conditions, learnerId) => {
  const courseId = getDefaultCourseId() || getCoursePlaceholder();
  const parsedFinalScore = Number(getTextFieldValue("testFinalScore"));
  const finalScore =
    Number.isFinite(parsedFinalScore) && parsedFinalScore >= 0 && parsedFinalScore <= 100
      ? parsedFinalScore
      : 92;
  const parsedCompletionPercent = Number(getTextFieldValue("testCompletionPercent"));
  const completionPercent =
    Number.isFinite(parsedCompletionPercent) &&
    parsedCompletionPercent >= 0 &&
    parsedCompletionPercent <= 100
      ? parsedCompletionPercent
      : 100;
  const facts = {
    grades: [],
    completions: [],
    submissions: [],
    surveyCompletions: [],
    customFields: [],
    earnedBadgeTemplateIds: [],
  };

  conditions.forEach((condition) => {
    const leaf = leafConditionFromCondition(condition);

    if (leaf === null || typeof leaf !== "object") {
      return;
    }

    if (leaf.type === "grade_threshold") {
      facts.grades.push({
        courseId: leaf.courseId ?? courseId,
        learnerId,
        finalScore,
      });
      return;
    }

    if (leaf.type === "course_completion" || leaf.type === "program_completion") {
      const courseIds = Array.isArray(leaf.courseIds)
        ? leaf.courseIds
        : [leaf.courseId ?? courseId];
      courseIds.forEach((entryCourseId) => {
        facts.completions.push({
          courseId: entryCourseId,
          learnerId,
          completed: completionPercent >= 100,
          completionPercent,
        });
      });
      return;
    }

    if (leaf.type === "assignment_submission") {
      facts.submissions.push({
        courseId: leaf.courseId,
        assignmentId: leaf.assignmentId,
        learnerId,
        score: finalScore,
        workflowState: "submitted",
        submittedAt: new Date().toISOString(),
      });
      return;
    }

    if (leaf.type === "survey_completion") {
      facts.surveyCompletions.push({
        surveyId: leaf.surveyId,
        learnerId,
        ...(leaf.source === undefined ? {} : { source: leaf.source }),
        completed: true,
        completedAt: new Date().toISOString(),
      });
      return;
    }

    if (leaf.type === "custom_field") {
      facts.customFields.push({
        learnerId,
        fieldName: leaf.fieldName,
        value: leaf.expectedValue,
      });
      return;
    }

    if (leaf.type === "prerequisite_badge") {
      facts.earnedBadgeTemplateIds.push(leaf.badgeTemplateId ?? "badge_template_foundations");
    }
  });

  return facts;
};

const buildSampleFactsPreview = (conditions) => {
  const advancedFactsJson = getTextFieldValue("testFactsJson");

  if (advancedFactsJson.length > 0) {
    try {
      return JSON.stringify(JSON.parse(advancedFactsJson), null, 2);
    } catch {
      return "Advanced facts JSON is invalid.";
    }
  }

  return JSON.stringify(buildSampleFactsFromConditions(conditions, "example-learner"), null, 2);
};

const renderSourceReadiness = () => {
  if (!(ruleBuilderSourceList instanceof HTMLElement)) {
    return;
  }

  const conditions = readConditionsForPreview();
  const entries = sourceEntriesForConditions(conditions);

  if (entries.length === 0) {
    const row = document.createElement("div");
    const term = document.createElement("dt");
    const detail = document.createElement("dd");
    term.textContent = "No sources yet";
    detail.textContent = "Add requirements to see which facts CredTrail needs.";
    row.append(term, detail);
    ruleBuilderSourceList.replaceChildren(row);
    setCodeOutput(ruleBuilderSourceSample, "");
    return;
  }

  const rows = entries.map((entry) => {
    const row = document.createElement("div");
    const term = document.createElement("dt");
    const detail = document.createElement("dd");
    const state = document.createElement("span");
    const text = document.createElement("span");

    term.textContent = entry.label;
    state.className = "ct-admin__status-pill";
    state.textContent = entry.state;
    text.textContent = entry.details.join(" ");
    detail.append(state, text);
    row.append(term, detail);

    return row;
  });

  ruleBuilderSourceList.replaceChildren(...rows);
  setCodeOutput(ruleBuilderSourceSample, buildSampleFactsPreview(conditions));
};

const validateConditionCards = (updateRows) => {
  const errors = [];

  getConditionCards().forEach((card, index) => {
    try {
      readConditionFromCard(card, true);

      if (updateRows) {
        setConditionResultState(card, "idle", "Ready to test.");
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Requirement needs attention.";
      errors.push("Requirement " + String(index + 1) + ": " + message);

      if (updateRows) {
        setConditionResultState(card, "fail", message);
      }
    }
  });

  return errors;
};

let ruleBuilderLastTestSummary = "Not run";

const resetConditionEvaluationResults = () => {
  getConditionCards().forEach((card) => {
    setConditionResultState(card, "idle", "Not evaluated yet.");
  });
};

const collectLeafEvaluationNodes = (node, output) => {
  if (node === null || typeof node !== "object") {
    return;
  }

  const children = Array.isArray(node.children) ? node.children : [];

  if (children.length === 0) {
    output.push(node);
    return;
  }

  children.forEach((child) => {
    collectLeafEvaluationNodes(child, output);
  });
};

const rootChildrenFromEvaluationTree = (tree) => {
  if (tree === null || typeof tree !== "object") {
    return [];
  }

  return Array.isArray(tree.children) ? tree.children : [];
};

const applyConditionEvaluationResults = (evaluation) => {
  const cards = getConditionCards();

  if (cards.length === 0) {
    return {
      total: 0,
      matched: 0,
    };
  }

  const directChildren = rootChildrenFromEvaluationTree(
    evaluation && typeof evaluation === "object" ? evaluation.tree : null,
  );
  let mappedNodes = directChildren;

  if (mappedNodes.length !== cards.length) {
    const leafNodes = [];
    collectLeafEvaluationNodes(
      evaluation && typeof evaluation === "object" ? evaluation.tree : null,
      leafNodes,
    );
    mappedNodes = leafNodes.length === cards.length ? leafNodes : [];
  }

  if (mappedNodes.length !== cards.length) {
    resetConditionEvaluationResults();
    return {
      total: cards.length,
      matched: 0,
    };
  }

  let matchedCount = 0;

  cards.forEach((card, index) => {
    const node = mappedNodes[index];
    const matched = node && typeof node.matched === "boolean" ? node.matched : null;
    const detail = node && typeof node.detail === "string" ? node.detail : "No evaluation detail.";
    const resultKind = node && typeof node.resultKind === "string" ? node.resultKind : null;

    if (matched === true) {
      matchedCount += 1;
      setConditionResultState(card, "pass", "Pass: " + detail);
      return;
    }

    if (resultKind === "missing_data") {
      setConditionResultState(card, "review", "Missing data: " + detail);
      return;
    }

    if (matched === false) {
      setConditionResultState(card, "fail", "Fail: " + detail);
      return;
    }

    setConditionResultState(card, "idle", "Not evaluated.");
  });

  return {
    total: cards.length,
    matched: matchedCount,
  };
};

const setSummaryText = (element, value) => {
  if (element instanceof HTMLElement) {
    element.textContent = value;
  }
};

const setSummaryTone = (element, tone) => {
  if (!(element instanceof HTMLElement)) {
    return;
  }

  if (typeof tone !== "string" || tone.length === 0) {
    delete element.dataset.tone;
    return;
  }

  element.dataset.tone = tone;
};

const syncConditionCanvasMeta = () => {
  const cards = getConditionCards();

  cards.forEach((card, index) => {
    const indexElement = card.querySelector("[data-condition-index]");

    if (indexElement instanceof HTMLElement) {
      indexElement.textContent = "Requirement " + String(index + 1);
    }

    const moveUpButton = card.querySelector('button[data-condition-move="up"]');
    const moveDownButton = card.querySelector('button[data-condition-move="down"]');

    if (moveUpButton instanceof HTMLButtonElement) {
      moveUpButton.disabled = index === 0;
    }

    if (moveDownButton instanceof HTMLButtonElement) {
      moveDownButton.disabled = index === cards.length - 1;
    }
  });

  if (ruleBuilderCanvasCount instanceof HTMLElement) {
    ruleBuilderCanvasCount.textContent =
      String(cards.length) + (cards.length === 1 ? " requirement" : " requirements");
  }

  if (ruleBuilderCanvasLogic instanceof HTMLElement) {
    const rootLogic = getRuleBuilderRootLogic();
    ruleBuilderCanvasLogic.textContent =
      rootLogic === "any"
        ? "Learner can meet any one requirement"
        : "Learner must meet every requirement";
    ruleBuilderCanvasLogic.className = adminStatusPillClass(
      rootLogic === "any" ? "warning" : "active",
    );
  }

  syncRootLogicToolbarVisibility();
};

const syncRootLogicToolbarVisibility = () => {
  const rootLogic = getRuleBuilderRootLogic();

  if (ruleBuilderAddAlternativePathButton instanceof HTMLButtonElement) {
    ruleBuilderAddAlternativePathButton.hidden = rootLogic === "any";
  }

  if (ruleBuilderRequireEveryRequirementButton instanceof HTMLButtonElement) {
    ruleBuilderRequireEveryRequirementButton.hidden = rootLogic === "all";
  }
};

const syncRuleBuilderStepCompletion = () => {
  const completion = getRuleBuilderCompletionState();

  ruleBuilderStepButtons.forEach((candidate) => {
    if (!(candidate instanceof HTMLButtonElement)) {
      return;
    }

    const targetStep = candidate.dataset.ruleStepTarget ?? "";
    const isDone = completion[targetStep] === true;
    candidate.classList.toggle("is-done", isDone);
  });

  const completedCount = Object.values(completion).filter((value) => value).length;
  const activeStep = ruleBuilderStepOrder[activeRuleBuilderStepIndex] ?? "";
  const activeStepLabel = ruleBuilderStepLabels[activeStep] ?? "Step";

  if (ruleBuilderStepProgress instanceof HTMLElement) {
    ruleBuilderStepProgress.textContent =
      "Step " +
      String(activeRuleBuilderStepIndex + 1) +
      " of " +
      String(ruleBuilderStepOrder.length) +
      " · " +
      activeStepLabel +
      " · " +
      String(completedCount) +
      "/" +
      String(ruleBuilderStepOrder.length) +
      " complete";
  }

  updateStepNavigationState();
};

const syncRuleBuilderSummary = (statusOverride) => {
  renderRuleFlowPreview();
  renderSourceReadiness();

  const ruleName = getTextFieldValue("name");
  const cardCount = getConditionCards().length;
  const rootLogicLabel =
    getRuleBuilderRootLogic() === "any"
      ? "Learner can meet any one requirement"
      : "Learner must meet every requirement";
  let definitionStatus = "Drafting";
  let definitionTone = "warning";
  let summaryMessage = "Add at least one requirement to create a draft.";

  if (cardCount === 0) {
    definitionStatus = "Needs requirements";
    definitionTone = "warning";
  } else {
    const validationErrors = validateConditionCards(false);

    if (validationErrors.length > 0) {
      definitionStatus = "Needs attention";
      definitionTone = "error";
      summaryMessage = validationErrors[0];
    } else {
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

        definitionStatus = childCount > 0 ? "Ready for review" : "Needs requirements";
        definitionTone = childCount > 0 ? "success" : "warning";
        summaryMessage =
          childCount > 0
            ? "Requirements are synchronized with the generated rule JSON."
            : "Add one or more requirements to continue.";
      } catch (error) {
        definitionStatus = "Needs attention";
        definitionTone = "error";
        summaryMessage =
          error instanceof Error ? error.message : "Definition is not ready for submission.";
      }
    }
  }

  let lastTestTone = "info";

  if (ruleBuilderLastTestSummary.startsWith("Matched")) {
    lastTestTone = "success";
  } else if (ruleBuilderLastTestSummary.startsWith("Review required")) {
    lastTestTone = "warning";
  } else if (ruleBuilderLastTestSummary.startsWith("No match")) {
    lastTestTone = "warning";
  } else if (
    ruleBuilderLastTestSummary.startsWith("Failed") ||
    ruleBuilderLastTestSummary.includes("invalid") ||
    ruleBuilderLastTestSummary.includes("Missing")
  ) {
    lastTestTone = "error";
  }

  setSummaryText(ruleBuilderSummaryRuleName, ruleName.length > 0 ? ruleName : "(unnamed draft)");
  setSummaryText(ruleBuilderSummaryConditionCount, String(cardCount));
  setSummaryText(ruleBuilderSummaryRootLogic, rootLogicLabel);
  setSummaryText(ruleBuilderSummaryValidity, definitionStatus);
  setSummaryText(ruleBuilderSummaryLastTest, ruleBuilderLastTestSummary);
  setSummaryText(ruleBuilderSummaryMessage, statusOverride ?? summaryMessage);
  setSummaryTone(ruleBuilderSummaryValidity, definitionTone);
  setSummaryTone(ruleBuilderSummaryLastTest, lastTestTone);
  setSummaryTone(
    ruleBuilderSummaryMessage,
    statusOverride === undefined
      ? definitionTone
      : ruleCreateStatus.dataset.tone === "error"
        ? "error"
        : ruleCreateStatus.dataset.tone === "success"
          ? "success"
          : ruleCreateStatus.dataset.tone === "warning"
            ? "warning"
            : "info",
  );
  syncRuleBuilderStepCompletion();
};

const syncDefinitionJsonFromBuilder = () => {
  syncConditionCanvasMeta();
  renderRuleFlowPreview();
  renderSourceReadiness();

  try {
    const definition = readDefinitionFromBuilder(false);
    ruleBuilderDefinitionJson.value = JSON.stringify(definition, null, 2);
  } catch {
    // Ignore transient editing errors while user updates fields.
  }

  ruleBuilderLastTestSummary = "Not run";
  validateConditionCards(true);
  getConditionCards().forEach((card) => {
    updateConditionPlainSummary(card);
  });
  syncRuleBuilderSummary();
};

const createConditionCard = (seed) => {
  const card = cloneRuleBuilderConditionCard();

  if (!(card instanceof HTMLElement)) {
    return null;
  }

  const typeSelect = card.querySelector(".ct-admin__condition-type");

  if (typeSelect instanceof HTMLSelectElement) {
    typeSelect.value = typeof seed.type === "string" ? seed.type : "grade_threshold";
  }

  setCheckboxOnCard(card, "negate", Boolean(seed.negate));
  renderConditionFields(card, seed);
  setConditionResultState(card, "idle", "Not evaluated yet.");

  card.addEventListener("change", (event) => {
    const target = event.target;

    if (
      target instanceof HTMLSelectElement &&
      target.classList.contains("ct-admin__condition-type")
    ) {
      renderConditionFields(card, {
        type: target.value,
        negate: readCheckboxFromCard(card, "negate"),
      });
    }

    syncDefinitionJsonFromBuilder();
  });

  card.addEventListener("input", () => {
    syncDefinitionJsonFromBuilder();
  });

  card.addEventListener("click", (event) => {
    const target = event.target;

    if (target instanceof HTMLButtonElement && target.dataset.conditionMove === "up") {
      const previous = card.previousElementSibling;

      if (previous instanceof HTMLElement) {
        ruleBuilderConditionList.insertBefore(card, previous);
      }

      syncDefinitionJsonFromBuilder();
      return;
    }

    if (target instanceof HTMLButtonElement && target.dataset.conditionMove === "down") {
      const next = card.nextElementSibling;

      if (next instanceof HTMLElement) {
        ruleBuilderConditionList.insertBefore(next, card);
      }

      syncDefinitionJsonFromBuilder();
      return;
    }

    if (
      target instanceof HTMLButtonElement &&
      target.classList.contains("ct-admin__condition-remove")
    ) {
      card.remove();
      syncDefinitionJsonFromBuilder();
    }
  });

  card.addEventListener("dragstart", () => {
    card.classList.add("is-dragging");
  });

  card.addEventListener("dragend", () => {
    card.classList.remove("is-dragging");
    syncDefinitionJsonFromBuilder();
  });

  return card;
};

const getDragAfterElement = (container, y) => {
  const cards = Array.from(
    container.querySelectorAll(".ct-admin__condition-card:not(.is-dragging)"),
  );
  let closestOffset = Number.NEGATIVE_INFINITY;
  let closestElement = null;

  cards.forEach((card) => {
    if (!(card instanceof HTMLElement)) {
      return;
    }

    const box = card.getBoundingClientRect();
    const offset = y - box.top - box.height / 2;

    if (offset < 0 && offset > closestOffset) {
      closestOffset = offset;
      closestElement = card;
    }
  });

  return closestElement;
};

ruleBuilderConditionList.addEventListener("dragover", (event) => {
  event.preventDefault();
  const dragging = ruleBuilderConditionList.querySelector(".ct-admin__condition-card.is-dragging");

  if (!(dragging instanceof HTMLElement)) {
    return;
  }

  const afterElement = getDragAfterElement(ruleBuilderConditionList, event.clientY);

  if (afterElement === null) {
    ruleBuilderConditionList.appendChild(dragging);
    return;
  }

  ruleBuilderConditionList.insertBefore(dragging, afterElement);
});

const clearConditionCanvas = () => {
  ruleBuilderConditionList.replaceChildren();
};

const addConditionToCanvas = (seed) => {
  const card = createConditionCard(seed);

  if (!(card instanceof HTMLElement)) {
    setStatus(ruleCreateStatus, "Unable to add requirement row.", true);
    return;
  }

  ruleBuilderConditionList.appendChild(card);
  syncDefinitionJsonFromBuilder();
};

const refreshConditionCardValueListOptions = () => {
  getConditionCards().forEach((card) => {
    try {
      const currentCondition = readConditionFromCard(card, false);
      const normalizedCondition = normalizeLeafConditionForBuilder(currentCondition);

      if (normalizedCondition === null) {
        return;
      }

      const typeSelect = card.querySelector(".ct-admin__condition-type");

      if (typeSelect instanceof HTMLSelectElement) {
        typeSelect.value = normalizedCondition.type;
      }

      setCheckboxOnCard(card, "negate", Boolean(normalizedCondition.negate));
      renderConditionFields(card, normalizedCondition);
    } catch {
      // Ignore partially edited cards while refreshing reusable-list options.
    }
  });
};

const normalizeLeafConditionForBuilder = (condition) => {
  if (condition === null || typeof condition !== "object" || Array.isArray(condition)) {
    return null;
  }

  if ("type" in condition && typeof condition.type === "string") {
    return {
      ...condition,
      negate: false,
    };
  }

  if ("not" in condition) {
    const nested = normalizeLeafConditionForBuilder(condition.not);

    if (nested === null) {
      return null;
    }

    return {
      ...nested,
      negate: true,
    };
  }

  return null;
};

const applyDefinitionToBuilder = (definition, sourceLabel) => {
  if (definition === null || typeof definition !== "object" || !("conditions" in definition)) {
    throw new Error("Rule definition must include a conditions object.");
  }

  const reviewOnMissingFacts =
    definition.options &&
    typeof definition.options === "object" &&
    definition.options.reviewOnMissingFacts === true;
  const reviewOnMissingFactsField = getRuleCreateField("reviewOnMissingFacts");

  if (reviewOnMissingFactsField instanceof HTMLInputElement) {
    reviewOnMissingFactsField.checked = reviewOnMissingFacts;
  }

  const rootConditions = definition.conditions;
  let rootLogic = "all";
  let rawChildren = [];

  if (rootConditions && typeof rootConditions === "object" && Array.isArray(rootConditions.all)) {
    rootLogic = "all";
    rawChildren = rootConditions.all;
  } else if (
    rootConditions &&
    typeof rootConditions === "object" &&
    Array.isArray(rootConditions.any)
  ) {
    rootLogic = "any";
    rawChildren = rootConditions.any;
  } else {
    rawChildren = [rootConditions];
  }

  const normalizedChildren = rawChildren
    .map((condition) => normalizeLeafConditionForBuilder(condition))
    .filter((condition) => condition !== null);

  if (normalizedChildren.length !== rawChildren.length) {
    setStatus(
      ruleCreateStatus,
      sourceLabel +
        " includes nested requirement groups not editable as rows. JSON mode remains active.",
      true,
    );
    syncRuleBuilderSummary(
      sourceLabel +
        " includes nested requirement groups not editable as rows. Adjust JSON manually.",
    );
    return;
  }

  clearConditionCanvas();
  setRuleBuilderRootLogic(rootLogic);
  normalizedChildren.forEach((seed) => {
    addConditionToCanvas(seed);
  });

  if (normalizedChildren.length === 0) {
    addConditionToCanvas({
      type: "course_completion",
      courseId: getDefaultCourseId() || getCoursePlaceholder(),
      minCompletionPercent: 100,
      negate: false,
    });
  }

  syncDefinitionJsonFromBuilder();
  setStatus(ruleCreateStatus, sourceLabel + " loaded into visual builder.", false, "success");
  syncRuleBuilderSummary(sourceLabel + " loaded into visual builder.");
};

const parseDefinitionJson = () => {
  const definitionJsonText = ruleBuilderDefinitionJson.value.trim();
  const fallbackDefinition = readDefinitionFromBuilder(true);

  if (definitionJsonText.length === 0) {
    return fallbackDefinition;
  }

  let parsed;

  try {
    parsed = JSON.parse(definitionJsonText);
  } catch {
    throw new Error("Rule JSON is not valid JSON.");
  }

  if (parsed === null || typeof parsed !== "object" || !("conditions" in parsed)) {
    throw new Error("Rule JSON must include a top-level conditions object.");
  }

  return parsed;
};

const collectRuleBuilderLearnerCourseIds = (condition, courseIds) => {
  if (!condition || typeof condition !== "object") {
    return;
  }

  if (Array.isArray(condition.all)) {
    condition.all.forEach((child) => collectRuleBuilderLearnerCourseIds(child, courseIds));
  }

  if (Array.isArray(condition.any)) {
    condition.any.forEach((child) => collectRuleBuilderLearnerCourseIds(child, courseIds));
  }

  if (condition.not && typeof condition.not === "object") {
    collectRuleBuilderLearnerCourseIds(condition.not, courseIds);
  }

  if (typeof condition.courseId === "string" && condition.courseId.length > 0) {
    courseIds.add(condition.courseId);
  }

  if (Array.isArray(condition.courseIds)) {
    condition.courseIds.forEach((courseId) => {
      if (typeof courseId === "string" && courseId.length > 0) {
        courseIds.add(courseId);
      }
    });
  }
};

const ruleBuilderLearnerCourseIds = () => {
  const courseIds = new Set();
  readConditionsForPreview().forEach((condition) => {
    collectRuleBuilderLearnerCourseIds(condition, courseIds);
  });
  return Array.from(courseIds).sort();
};

const conditionRequiresRecipientIdentity = (condition) => {
  if (!condition || typeof condition !== "object") {
    return false;
  }

  if (condition.type === "prerequisite_badge") {
    return true;
  }

  if (Array.isArray(condition.all) && condition.all.some(conditionRequiresRecipientIdentity)) {
    return true;
  }

  if (Array.isArray(condition.any) && condition.any.some(conditionRequiresRecipientIdentity)) {
    return true;
  }

  return condition.not && typeof condition.not === "object"
    ? conditionRequiresRecipientIdentity(condition.not)
    : false;
};

const ruleBuilderTestRequiresRecipientIdentity = () => {
  return readConditionsForPreview().some(conditionRequiresRecipientIdentity);
};

const syncRuleBuilderTestRecipientFields = () => {
  if (ruleBuilderTestRecipientFields instanceof HTMLElement) {
    ruleBuilderTestRecipientFields.hidden = !ruleBuilderTestRequiresRecipientIdentity();
  }
};

const setRuleBuilderLearnerStatus = (message, isError) => {
  if (!(ruleBuilderLearnerStatus instanceof HTMLElement)) {
    return;
  }

  ruleBuilderLearnerStatus.textContent = message;
  ruleBuilderLearnerStatus.dataset.tone = isError ? "error" : "info";
};

const clearRuleBuilderLearnerSelection = (message) => {
  setRuleCreateFieldValue("testLearnerId", "");
  setRuleCreateFieldValue("testRecipientIdentity", "");

  if (ruleBuilderLearnerSelect instanceof HTMLSelectElement) {
    ruleBuilderLearnerSelect.replaceChildren(new Option(message, ""));
    ruleBuilderLearnerSelect.disabled = true;
    ruleBuilderLearnerSelect.dataset.courseIds = "";
  }
};

const ruleBuilderLearnersPath = (courseId, query) => {
  const connectionId = getSelectedLmsConnectionId();

  if (connectionId.length === 0) {
    return "";
  }

  const path =
    lmsConnectionsApiPath +
    "/" +
    encodeURIComponent(connectionId) +
    "/courses/" +
    encodeURIComponent(courseId) +
    "/learners";

  return query.length === 0 ? path : path + "?q=" + encodeURIComponent(query);
};

const mergeRuleBuilderLearners = (courseResults, courseCount) => {
  const learnersById = new Map();

  courseResults.forEach((courseResult) => {
    courseResult.learners.forEach((learner) => {
      if (
        !learner ||
        typeof learner !== "object" ||
        typeof learner.learnerId !== "string" ||
        typeof learner.displayName !== "string"
      ) {
        return;
      }

      const existing = learnersById.get(learner.learnerId);

      if (existing) {
        existing.courseCount += 1;
        if (existing.email === null && typeof learner.email === "string") {
          existing.email = learner.email;
        }
        return;
      }

      learnersById.set(learner.learnerId, {
        learnerId: learner.learnerId,
        displayName: learner.displayName,
        email: typeof learner.email === "string" ? learner.email : null,
        courseCount: 1,
        requiredCourseCount: courseCount,
      });
    });
  });

  return Array.from(learnersById.values()).sort((left, right) => {
    if (left.courseCount !== right.courseCount) {
      return right.courseCount - left.courseCount;
    }

    return left.displayName.localeCompare(right.displayName);
  });
};

const ruleBuilderLearnerOptionLabel = (learner) => {
  const identity = learner.email === null ? learner.learnerId : learner.email;
  const coverage =
    learner.requiredCourseCount > 1
      ? " · " + String(learner.courseCount) + "/" + String(learner.requiredCourseCount) + " courses"
      : "";
  return learner.displayName + " · " + identity + coverage;
};

const applyRuleBuilderLearnerSelection = (option) => {
  const learnerId = option === null ? "" : option.value;
  const email = option === null ? "" : (option.dataset.email ?? "");
  setRuleCreateFieldValue("testLearnerId", learnerId);
  setRuleCreateFieldValue("testRecipientIdentity", email);
};

const setRuleBuilderLearnerFilterVisibility = (isVisible) => {
  if (ruleBuilderLearnerFilter instanceof HTMLElement) {
    ruleBuilderLearnerFilter.hidden = !isVisible;
  }
};

const RULE_BUILDER_LEARNER_OPTION_LIMIT = 100;
let ruleBuilderLearnerLoadSequence = 0;

const resetRuleBuilderLearnerPicker = (optionLabel, statusMessage, isError = false) => {
  ruleBuilderLearnerLoadSequence += 1;
  clearRuleBuilderLearnerSelection(optionLabel);
  setRuleBuilderLearnerFilterVisibility(false);
  setRuleBuilderLearnerStatus(statusMessage, isError);

  if (ruleBuilderLearnerFilterQuery instanceof HTMLInputElement) {
    ruleBuilderLearnerFilterQuery.value = "";
  }
};

const loadRuleBuilderLearners = async (query = "") => {
  if (!(ruleBuilderLearnerSelect instanceof HTMLSelectElement)) {
    return;
  }

  syncRuleBuilderTestRecipientFields();
  const courseIds = ruleBuilderLearnerCourseIds();

  if (courseIds.length === 0) {
    resetRuleBuilderLearnerPicker(
      "No course learners available",
      "This rule has no course requirement. Use generated example data to test its structure.",
    );
    return;
  }

  if (getSelectedLmsConnectionId().length === 0) {
    resetRuleBuilderLearnerPicker(
      "Select an LMS connection first",
      "Select an LMS connection before choosing a learner.",
      true,
    );
    return;
  }

  const loadSequence = ++ruleBuilderLearnerLoadSequence;

  if (query.length === 0 && ruleBuilderLearnerFilterQuery instanceof HTMLInputElement) {
    ruleBuilderLearnerFilterQuery.value = "";
  }

  clearRuleBuilderLearnerSelection("Loading learners...");
  setRuleBuilderLearnerStatus("Loading current LMS rosters...", false);

  try {
    const courseResults = await Promise.all(
      courseIds.map(async (courseId) => {
        const payload = await lmsFetchJson(
          ruleBuilderLearnersPath(courseId, query),
          "Unable to load LMS learners.",
        );
        return {
          learners: payload && Array.isArray(payload.learners) ? payload.learners : [],
          hasMore: payload?.hasMore === true,
        };
      }),
    );

    if (loadSequence !== ruleBuilderLearnerLoadSequence) {
      return;
    }

    const learners = mergeRuleBuilderLearners(courseResults, courseIds.length);
    const requiresSearch =
      courseResults.some((courseResult) => courseResult.hasMore) ||
      learners.length > RULE_BUILDER_LEARNER_OPTION_LIMIT;
    const visibleLearners = learners.slice(0, RULE_BUILDER_LEARNER_OPTION_LIMIT);
    const placeholder =
      learners.length === 0
        ? query.length === 0
          ? "No learners found"
          : "No matching learners"
        : "Choose a learner";
    const options = [
      new Option(placeholder, ""),
      ...visibleLearners.map((learner) => {
        const option = new Option(ruleBuilderLearnerOptionLabel(learner), learner.learnerId);
        option.dataset.email = learner.email ?? "";
        option.dataset.courseCount = String(learner.courseCount);
        return option;
      }),
    ];
    ruleBuilderLearnerSelect.replaceChildren(...options);
    ruleBuilderLearnerSelect.disabled = learners.length === 0;
    ruleBuilderLearnerSelect.dataset.courseIds = courseIds.join(",");
    setRuleBuilderLearnerFilterVisibility(requiresSearch || query.length > 0);

    if (learners.length === 1 && !requiresSearch) {
      ruleBuilderLearnerSelect.value = learners[0].learnerId;
      applyRuleBuilderLearnerSelection(ruleBuilderLearnerSelect.selectedOptions.item(0));
      setRuleBuilderLearnerStatus("The only learner in this roster is selected.", false);
      return;
    }

    applyRuleBuilderLearnerSelection(null);

    if (learners.length === 0) {
      setRuleBuilderLearnerStatus(
        query.length === 0
          ? "No learners were found in the courses for this rule."
          : "No learners matched this search.",
        true,
      );
      return;
    }

    setRuleBuilderLearnerStatus(
      requiresSearch
        ? "This roster has more learners than the list can show. Search to narrow it."
        : "Choose one of " + String(learners.length) + " learners.",
      false,
    );
  } catch (error) {
    if (loadSequence !== ruleBuilderLearnerLoadSequence) {
      return;
    }

    clearRuleBuilderLearnerSelection("Unable to load learners");
    setRuleBuilderLearnerStatus(
      lmsLookupErrorMessage(error, "Unable to load LMS learners."),
      true,
    );
  }
};

if (ruleBuilderLearnerFilterQuery instanceof HTMLInputElement) {
  lmsBindDebouncedSearch({
    searchInput: ruleBuilderLearnerFilterQuery,
    debounceMs: 250,
    onInput: () => loadRuleBuilderLearners(ruleBuilderLearnerFilterQuery.value.trim()),
  });
}

if (ruleBuilderLearnerSelect instanceof HTMLSelectElement) {
  ruleBuilderLearnerSelect.addEventListener("change", () => {
    const option = ruleBuilderLearnerSelect.selectedOptions.item(0);
    applyRuleBuilderLearnerSelection(option);

    if (option === null || option.value.length === 0) {
      setRuleBuilderLearnerStatus("Choose an LMS learner.", false);
      return;
    }

    setRuleBuilderLearnerStatus(
      "Selected learner will be checked against current LMS data.",
      false,
    );
  });
}

syncRuleBuilderTestRecipientFields();

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

const setRuleBuilderDraftStatus = (message, tone) => {
  if (!(ruleBuilderDraftStatus instanceof HTMLElement)) {
    return;
  }

  ruleBuilderDraftStatus.textContent = message;
  if (tone) {
    ruleBuilderDraftStatus.dataset.tone = tone;
  } else {
    delete ruleBuilderDraftStatus.dataset.tone;
  }
};

const currentRuleBuilderStep = () => {
  return ruleBuilderStepOrder[activeRuleBuilderStepIndex] ?? "metadata";
};

const readRuleBuilderDraftPayload = () => {
  const definitionJson =
    ruleBuilderDefinitionJson instanceof HTMLTextAreaElement ? ruleBuilderDefinitionJson.value : "";
  const builderState = {
    rootLogic: getTextFieldValue("rootLogic"),
    issuanceTiming: getTextFieldValue("issuanceTiming"),
    changeSummary: getTextFieldValue("changeSummary"),
    reviewOnMissingFacts:
      getRuleCreateField("reviewOnMissingFacts") instanceof HTMLInputElement
        ? getRuleCreateField("reviewOnMissingFacts").checked
        : false,
    lastTestSummary: ruleBuilderLastTestSummary,
  };

  return {
    target:
      isRuleBuilderEditMode && typeof editRuleContext.latestVersionId === "string"
        ? {
            kind: "formal_rule",
            ruleId: editRuleContext.id,
            versionId: editRuleContext.latestVersionId,
          }
        : { kind: "unfinished" },
    currentStep: currentRuleBuilderStep(),
    name: getTextFieldValue("name"),
    description: getTextFieldValue("description"),
    badgeTemplateId: getTextFieldValue("badgeTemplateId"),
    lmsConnectionId: getTextFieldValue("lmsConnectionId"),
    lmsProviderKind: getTextFieldValue("lmsProviderKind"),
    definitionJson,
    builderState,
  };
};

const performRuleBuilderDraftSave = async (options) => {
  if (ruleBuilderDraftApiPath.length === 0) {
    return false;
  }

  const quiet = options && options.quiet === true;

  if (!quiet) {
    setRuleBuilderDraftStatus("Saving unfinished work...", "info");
  }

  try {
    const response = await fetch(ruleBuilderDraftApiPath, {
      method: "PUT",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify(readRuleBuilderDraftPayload()),
    });
    const payload = await parseJsonBody(response);

    if (!response.ok) {
      const message = errorDetailFromPayload(payload);
      setRuleBuilderDraftStatus(message, "error");
      if (!quiet) {
        setStatus(ruleCreateStatus, message, true);
      }
      return false;
    }

    const savedAt =
      payload &&
      payload.draft &&
      typeof payload.draft.updatedAt === "string" &&
      payload.draft.updatedAt.length > 0
        ? new Date(payload.draft.updatedAt).toLocaleTimeString([], {
            hour: "numeric",
            minute: "2-digit",
          })
        : "now";

    setRuleBuilderDraftStatus("Unfinished work saved " + savedAt + ".", "success");

    if (
      !isRuleBuilderEditMode &&
      payload &&
      payload.draft &&
      typeof payload.draft.id === "string"
    ) {
      window.history.replaceState(
        null,
        "",
        rulesListPath +
          "/drafts/" +
          encodeURIComponent(payload.draft.id) +
          "/edit",
      );
    }
    return true;
  } catch {
    const message = "Unable to save this draft from this browser session.";
    setRuleBuilderDraftStatus(message, "error");
    if (!quiet) {
      setStatus(ruleCreateStatus, message, true);
    }
    return false;
  }
};

let ruleBuilderDraftSaveQueue = Promise.resolve(true);

const saveRuleBuilderDraft = (options) => {
  const save = ruleBuilderDraftSaveQueue.then(
    () => performRuleBuilderDraftSave(options),
    () => performRuleBuilderDraftSave(options),
  );
  ruleBuilderDraftSaveQueue = save;
  return save;
};

const persistRuleBuilderDraftOnStepChange = () => {
  setRuleBuilderDraftStatus("Saving unfinished work...", "info");
  void saveRuleBuilderDraft({ quiet: true });
};

const applyBuilderDraftPayload = (draftContext) => {
  const payload = draftContext.payload;

  if (typeof payload.name === "string") {
    setRuleCreateFieldValue("name", payload.name);
  }

  if (typeof payload.description === "string") {
    setRuleCreateFieldValue("description", payload.description);
  }

  if (typeof payload.badgeTemplateId === "string") {
    setRuleCreateFieldValue("badgeTemplateId", payload.badgeTemplateId);
  }

  if (typeof payload.lmsConnectionId === "string") {
    setRuleCreateFieldValue("lmsConnectionId", payload.lmsConnectionId);
    syncSelectedLmsProviderKind();
  }

  if (typeof payload.definitionJson === "string" && payload.definitionJson.trim().length > 0) {
    try {
      const savedDefinition = JSON.parse(payload.definitionJson);
      ruleBuilderDefinitionJson.value = JSON.stringify(savedDefinition, null, 2);
      applyDefinitionToBuilder(savedDefinition, "Saved draft");
    } catch {
      setRuleBuilderDraftStatus("Saved draft requirements could not be restored.", "warning");
    }
  }

  const builderState = payload.builderState;
  if (builderState && typeof builderState === "object" && !Array.isArray(builderState)) {
    if (builderState.rootLogic === "all" || builderState.rootLogic === "any") {
      setRuleBuilderRootLogic(builderState.rootLogic);
    }

    if (typeof builderState.issuanceTiming === "string") {
      setRuleCreateFieldValue("issuanceTiming", builderState.issuanceTiming);
    }

    if (typeof builderState.changeSummary === "string") {
      setRuleCreateFieldValue("changeSummary", builderState.changeSummary);
    }

    const reviewField = getRuleCreateField("reviewOnMissingFacts");
    if (
      reviewField instanceof HTMLInputElement &&
      typeof builderState.reviewOnMissingFacts === "boolean"
    ) {
      reviewField.checked = builderState.reviewOnMissingFacts;
    }

    if (
      typeof builderState.lastTestSummary === "string" &&
      builderState.lastTestSummary.length > 0
    ) {
      ruleBuilderLastTestSummary = builderState.lastTestSummary;
    }
  }

  const currentStep = draftContext.currentStep;
  if (typeof currentStep === "string") {
    const stepIndex = ruleBuilderStepOrder.indexOf(currentStep);
    if (stepIndex >= 0) {
      setBuilderStepState(stepIndex);
    }
  }
};

const restoreBuilderDraftIfApplicable = () => {
  if (builderDraftContext === null) {
    return;
  }

  const restoreStatus =
    typeof builderDraftContext.restoreStatus === "string"
      ? builderDraftContext.restoreStatus
      : "invalid_payload";

  if (restoreStatus === "invalid_payload") {
    setRuleBuilderDraftStatus(
      "Saved draft data could not be restored. Continue from the current rule settings.",
      "warning",
    );
    return;
  }

  if (restoreStatus === "version_mismatch") {
    setRuleBuilderDraftStatus("Saved draft is for a different version and was ignored.", "warning");
    return;
  }

  if (restoreStatus === "stale") {
    setRuleBuilderDraftStatus(
      "Saved draft is older than the current rule version and was ignored.",
      "warning",
    );
    return;
  }

  applyBuilderDraftPayload(builderDraftContext);
  setRuleBuilderDraftStatus("Draft restored from last save.", "success");
};

if (ruleBuilderStepButtons.length > 0) {
  ruleBuilderStepButtons.forEach((candidate) => {
    if (!(candidate instanceof HTMLButtonElement)) {
      return;
    }

    candidate.addEventListener("click", () => {
      const targetStep = candidate.dataset.ruleStepTarget ?? "";
      const targetIndex = ruleBuilderStepOrder.indexOf(targetStep);

      if (targetIndex >= 0) {
        tryNavigateToStep(targetIndex);
      }
    });
  });
}

if (ruleBuilderStepNextButton instanceof HTMLButtonElement) {
  ruleBuilderStepNextButton.addEventListener("click", () => {
    const currentStep = ruleBuilderStepOrder[activeRuleBuilderStepIndex] ?? "";

    if (!isStepComplete(currentStep)) {
      showStepGateMessage(currentStep);
      return;
    }

    setBuilderStepState(activeRuleBuilderStepIndex + 1);
  });
}

ruleCreateForm.addEventListener("input", () => {
  syncRuleBuilderSummary();
  setRuleBuilderDraftStatus("Unsaved changes.", "warning");
});

ruleCreateForm.addEventListener("change", () => {
  syncRuleBuilderSummary();
  setRuleBuilderDraftStatus("Unsaved changes.", "warning");
});

if (ruleBuilderSaveDraftButton instanceof HTMLButtonElement) {
  ruleBuilderSaveDraftButton.addEventListener("click", () => {
    void saveRuleBuilderDraft({ quiet: false });
  });
}

const reviewOnMissingFactsField = getRuleCreateField("reviewOnMissingFacts");

if (reviewOnMissingFactsField instanceof HTMLInputElement) {
  reviewOnMissingFactsField.addEventListener("change", () => {
    syncDefinitionJsonFromBuilder();
  });
}

if (ruleBuilderAddConditionButton instanceof HTMLButtonElement) {
  ruleBuilderAddConditionButton.addEventListener("click", () => {
    addConditionToCanvas({
      type: "course_completion",
      courseId: getDefaultCourseId() || getCoursePlaceholder(),
      minCompletionPercent: 100,
      negate: false,
    });
  });
}

if (ruleBuilderAddAlternativePathButton instanceof HTMLButtonElement) {
  ruleBuilderAddAlternativePathButton.addEventListener("click", () => {
    setRuleBuilderRootLogic("any");
    addConditionToCanvas({
      type: "grade_threshold",
      courseId: getDefaultCourseId() || getCoursePlaceholder(),
      scoreField: "final_score",
      minScore: 80,
      negate: false,
    });
    syncDefinitionJsonFromBuilder();
    syncRuleBuilderSummary("Alternative earning path added.");
  });
}

if (ruleBuilderRequireEveryRequirementButton instanceof HTMLButtonElement) {
  ruleBuilderRequireEveryRequirementButton.addEventListener("click", () => {
    setRuleBuilderRootLogic("all");
    syncDefinitionJsonFromBuilder();
    syncRuleBuilderSummary("Learner must meet every requirement.");
  });
}

if (ruleBuilderApplyTemplateButton instanceof HTMLButtonElement) {
  ruleBuilderApplyTemplateButton.addEventListener("click", () => {
    applyTemplatePreset();
  });
}

if (ruleBuilderApplyJsonButton instanceof HTMLButtonElement) {
  ruleBuilderApplyJsonButton.addEventListener("click", () => {
    try {
      const definition = parseDefinitionJson();
      applyDefinitionToBuilder(definition, "JSON");
    } catch (error) {
      setStatus(
        ruleCreateStatus,
        error instanceof Error ? error.message : "Unable to apply JSON to builder.",
        true,
      );
    }
  });
}

if (
  ruleBuilderImportJsonButton instanceof HTMLButtonElement &&
  ruleBuilderImportFileInput instanceof HTMLInputElement
) {
  ruleBuilderImportJsonButton.addEventListener("click", () => {
    ruleBuilderImportFileInput.click();
  });

  ruleBuilderImportFileInput.addEventListener("change", async () => {
    const file = ruleBuilderImportFileInput.files?.item(0);

    if (!(file instanceof File)) {
      return;
    }

    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      const definition =
        parsed && typeof parsed === "object" && "definition" in parsed
          ? parsed.definition
          : parsed && typeof parsed === "object" && "conditions" in parsed
            ? parsed
            : null;

      if (
        parsed !== null &&
        typeof parsed === "object" &&
        !Array.isArray(parsed) &&
        "name" in parsed &&
        typeof parsed.name === "string"
      ) {
        setRuleCreateFieldValue("name", parsed.name);
      }

      if (
        parsed !== null &&
        typeof parsed === "object" &&
        !Array.isArray(parsed) &&
        "description" in parsed &&
        typeof parsed.description === "string"
      ) {
        setRuleCreateFieldValue("description", parsed.description);
      }

      if (
        parsed !== null &&
        typeof parsed === "object" &&
        !Array.isArray(parsed) &&
        "badgeTemplateId" in parsed &&
        typeof parsed.badgeTemplateId === "string"
      ) {
        setRuleCreateFieldValue("badgeTemplateId", parsed.badgeTemplateId);
      }

      if (
        parsed !== null &&
        typeof parsed === "object" &&
        !Array.isArray(parsed) &&
        "lmsConnectionId" in parsed &&
        typeof parsed.lmsConnectionId === "string"
      ) {
        setRuleCreateFieldValue("lmsConnectionId", parsed.lmsConnectionId);
        syncSelectedLmsProviderKind();
      }

      if (definition === null) {
        throw new Error("Imported JSON must contain definition.conditions or conditions.");
      }

      ruleBuilderDefinitionJson.value = JSON.stringify(definition, null, 2);
      applyDefinitionToBuilder(definition, "Imported JSON");
      ruleBuilderImportFileInput.value = "";
    } catch (error) {
      setStatus(
        ruleCreateStatus,
        error instanceof Error ? error.message : "Unable to import JSON.",
        true,
      );
      ruleBuilderImportFileInput.value = "";
    }
  });
}

if (ruleBuilderExportJsonButton instanceof HTMLButtonElement) {
  ruleBuilderExportJsonButton.addEventListener("click", () => {
    try {
      const definition = parseDefinitionJson();
      const payload = {
        name: getTextFieldValue("name"),
        description: getTextFieldValue("description"),
        badgeTemplateId: getTextFieldValue("badgeTemplateId"),
        lmsConnectionId: getTextFieldValue("lmsConnectionId"),
        definition,
      };
      const blob = new Blob([JSON.stringify(payload, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      const exportName =
        payload.name.length === 0
          ? "rule-definition.json"
          : payload.name
              .toLowerCase()
              .replace(/[^a-z0-9]+/g, "-")
              .replace(/^-+|-+$/g, "") + ".json";
      anchor.href = url;
      anchor.download = exportName;
      anchor.click();
      URL.revokeObjectURL(url);
      setStatus(ruleCreateStatus, "Rule JSON exported.", false, "success");
      syncRuleBuilderSummary("Rule JSON exported.");
    } catch (error) {
      setStatus(
        ruleCreateStatus,
        error instanceof Error ? error.message : "Unable to export JSON.",
        true,
      );
      syncRuleBuilderSummary(error instanceof Error ? error.message : "Unable to export JSON.");
    }
  });
}

if (
  ruleBuilderCloneLoadButton instanceof HTMLButtonElement &&
  ruleBuilderCloneRuleSelect instanceof HTMLSelectElement
) {
  ruleBuilderCloneLoadButton.addEventListener("click", async () => {
    const ruleId = ruleBuilderCloneRuleSelect.value.trim();

    if (ruleId.length === 0) {
      setStatus(ruleCreateStatus, "Select a rule to copy.", true);
      syncRuleBuilderSummary("Select a rule to copy.");
      return;
    }

    setStatus(ruleCreateStatus, "Copying rule settings...", false);
    syncRuleBuilderSummary("Copying rule settings...");

    try {
      const response = await fetch(badgeRuleApiPath + "/" + encodeURIComponent(ruleId));
      const payload = await parseJsonBody(response);

      if (!response.ok) {
        setStatus(ruleCreateStatus, errorDetailFromPayload(payload), true);
        syncRuleBuilderSummary(errorDetailFromPayload(payload));
        return;
      }

      const rule = payload && payload.rule ? payload.rule : null;
      const versions = payload && Array.isArray(payload.versions) ? payload.versions : [];
      const latestVersion = versions.slice().sort((left, right) => {
        const leftVersion = typeof left.versionNumber === "number" ? left.versionNumber : 0;
        const rightVersion = typeof right.versionNumber === "number" ? right.versionNumber : 0;
        return rightVersion - leftVersion;
      })[0];

      if (rule && typeof rule.description === "string" && rule.description.length > 0) {
        setRuleCreateFieldValue("description", rule.description);
      }

      if (rule && typeof rule.badgeTemplateId === "string") {
        setRuleCreateFieldValue("badgeTemplateId", rule.badgeTemplateId);
      }

      if (rule && typeof rule.lmsConnectionId === "string") {
        setRuleCreateFieldValue("lmsConnectionId", rule.lmsConnectionId);
        syncSelectedLmsProviderKind();
      }

      if (latestVersion && typeof latestVersion.ruleJson === "string") {
        const definition = JSON.parse(latestVersion.ruleJson);
        ruleBuilderDefinitionJson.value = JSON.stringify(definition, null, 2);
        applyDefinitionToBuilder(definition, "Copied rule settings");
      } else {
        setStatus(ruleCreateStatus, "Selected rule has no saved settings to copy.", true);
        syncRuleBuilderSummary("Selected rule has no saved settings to copy.");
      }
    } catch {
      setStatus(ruleCreateStatus, "Unable to copy selected rule from this browser session.", true);
      syncRuleBuilderSummary("Unable to copy selected rule from this browser session.");
    }
  });
}


    runRuleBuilderTest = async (options) => {
      const autoRun = options && options.auto === true;
      const runningMessage = autoRun
        ? 'Running automatic test with sample learner...'
        : getRuleBuilderTestDataSource() === 'lms'
          ? 'Checking current LMS data...'
          : 'Evaluating generated example data...';

      setStatus(ruleCreateStatus, runningMessage, false);
      setCodeOutput(ruleBuilderTestOutput, '');

      if (ruleBuilderTestResult instanceof HTMLElement) {
        setStatus(ruleBuilderTestResult, runningMessage, false);
      }

      resetConditionEvaluationResults();
      ruleBuilderLastTestSummary = 'Running...';
      syncRuleBuilderSummary(runningMessage);

      let definition;

      try {
        definition = parseDefinitionJson();
      } catch (error) {
        const message =
          error instanceof Error ? error.message : 'Rule definition is invalid.';
        setStatus(ruleCreateStatus, message, true);
        if (ruleBuilderTestResult instanceof HTMLElement) {
          setStatus(ruleBuilderTestResult, message, true);
        }
        ruleBuilderLastTestSummary = 'Definition invalid';
        syncRuleBuilderSummary(message);
        return;
      }

      const lmsConnectionId = getTextFieldValue('lmsConnectionId');
      const lmsProviderKind = getSelectedLmsProviderKind();
      const testDataSource = getRuleBuilderTestDataSource();
      const learnerId =
        testDataSource === 'example' ? 'example-learner' : getTextFieldValue('testLearnerId');
      const recipientIdentity = getTextFieldValue('testRecipientIdentity').toLowerCase();
      const requiresRecipientIdentity =
        testDataSource === 'lms' && ruleBuilderTestRequiresRecipientIdentity();
      const sampleFinalScoreText = getTextFieldValue('testFinalScore');
      const testFactsJson = getTextFieldValue('testFactsJson');

      if (learnerId.length === 0) {
        const message = 'Choose an LMS learner.';
        setStatus(ruleCreateStatus, message, true);
        if (ruleBuilderTestResult instanceof HTMLElement) {
          setStatus(ruleBuilderTestResult, message, true);
        }
        ruleBuilderLastTestSummary = 'Missing test identifiers';
        syncRuleBuilderSummary(message);
        return;
      }

      if (testDataSource === 'lms' && ruleBuilderLearnerSelect instanceof HTMLSelectElement) {
        const selectedCourseIds = ruleBuilderLearnerSelect.dataset.courseIds ?? '';
        const currentCourseIds = ruleBuilderLearnerCourseIds().join(',');

        if (selectedCourseIds !== currentCourseIds) {
          const message = 'The rule courses changed. Choose the learner again.';
          setStatus(ruleCreateStatus, message, true);
          if (ruleBuilderTestResult instanceof HTMLElement) {
            setStatus(ruleBuilderTestResult, message, true);
          }
          ruleBuilderLastTestSummary = 'Learner selection outdated';
          syncRuleBuilderSummary(message);
          return;
        }
      }

      if (requiresRecipientIdentity && recipientIdentity.length === 0) {
        const message = 'Enter the learner credential email required by the prerequisite badge check.';
        setStatus(ruleCreateStatus, message, true);
        if (ruleBuilderTestResult instanceof HTMLElement) {
          setStatus(ruleBuilderTestResult, message, true);
        }
        ruleBuilderLastTestSummary = 'Missing credential email';
        syncRuleBuilderSummary(message);
        return;
      }

      if (lmsConnectionId.length === 0) {
        const message = 'Select an LMS connection before testing the rule.';
        setStatus(ruleCreateStatus, message, true);
        if (ruleBuilderTestResult instanceof HTMLElement) {
          setStatus(ruleBuilderTestResult, message, true);
        }
        ruleBuilderLastTestSummary = 'Missing LMS connection';
        syncRuleBuilderSummary(message);
        return;
      }

      let facts = undefined;

      if (testDataSource === 'lms') {
        facts = undefined;
      } else if (testFactsJson.length > 0) {
        try {
          facts = JSON.parse(testFactsJson);
        } catch {
          const message = 'Advanced facts JSON is invalid.';
          setStatus(ruleCreateStatus, message, true);
          if (ruleBuilderTestResult instanceof HTMLElement) {
            setStatus(ruleBuilderTestResult, message, true);
          }
          ruleBuilderLastTestSummary = 'Facts JSON invalid';
          syncRuleBuilderSummary(message);
          return;
        }
      } else {
        const sampleFinalScore = Number(sampleFinalScoreText);

        if (!Number.isFinite(sampleFinalScore) || sampleFinalScore < 0 || sampleFinalScore > 100) {
          const message = 'Sample final score must be a number between 0 and 100.';
          setStatus(ruleCreateStatus, message, true);
          if (ruleBuilderTestResult instanceof HTMLElement) {
            setStatus(ruleBuilderTestResult, message, true);
          }
          ruleBuilderLastTestSummary = 'Sample score invalid';
          syncRuleBuilderSummary(message);
          return;
        }

        facts = buildSampleFactsFromConditions(readConditionsForPreview(), learnerId);
      }

      try {
        const response = await fetch(badgeRulePreviewApiPath, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
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
                    identityType: 'email',
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
          ruleBuilderLastTestSummary = 'Failed';
          syncRuleBuilderSummary(message);
          return;
        }

        const matched =
          payload && payload.evaluation && payload.evaluation.matched === true;
        let outcome = 'no_match';

        if (payload && typeof payload.outcome === 'string') {
          outcome = payload.outcome;
        } else if (matched) {
          outcome = 'matched';
        }
        const evaluationSummary =
          payload && payload.evaluationSummary && typeof payload.evaluationSummary === 'object'
            ? payload.evaluationSummary
            : null;
        const missingDataCount =
          evaluationSummary && typeof evaluationSummary.missingDataCount === 'number'
            ? evaluationSummary.missingDataCount
            : 0;
        const conditionSummary = applyConditionEvaluationResults(
          payload && payload.evaluation ? payload.evaluation : null,
        );
        const conditionSummaryText =
          conditionSummary.total === 0
            ? ''
            : ' Requirements passed: ' +
              String(conditionSummary.matched) +
              '/' +
              String(conditionSummary.total) +
              '.';
        let resultMessage = '';

        if (outcome === 'review_required') {
          resultMessage =
            'Review required: ' +
            String(conditionSummary.matched) +
            ' of ' +
            String(conditionSummary.total) +
            ' requirements matched, with missing data for ' +
            String(missingDataCount) +
            ' check(s).';
        } else if (matched) {
          resultMessage =
            (testDataSource === 'lms' ? 'This learner' : 'The example learner') +
            ' qualifies for this badge (' +
            String(conditionSummary.matched) +
            ' of ' +
            String(conditionSummary.total) +
            ' requirements matched).';
        } else if (missingDataCount > 0) {
          resultMessage =
            'CredTrail could not find all data needed to evaluate this learner. Review the requirement results for the missing LMS data, then confirm the learner ID and course records.';
        } else {
          resultMessage =
            (testDataSource === 'lms' ? 'This learner' : 'The example learner') +
            ' does not qualify yet (' +
            String(conditionSummary.matched) +
            ' of ' +
            String(conditionSummary.total) +
            (testDataSource === 'lms'
              ? ' requirements matched). Confirm the learner records or adjust the requirements and run again.'
              : ' requirements matched). Adjust the requirements or example data and run again.');
        }

        const testStatusMessage =
          outcome === 'matched'
            ? 'Test passed.' + conditionSummaryText
            : outcome === 'review_required'
              ? 'Test needs review. Data was unavailable for ' +
                String(missingDataCount) +
                ' requirement(s).' +
                conditionSummaryText
              : missingDataCount > 0
                ? 'Test could not confirm eligibility because data was unavailable for ' +
                  String(missingDataCount) +
                  ' requirement(s).' +
                  conditionSummaryText
                : 'Test complete.' + conditionSummaryText;

        setStatus(
          ruleCreateStatus,
          testStatusMessage,
          false,
          outcome === 'matched' ? 'success' : 'warning',
        );

        if (ruleBuilderTestResult instanceof HTMLElement) {
          setStatus(
            ruleBuilderTestResult,
            resultMessage,
            false,
            outcome === 'matched' ? 'success' : 'warning',
          );
        }

        if (outcome === 'review_required') {
          ruleBuilderLastTestSummary =
            'Review required (' +
            String(missingDataCount) +
            ' missing, ' +
            String(conditionSummary.matched) +
            '/' +
            String(conditionSummary.total) +
            ' requirements matched)';
        } else {
          ruleBuilderLastTestSummary =
            (matched ? 'Matched' : 'No match') +
            ' (' +
            String(conditionSummary.matched) +
            '/' +
            String(conditionSummary.total) +
            ' requirements)';
        }

        syncRuleBuilderSummary(testStatusMessage);
        setCodeOutput(ruleBuilderTestOutput, JSON.stringify(payload, null, 2));
      } catch {
        const message = 'Unable to run rule test from this browser session.';
        setStatus(ruleCreateStatus, message, true);
        if (ruleBuilderTestResult instanceof HTMLElement) {
          setStatus(ruleBuilderTestResult, message, true);
        }
        ruleBuilderLastTestSummary = 'Failed';
        syncRuleBuilderSummary(message);
      }
    };

    if (ruleBuilderTestButton instanceof HTMLButtonElement) {
      ruleBuilderTestButton.addEventListener('click', () => {
        void runRuleBuilderTest({ auto: false });
      });
    }

    ruleCreateForm.addEventListener('submit', async (event) => {
      event.preventDefault();

      if (ruleBuilderAuthoringController.state() !== 'idle') {
        return;
      }

      const action =
        event.submitter instanceof HTMLButtonElement ? event.submitter.value : '';

      if (action !== 'save_draft' && action !== 'submit_for_approval') {
        const message = 'Choose whether to submit this rule or save it as a draft.';
        setStatus(ruleCreateStatus, message, true);
        syncRuleBuilderSummary(message);
        return;
      }

      const name = getTextFieldValue('name');
      const description = getTextFieldValue('description');
      const badgeTemplateId = getTextFieldValue('badgeTemplateId');
      const lmsConnectionId = getTextFieldValue('lmsConnectionId');
      const issuanceTiming = getTextFieldValue('issuanceTiming');
      const changeSummaryInput = getTextFieldValue('changeSummary');

      if (name.length === 0 || badgeTemplateId.length === 0 || lmsConnectionId.length === 0) {
        setStatus(
          ruleCreateStatus,
          'Rule name, badge template, and LMS connection are required.',
          true,
        );
        syncRuleBuilderSummary(
          'Rule name, badge template, and LMS connection are required.',
        );
        return;
      }

      let definition;

      try {
        definition = parseDefinitionJson();
      } catch (error) {
        setStatus(
          ruleCreateStatus,
          error instanceof Error ? error.message : 'Rule payload is invalid.',
          true,
        );
        syncRuleBuilderSummary(
          error instanceof Error ? error.message : 'Rule payload is invalid.',
        );
        return;
      }

      const definitionWithOptions = {
        ...definition,
        options: {
          ...(definition && typeof definition === 'object' && definition.options && typeof definition.options === 'object'
            ? definition.options
            : {}),
          issuanceTiming:
            issuanceTiming === 'manual' || issuanceTiming === 'end_of_term'
              ? issuanceTiming
              : 'immediate',
        },
      };

      let changeSummary = changeSummaryInput;
      const issuanceLabel = definitionWithOptions.options.issuanceTiming.replaceAll('_', ' ');

      if (changeSummary.length === 0) {
        changeSummary =
          (isRuleBuilderEditMode
            ? 'New draft version saved via visual builder; issuance timing: '
            : 'Rule created via visual builder; issuance timing: ') +
          issuanceLabel +
          '.';
      } else if (!changeSummary.toLowerCase().includes('issuance timing')) {
        changeSummary =
          changeSummary + ' Issuance timing: ' + issuanceLabel + '.';
      }

      const authoringPromise = ruleBuilderAuthoringController.execute({
        apiPath: ruleBuilderSubmitApiPath,
        payload: {
          name,
          ...(description.length > 0 ? { description } : {}),
          badgeTemplateId,
          lmsConnectionId,
          definition: definitionWithOptions,
          ...(changeSummary.length > 0 ? { changeSummary } : {}),
          action,
          ...(!isRuleBuilderEditMode &&
          ruleBuilderContext &&
          typeof ruleBuilderContext.builderDraftId === 'string'
            ? { builderDraftId: ruleBuilderContext.builderDraftId }
            : {}),
        },
      });
      updateStepNavigationState();
      const savingMessage =
        action === 'submit_for_approval'
          ? 'Saving and submitting the rule...'
          : isRuleBuilderEditMode
            ? 'Saving a new draft version...'
            : 'Creating rule draft...';
      setStatus(ruleCreateStatus, savingMessage, false);
      setCodeOutput(ruleBuilderTestOutput, '');
      syncRuleBuilderSummary(savingMessage);
      const result = await authoringPromise;
      updateStepNavigationState();

      if (result.status === 'ignored') {
        return;
      }

      if (result.status === 'rejected') {
        setStatus(ruleCreateStatus, result.message, true);
        syncRuleBuilderSummary(result.message);
        return;
      }

      if (result.status === 'unknown') {
        const message =
          'CredTrail could not confirm the result. Try again safely, or check Rules.';
        setStatus(ruleCreateStatus, message, true);
        syncRuleBuilderSummary(message);
        return;
      }

      const successMessage =
        result.outcome === 'approved'
          ? 'Rule saved and approved by institution policy.'
          : result.outcome === 'pending_approval'
            ? 'Rule submitted for approval.'
            : isRuleBuilderEditMode
              ? 'New draft version saved.'
              : 'Rule draft created.';
      setStatus(ruleCreateStatus, successMessage, false, 'success');
      syncRuleBuilderSummary(successMessage);
      setTimeout(() => {
        window.location.assign(rulesListPath);
      }, 900);
    });

    const badgeTemplateField = getRuleCreateField('badgeTemplateId');

    if (badgeTemplateField instanceof HTMLSelectElement) {
      badgeTemplateField.addEventListener('change', () => {
        syncSuggestedRuleName();
        syncRuleBuilderSummary();

        if (ruleBuilderTemplatePreset instanceof HTMLSelectElement) {
          applyTemplatePreset();
        }
      });
    }

    if (ruleBuilderLmsConnectionSelect instanceof HTMLSelectElement) {
      ruleBuilderLmsConnectionSelect.addEventListener('change', () => {
        setLmsLookupStatus('', false);
        resetRuleBuilderLearnerPicker(
          'Learners load when this step opens',
          'CredTrail loads learners from the courses configured in this rule.',
        );
        syncSelectedLmsProviderKind();
        refreshConditionCardValueListOptions();
        syncRuleBuilderSummary();
      });
      syncSelectedLmsProviderKind();
    }

    if (ruleBuilderTemplatePreset instanceof HTMLSelectElement) {
      ruleBuilderTemplatePreset.addEventListener('change', () => {
        applyTemplatePreset();
        syncSuggestedRuleName();
        syncRuleBuilderSummary();
      });
    }

    setBuilderStepState(0);

    if (isRuleBuilderEditMode) {
      if (typeof editRuleContext.name === 'string') {
        setRuleCreateFieldValue('name', editRuleContext.name);
      }

      if (typeof editRuleContext.description === 'string') {
        setRuleCreateFieldValue('description', editRuleContext.description);
      }

      if (typeof editRuleContext.badgeTemplateId === 'string') {
        setRuleCreateFieldValue('badgeTemplateId', editRuleContext.badgeTemplateId);
      }

      if (typeof editRuleContext.lmsConnectionId === 'string') {
        setRuleCreateFieldValue('lmsConnectionId', editRuleContext.lmsConnectionId);
        syncSelectedLmsProviderKind();
      }

      if (editRuleContext.definition && typeof editRuleContext.definition === 'object') {
        ruleBuilderDefinitionJson.value = JSON.stringify(editRuleContext.definition, null, 2);
        applyDefinitionToBuilder(editRuleContext.definition, 'Saved rule settings');
      } else {
        setStatus(ruleCreateStatus, 'Saved rule JSON could not be loaded into the builder.', true);
        syncRuleBuilderSummary('Saved rule JSON could not be loaded into the builder.');
      }
    } else {
      syncSuggestedRuleName();
      applyTemplatePreset();
    }

    restoreBuilderDraftIfApplicable();

    refreshConditionCardValueListOptions();
    syncRuleBuilderSummary();
  }

})();